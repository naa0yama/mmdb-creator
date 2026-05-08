# Design: ワークスペース分割 — マルチクレート構成

## Problem

現行の `mmdb-creator` 単一クレートに全機能が混在している。
機能ごとの独立テスト・依存管理・将来の Web UI 再利用が困難。

## Goals

- 各クレートが単一責務を持つ
- ライブラリクレートは binary に依存しない (単体でテスト可能)
- 依存関係が一方向 (循環なし)
- `mmdb-whois` は ASN / IP / CIDR を入力として受け付ける汎用クライアント

## Non-Goals

- `mmdb-web` の実装 (stub のみ、将来タスク)
- xlsx のデータ処理ロジック (binary 側の責務)
- クレート単位の publish (全クレート `publish = false`)

## クレート構成

凡例: ✅ 実装済み / 🔲 未実装 (将来タスク)

```
crates/
├── mmdb-creator   (binary)  ✅ CLI シェル — 各ライブラリの orchestration
├── mmdb-core      (lib)     ✅ 共有型 / 設定スキーマ / 外部コマンドチェック
├── mmdb-whois     (lib)     ✅ ASN・IP・CIDR → WhoisData (RIPE + bgp.tools + TCP 43)
├── mmdb-xlsx      (lib)     ✅ Excel R/W のみ (calamine + rust_xlsxwriter)
├── mmdb-dns       (lib)     ✅ Team Cymru DNS TXT lookup / PTR reverse lookup (仕様策定後に追加)
├── mmdb-scan      (lib)     🔲 scamper デーモン統合 (現在は mmdb-creator/src/scan/ に内包)
├── mmdb-export    (lib)     🔲 mmdbctl 統合 (現在は mmdb-creator/src/export/ に内包)
└── mmdb-web       (binary)  🔲 将来の Web UI (stub も未作成)
```

### 依存関係図

```
mmdb-creator ──► mmdb-core
             ──► mmdb-whois  ──► mmdb-core
             ──► mmdb-xlsx   ──► mmdb-core
             ──► mmdb-dns    (mmdb-core には依存しない)
             ──► (mmdb-scan: 将来抽出予定)
             ──► (mmdb-export: 将来抽出予定)

mmdb-web     ──► mmdb-core   (将来)
             ──► mmdb-whois  (将来)
             ──► mmdb-xlsx   (将来)
             ──► mmdb-scan   (将来)
             ──► mmdb-export (将来)
```

### 各クレートの責務

| クレート       | 種別   | 状態 | 責務                                                                                      | 主な依存                       |
| -------------- | ------ | ---- | ----------------------------------------------------------------------------------------- | ------------------------------ |
| `mmdb-core`    | lib    | ✅   | `MmdbRecord`, `WhoisData`, `RouteData` 等の共有型 / `Config` スキーマ / `require_command` | serde, ipnet, chrono           |
| `mmdb-whois`   | lib    | ✅   | ASN → 広報 CIDR 取得 (RIPE Stat / bgp.tools) + TCP 43 whois + RPSL パース                 | mmdb-core, tokio, reqwest      |
| `mmdb-xlsx`    | lib    | ✅   | Excel ファイル読み取り (calamine) / 書き出し (rust_xlsxwriter) のみ                       | calamine, rust_xlsxwriter      |
| `mmdb-dns`     | lib    | ✅   | Team Cymru DNS TXT で ASN 一括取得 / PTR reverse lookup                                   | hickory-resolver, ipnet, tokio |
| `mmdb-scan`    | lib    | 🔲   | scamper デーモン起動・停止 / Unix ソケット通信 / JSON パース / TUI 進捗                   | mmdb-core, tokio, indicatif    |
| `mmdb-export`  | lib    | 🔲   | data/*.jsonl マージ / NDJSON 生成 / mmdbctl 呼び出し                                      | mmdb-core, tokio               |
| `mmdb-creator` | binary | ✅   | CLI 引数定義 / 各ライブラリの呼び出し / データ変換ロジック                                | 全ライブラリ                   |
| `mmdb-web`     | binary | 🔲   | Web UI (stub も未作成)                                                                    | mmdb-core                      |

---

## mmdb-whois クレート詳細設計

### 入力形式

CLI (`mmdb-creator import --whois`) は以下を受け付ける:

```bash
# ASN — カンマ区切り、AS プレフィックスあり/なし両対応
mmdb-creator import --whois --asn 64496,64497
mmdb-creator import --whois --asn AS64496,AS64497

# IP / CIDR — カンマ区切り、単一 IP は /32 として扱う
mmdb-creator import --whois --ip 192.0.2.1
mmdb-creator import --whois --ip 192.0.2.0/24
mmdb-creator import --whois --ip 192.0.2.1,192.0.2.0/24

# 組み合わせ
mmdb-creator import --whois --asn 64496 --ip 192.0.2.0/24
```

### データフロー

```
--asn  → [RIPE Stat / bgp.tools REST] → 広報 CIDR リスト
                                              ↓
--ip   → (RIPE Stat をスキップ)   → 入力 IP/CIDR をそのまま使用
                                              ↓
                              [TCP 43 whois (rate-limited)]
                                              ↓
                              [RPSL パーサー → WhoisData]
```

### Public API

```rust
/// Query by ASN: fetch announced CIDRs from RIPE Stat / bgp.tools, then query whois for each.
pub async fn query_asn(
    client: &WhoisClient,
    asn: u32,
) -> Result<Vec<(IpNet, Result<WhoisData>)>>;

/// Query by prefixes directly: skip RIPE Stat, go straight to TCP 43.
/// Single IPs are treated as /32 (IPv4) or /128 (IPv6).
pub async fn query_prefixes(
    client: &WhoisClient,
    prefixes: &[IpNet],
) -> Vec<(IpNet, Result<WhoisData>)>;
```

### WhoisClient 設定

`mmdb-core` の `WhoisConfig` を拡張:

```json
{
	"whois": {
		"server": "whois.apnic.net",
		"timeout_sec": 10,
		"rate_limit_ms": 2000,
		"max_retries": 3,
		"initial_backoff_ms": 1000,
		"ripe_stat_rate_limit_ms": 1000,
		"bgptool_rate_limit_ms": 1000
	}
}
```

| フィールド                | デフォルト | 対象                    |
| ------------------------- | ---------- | ----------------------- |
| `rate_limit_ms`           | 2000       | TCP 43 クエリ間隔       |
| `ripe_stat_rate_limit_ms` | 1000       | RIPE Stat REST API 間隔 |
| `bgptool_rate_limit_ms`   | 1000       | bgp.tools REST API 間隔 |

### User-Agent

REST API リクエストには必ず User-Agent を付与する。`Cargo.toml` のメタデータから自動生成:

```
mmdb-creator/0.1.0 (https://github.com/naa0yama/mmdb-creator)
```

実装:

```rust
// build.rs または定数として
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),
    " (", env!("CARGO_PKG_REPOSITORY"), ")"
);
```

RIPE Stat には User-Agent に加えて `sourceapp` クエリパラメーターも付与する:

```
https://stat.ripe.net/data/announced-prefixes/data.json
  ?resource=AS64496
  &sourceapp=mmdb-creator
```

### データソース (mmdb-whois 内部実装)

| ソース       | 用途                          | エンドポイント                                                                                    |
| ------------ | ----------------------------- | ------------------------------------------------------------------------------------------------- |
| RIPE Stat    | ASN → 広報 CIDR リスト        | `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=mmdb-creator` |
| bgp.tools    | 補完 / フルテーブル           | `https://bgp.tools/table.jsonl` (per-ASN REST API も使用)                                         |
| whois TCP 43 | CIDR → サブアロケーション情報 | `{config.whois.server}:43`                                                                        |

外部からはこれらのソースは不可視。`WhoisClient::query_asn()` の内部実装詳細。

---

## 移行計画

### Phase 1: mmdb-core 抽出 ✅ 完了

現 `mmdb-creator` から以下を `crates/mmdb-core/` に移動:

- `src/types.rs` → `mmdb-core/src/types.rs`
- `src/config.rs` → `mmdb-core/src/config.rs`
- `src/external.rs` → `mmdb-core/src/external.rs`

### Phase 2: mmdb-whois 抽出 ✅ 完了

- `src/import/whois.rs` → `mmdb-whois/src/`
- RIPE Stat / bgp.tools クライアントを追加実装
- `--ip` オプション対応

### Phase 3: mmdb-xlsx 新規作成 ✅ 完了

- `mmdb-xlsx/src/` に calamine + rust_xlsxwriter ラッパーを実装

### Phase 3.5: mmdb-dns 新規作成 ✅ 完了 (仕様策定後に追加)

- `mmdb-dns/src/` に Team Cymru DNS TXT lookup と PTR reverse lookup を実装
- scan フェーズの enrich 処理で使用

### Phase 4: mmdb-scan 抽出 🔲 未着手

- `crates/mmdb-creator/src/scan/` → `crates/mmdb-scan/src/`
- scamper デーモン統合実装は `2026-05-06-scan-scamper-design.md` を参照

### Phase 5: mmdb-export 抽出 🔲 未着手

- `crates/mmdb-creator/src/export/` → `crates/mmdb-export/src/`

### Phase 6: mmdb-web stub 追加 🔲 未着手

- `crates/mmdb-web/src/main.rs` に最小 stub

## Testing Strategy

- 各ライブラリクレートは独立して `cargo test -p mmdb-whois` 等で実行可能
- `mmdb-whois`: RPSL パーサーの単体テスト、rate limiter のタイミングテスト
- `mmdb-xlsx`: サンプル xlsx ファイルを使った R/W 往復テスト
- `mmdb-dns`: Cymru TXT パーサーの単体テスト
- `mmdb-scan`: scamper JSON パーサーの単体テスト (Phase 4 完了後)
- `mise run test` は `--all-targets` で全クレートをカバー

## Open Questions

- `mmdb-whois` の `query_asn` で RIPE Stat と bgp.tools の両方を叩くか、
  設定で切り替えるか (現時点は RIPE Stat primary, bgp.tools は補完)
- bgp.tools フルテーブル (`table.jsonl`) の利用タイミング
  (per-ASN API で足りない場合のフォールバック?)
