# Design: scan サブコマンド — scamper ICMP-Paris 実装

## Problem

現行 DESIGN.md は `mtr` を使った scan を想定しているが、以下の理由で要件を満たせない:

- `mtr` は ECMP 非対応 (ホップ単位の集計でパスが混在する)
- 1 ターゲット = 1 プロセスのため 5000 IP 処理時にプロセス管理が煩雑
- pps 制御が Rust 側のセマフォに依存し、実際の送信レートが見えにくい

## Goals

- ECMP 区間でも安定したパスを追跡できる (ICMP-Paris)
- 5000 IP をネットワーク負荷を制御しながら非同期スキャン
- TUI によるリアルタイム進捗表示
- 再実行時に完了済み IP をスキップ (scan.jsonl との差分で判定)
- Ctrl+C や異常終了時もバッファを flush してデータを保護
- scamper デーモンのライフサイクルを Rust が完全管理 (事前起動不要)

## Non-Goals

- scan 中のリアルタイム ASN 付与 (post-scan フェーズで処理)
- TCP / UDP プローブ (ICMP のみ)
- IPv6 の scan (Phase 1 は IPv4 のみ)

## Approach

**scamper デーモンモード + Unix ソケット** を採用する。

- 1 プロセスで全 5000 ターゲットを管理し、`-p <pps>` でグローバル pps を制御
- Rust が scan 開始時にデーモンを spawn し、終了時に kill する
- 結果は 1 IP 単位でソケットから返り、バッファ経由で bulk flush する

mtr バッチ案 (案 A) を採用しなかった理由: ターゲットリストが確定している場合でも、
デーモンモードの方が pps 制御の精度が高く (中央スケジューラー)、
かつ完了粒度が細かいため resume 精度で優る。

## Implementation Notes

### 1. scamper デーモンのライフサイクル

```
scan 開始
  ├─ scamper -D -U /tmp/mmdb-creator-<pid>.sock -p <pps> を spawn
  ├─ ソケットが ready になるまでポーリング (最大 3 秒, 100ms 間隔)
  └─ UnixStream::connect で接続

scan 終了 / Ctrl+C / panic
  ├─ writer タスクに shutdown シグナル送信 → バッファを flush
  ├─ child.kill().await でデーモンを終了
  └─ ソケットファイルを削除
```

### 2. ソケットプロトコル

scamper デーモンとのやり取りはテキストベース:

```
Rust → デーモン:
  "attach\n"                                         # セッション開始
  "trace -P icmp-paris -q 3 192.0.2.1\n"            # ターゲット投入
  "trace -P icmp-paris -q 3 198.51.100.1\n"
  ...

デーモン → Rust (完了した順に JSON で返る):
  {
    "type": "trace", "method": "icmp-echo-paris",
    "src": "172.31.164.174", "dst": "192.0.2.1",
    "stop_reason": "GAPLIMIT",
    "hops": [
      { "addr": "192.0.2.1", "probe_ttl": 1, "probe_id": 1, "rtt": 0.232 },
      { "addr": "192.0.2.1", "probe_ttl": 1, "probe_id": 2, "rtt": 0.241 },
      { "addr": "192.0.2.1", "probe_ttl": 1, "probe_id": 3, "rtt": 0.228 }
    ]
  }
```

**mtr との主な差分:**

| 項目                   | mtr                                | scamper                                             |
| ---------------------- | ---------------------------------- | --------------------------------------------------- |
| ホップの IP フィールド | `host`                             | `addr`                                              |
| ホップ番号フィールド   | `count`                            | `probe_ttl`                                         |
| 1 ホップのエントリ数   | 1 件 (集計済み)                    | probe 数分 (`-q 3` なら 3 件)                       |
| RTT                    | `Avg`/`Best`/`Wrst` として集計済み | 各 probe の `rtt` を個別に保持                      |
| ASN                    | `"ASN": "AS64497"` として含まれる  | **なし** (post-scan enrich で付与)                  |
| 到達不能ホップ (`*`)   | `host: "???"` エントリあり         | エントリ自体が存在しない (TTL がスキップ)           |
| トレース終了理由       | なし                               | `stop_reason`: `GAPLIMIT` / `COMPLETED` / `UNREACH` |

**パース処理 (Rust 側):**

ICMP-Paris は全プローブで `icmp_sum` を固定するため、同一 `probe_ttl` に異なる `addr` は
来ないことが保証される。グルーピングは `probe_ttl` 単位で十分。

1. `hops` を `probe_ttl` でグルーピング
2. 同一 `probe_ttl` グループの `rtt` から avg / best / worst を算出
3. 同一 `probe_ttl` に複数の `addr` が出た場合は**異常系**として扱う
   - `tracing::warn!` を出して多数決で代表 addr を選択
   - 原因: ICMP checksum を無視するルーター / anycast / 測定中のトポロジー変化
4. `probe_ttl` の歯抜け箇所 (応答なし) を `ip: null` ホップとして補完
5. `stop_reason` を記録 (`COMPLETED` = 宛先到達, `GAPLIMIT` = 連続無応答で終了)

```
通常ケース (ICMP-Paris 保証):
  probe_ttl=1, probe_id=1, addr=A
  probe_ttl=1, probe_id=2, addr=A  →  hop=1, ip=A, avg=0.234, best=0.228, worst=0.241
  probe_ttl=1, probe_id=3, addr=A

異常ケース (warn! を出して多数決):
  probe_ttl=3, probe_id=1, addr=X
  probe_ttl=3, probe_id=2, addr=Y  →  hop=3, ip=X (warn: multiple addrs at ttl=3)
  probe_ttl=3, probe_id=3, addr=X
```

- 並列ウィンドウサイズ (同時投入数) は設定可能 (デフォルト: 100)
- 結果は投入順ではなく完了順に返る

### 3. resume (スキップ機能)

scan 開始時に `data/scan.jsonl` を読み込み、完了済みの CIDR を抽出する。
ターゲットリストから差分を取り `remaining` だけを投入する。

```
total    = import データから生成したターゲット IP リスト
done     = scan.jsonl に記録済みの IP セット
remaining = total - done
```

TUI 上で "Skipped (cached): N" として表示する。

### 4. scamper JSON → 出力 JSON マッピング

#### `RouteData` フィールド

| 出力フィールド | scamper ソース             | 型         | 備考                                 |
| -------------- | -------------------------- | ---------- | ------------------------------------ |
| `version`      | `version`                  | `String`   | scamper のバージョン文字列           |
| `measured_at`  | `start.sec` + `start.usec` | `String`   | ISO 8601 UTC に変換                  |
| `source`       | `src`                      | `String`   | プローブ送信元 IP                    |
| `destination`  | `dst`                      | `String`   | 対象 IP                              |
| `stop_reason`  | `stop_reason`              | `String`   | `COMPLETED` / `GAPLIMIT` / `UNREACH` |
| `hops`         | `hops` (グルーピング後)    | `Vec<Hop>` |                                      |

#### `Hop` フィールド (probe_ttl でグルーピング後)

| 出力フィールド | scamper ソース                   | 型               | 備考                                  |
| -------------- | -------------------------------- | ---------------- | ------------------------------------- |
| `hop`          | `probe_ttl`                      | `u32`            | 1-indexed                             |
| `ip`           | `addr`                           | `Option<String>` | 無応答ホップは `null`                 |
| `rtt_avg`      | `rtt` の平均                     | `Option<f64>`    | 無応答は `null`                       |
| `rtt_best`     | `rtt` の最小                     | `Option<f64>`    | 無応答は `null`                       |
| `rtt_worst`    | `rtt` の最大                     | `Option<f64>`    | 無応答は `null`                       |
| `icmp_type`    | `icmp_type`                      | `Option<u8>`     | 11=TTL超過 / 0=到達 / 無応答は `null` |
| `asn`          | TBD                              | `Option<u32>`    | キーのみ保持、取得方法は後で検討      |
| `ptr`          | DNS reverse lookup (post-enrich) | `Option<String>` |                                       |

#### 出力例 (`data/scan.jsonl` の1行)

```json
{
	"range": "192.0.2.0/29",
	"routes": {
		"version": "0.1",
		"measured_at": "2026-05-06T01:20:26Z",
		"source": "172.31.164.174",
		"destination": "192.0.2.1",
		"stop_reason": "GAPLIMIT",
		"hops": [
			{
				"hop": 1,
				"ip": "192.0.2.1",
				"rtt_avg": 0.234,
				"rtt_best": 0.228,
				"rtt_worst": 0.241,
				"icmp_type": 11,
				"asn": null,
				"ptr": null
			},
			{
				"hop": 2,
				"ip": null,
				"rtt_avg": null,
				"rtt_best": null,
				"rtt_worst": null,
				"icmp_type": null,
				"asn": null,
				"ptr": null
			}
		]
	}
}
```

### 5. バッファリングと flush 戦略

mpsc チャネルで scan ループと writer タスクを分離する。

**flush トリガー (OR 条件):**

- バッファ件数 >= 100 件
- 前回 flush から 5 秒経過

**強制 flush トリガー:**

- shutdown シグナル受信時 (Ctrl+C / 正常終了)
- panic hook 経由の同期 flush (Mutex で保護したバッファを直接書き出す)

```
scan ループ ──result──► mpsc channel ──► writer タスク
                                              │
                                    ┌─ 100件 OR 5秒 ─► append to scan.jsonl
                                    └─ shutdown      ─► flush all + exit
```

### 6. Post-scan ASN・PTR 付与 (2 フェーズ)

scan フェーズでは IP のみ収集し、ASN・PTR は scan 完了後に一括処理する。

**Phase 1 (scan):** ホップ IP・RTT・icmp_type を収集、ASN・PTR は `null` で scan.jsonl に書き込む

**Phase 2 (enrich):** scan 完了後に実行

- 全ホップ IP を重複排除
- Team Cymru WHOIS bulk (`whois.cymru.com:43`) で ASN を一括取得
- DNS reverse lookup で PTR を一括解決
- scan.jsonl を上書き更新

### 7. TUI 表示

`indicatif` クレートを使用 (ratatui より軽量で進捗バー用途に最適)。
既存の tracing/OTel レイヤーと競合しないよう `tracing-indicatif` を組み合わせる。

```
Scanning  [=========>-----------]  2134/5000  42%
  Rate: 18.3 IP/s   ETA: 3m 09s
  Done: 2134   Skipped: 823   Failed: 6
```

### 8. Config 追加フィールド

`ScanConfig` を新設する:

```json
{
	"scan": {
		"pps": 50,
		"probes": 3,
		"window": 100,
		"flush_count": 100,
		"flush_interval_sec": 5
	}
}
```

| フィールド           | デフォルト | 説明                          |
| -------------------- | ---------- | ----------------------------- |
| `pps`                | 50         | scamper グローバル pps 上限   |
| `probes`             | 3          | ホップあたりプローブ数 (`-q`) |
| `window`             | 100        | 同時投入ターゲット数          |
| `flush_count`        | 100        | バッファ flush 件数閾値       |
| `flush_interval_sec` | 5          | バッファ flush 時間閾値 (秒)  |

### 9. 変更対象ファイル

| ファイル             | 変更内容                              |
| -------------------- | ------------------------------------- |
| `src/config.rs`      | `ScanConfig` 追加                     |
| `src/scan/mod.rs`    | scan オーケストレーター実装           |
| `src/scan/daemon.rs` | scamper デーモン起動・終了管理        |
| `src/scan/socket.rs` | Unix ソケット送受信・JSON パース      |
| `src/scan/writer.rs` | バッファリング writer タスク          |
| `src/scan/enrich.rs` | post-scan ASN + PTR 付与              |
| `src/scan/resume.rs` | scan.jsonl 読み込みとスキップ判定     |
| `Cargo.toml`         | `indicatif`, `tracing-indicatif` 追加 |

### 10. 外部ツール要件

| ツール    | 用途                  | インストール          |
| --------- | --------------------- | --------------------- |
| `scamper` | ICMP-Paris traceroute | `apt install scamper` |

## Testing Strategy

1. `mise run build` — コンパイル確認
2. 単体テスト:
   - RPSL JSON パーサー (scamper JSON → `ScanResult` 変換)
   - resume ロジック (既存 scan.jsonl からのスキップ判定)
   - バッファ flush トリガー (件数・時間の両条件)
3. 統合テスト (手動):
   - `mmdb-creator scan` でローカル環境に対してスキャン実行
   - 途中 Ctrl+C → 再実行でスキップ件数が正しいことを確認
4. `mise run pre-commit` — lint/format 通過

## Open Questions

- scamper のソケットプロトコルの正確な仕様 (warts vs JSON 出力モードの選択方法) は実装時に man page で確認する
- Team Cymru WHOIS bulk の rate limit は whois.apnic.net と同様に未公開のため、2 秒 delay を初期値とする
