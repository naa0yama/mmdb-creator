# Architecture: mmdb-cli

## Background

MaxMind MMDB database を自前で作成するためのツール。
ASN が広報している CIDR リストから最も細かい CIDR 単位の MMDB を構築する。

### Why Rust?

- MMDB の書き込みライブラリは MaxMind 公式では Go (`mmdbwriter`) と Perl (`MaxMind::DB::Writer`) のみ提供
- Rust には公式 writer crate が存在しない (`maxminddb` crate は読み取り専用)
- MMDB の書き込みは `mmdbctl` (Go CLI, IPinfo 製) に委譲し、データ加工を Rust で行う方針を採用
- Excel 操作・whois パースともに Rust で十分実現可能であり、Python に固執する理由がない
- 中間ファイル (NDJSON) を経由するため、言語間の依存が発生しない

## Subcommands

| Subcommand   | Purpose                                             | Data Source                                                |
| ------------ | --------------------------------------------------- | ---------------------------------------------------------- |
| `import`     | データ収集 (whois + xlsx)                           | `--whois`: RIPE Stat / whois TCP 43, `--xlsx`: Excel files |
| `mmdb build` | 収集データを統合して MMDB を生成                    | data/*.jsonl → NDJSON → mmdbctl                            |
| `mmdb query` | MMDB ファイルで IP アドレスを検索し縦型表で表示     | data/output.mmdb (または `--mmdb` で指定)                  |
| `scan`       | CIDR の demarc 探索 (scamper ICMP-Paris traceroute) | import の出力データ (data/*.jsonl)                         |
| `validate`   | config.toml の検証 / xlsx ヘッダー検査              | config.toml, xlsx files                                    |
| `enrich`     | ログファイルに MMDB ルックアップ結果を付与          | JSON/JSONL log files + data/output.mmdb                    |

## Data Flow

```text
mmdb-cli import --whois --asn <number>
   |  1. RIPE Stat から広報 CIDR リストを取得
   |     (API レスポンスを data/cache/import/ にキャッシュ)
   |  2. 各 CIDR を whois (TCP 43) に問い合わせ
   |  3. サブアロケーション (CIDR + name) を収集
   v
data/whois-cidr.jsonl  (統合出力)

mmdb-cli import --xlsx --config config.toml
   |  1. 設定ファイルに従い data/input/*.xlsx を読み取り
   |  2. シートごとにカラムをマッピング
   |  3. より細かい CIDR (/29 etc.) + 運用情報を出力
   v
data/xlsx-rows.jsonl  (統合出力)

mmdb-cli scan
   |  1. data/whois-cidr.jsonl + data/xlsx-rows.jsonl から CIDR リストを読み込み
   |  2. CIDR に応じて対象アドレスを決定 (先後3アドレスずつ、/30 は2アドレス等)
   |  3. 各アドレスに scamper icmp-paris を実施
   |  4. スキャン途中結果を data/cache/scan/scanning.jsonl に逐次書き込み
   |  5. enrich: ASN フィルタ + PTR 解決 + whois LPM join + xlsx PTR マッチ
   v
data/scanned.jsonl  (統合出力、enrich 済、whois + gateway + xlsx を含む)

mmdb-cli mmdb build
   |  1. data/scanned.jsonl を読み込み
   |  2. ScanGwRecord → MmdbRecord 変換 (GeoLite2 互換フィールド名)
   |  3. NDJSON 中間ファイル data/output.jsonl を出力 (diff 確認用)
   |  4. mmdbctl import --json --ip 4 --size 32 で .mmdb を生成
   v
data/output.jsonl + data/output.mmdb

mmdb-cli mmdb query <ip>
   |  1. data/output.mmdb を maxminddb クレートで直接読み取り
   |  2. ネストされたフィールドをドット記法に展開
   |  3. 縦型キー/値テーブルで stdout に表示
   v
stdout (縦型テーブル)
```

## Directory Layout

```
data/
  input/                    ユーザー持ち込みファイル (xlsx 等、config.toml で参照)
  cache/
    import/                 import サブコマンドの API キャッシュ (ripestat-*, whois-cidr-*)
    scan/                   scan サブコマンドの中間ファイル
      scanning.jsonl        スキャン中の生ログ (再開用、ScanRecord)
      scanned.jsonl         enrich 済みの per-IP ScanRecord (後続 gw 解決の入力)
      scanned.*.jsonl       上記のローテーションバックアップ
  exsample/                 サンプル xlsx (committed)
  whois-cidr.jsonl          import --whois の統合出力
  whois-cidr.*.jsonl        上記のローテーションバックアップ
  xlsx-rows.jsonl           import --xlsx の統合出力 (行データ + _source)
  scanned.jsonl             scan の最終出力 (range 集約済み ScanGwRecord、enrich 済)
  scanned.*.jsonl           上記のローテーションバックアップ
  output.jsonl              mmdb build の中間 NDJSON (mmdbctl 入力 / diff 確認用)
  output.mmdb               mmdb build が生成した MMDB バイナリ (デフォルト: data/output.mmdb)
```

## Merge Strategy

MMDB のロンゲストマッチ特性を活用する。

`scanned.jsonl` はすでに whois + scan + xlsx が統合済み。各レコードの `range` が
MMDB エントリのキーになる:

- whois 由来の /24 スキャン → `/24` エントリ (whois + gateway データ)
- xlsx 由来の /30 スキャン → `/30` エントリ (whois + gateway + xlsx 運用データ)

MMDB 検索時に `/30` アドレスは `/30` エントリが最長マッチで優先される。
xlsx にない CIDR は whois レベルのエントリのみ登録され、PTR マッチが成立した
場合は xlsx 運用データが付加される。

## Workspace Layout (Multi-Crate)

凡例: ✅ 実装済み / 🔲 未実装 (将来タスク)

```
crates/
├── mmdb-cli   (binary) ✅ CLI クライアント (Clap + crate 呼び出しのみ)
├── mmdb-core  (lib)    ✅ 共有型 / Config / build 変換 (to_mmdb_record 等)
├── mmdb-dns   (lib)    ✅ Team Cymru DNS TXT lookup / PTR reverse lookup
├── mmdb-scan  (lib)    ✅ scamper 統合 / CIDR 展開 / gateway 解決 / enrich
├── mmdb-whois (lib)    ✅ RIPE Stat + TCP 43 whois + JSONL 書き出し
├── mmdb-xlsx  (lib)    ✅ Excel 読み取り + JSONL 書き出し + CIDR フィルタ
└── mmdb-web   (binary) 🔲 将来の Web UI
```

### Crate Dependency Graph

```
mmdb-cli ──► mmdb-core
         ──► mmdb-whois  ──► mmdb-core
         ──► mmdb-xlsx   ──► mmdb-core
         ──► mmdb-dns
         ──► mmdb-scan   ──► mmdb-core
                         ──► mmdb-dns
                         ──► mmdb-xlsx

mmdb-web ──► (将来)
```

### Crate Responsibilities

| Crate        | Kind   | Status | Responsibilities                                                            | Key deps                                     |
| ------------ | ------ | ------ | --------------------------------------------------------------------------- | -------------------------------------------- |
| `mmdb-core`  | lib    | ✅     | 共有型 / Config スキーマ / require_command / build 変換 (to_mmdb_record 等) | serde, ipnet, chrono                         |
| `mmdb-whois` | lib    | ✅     | ASN→CIDR (RIPE Stat) + TCP 43 whois + JSONL 書き出し                        | mmdb-core, tokio, reqwest                    |
| `mmdb-xlsx`  | lib    | ✅     | Excel 読み取り (calamine) + JSONL 書き出し + CIDR フィルタ                  | mmdb-core, tokio, calamine                   |
| `mmdb-dns`   | lib    | ✅     | Team Cymru DNS TXT + PTR reverse lookup                                     | hickory-resolver, ipnet, tokio               |
| `mmdb-scan`  | lib    | ✅     | scamper 統合 / CIDR 展開 / warts 解析 / gateway 解決 / enrich               | mmdb-core, mmdb-dns, mmdb-xlsx, tokio, regex |
| `mmdb-cli`   | binary | ✅     | Clap 引数定義 / OTel / 各 crate 呼び出し (thin client)                      | 全 lib crate                                 |
| `mmdb-web`   | binary | 🔲     | Web UI (stub も未作成)                                                      | mmdb-core                                    |

### Migration Progress

| Phase | Content                                                                    | Status  |
| ----- | -------------------------------------------------------------------------- | ------- |
| 1     | `mmdb-core` 抽出 (types, config, external)                                 | ✅ 完了 |
| 2     | `mmdb-whois` 抽出 (RIPE Stat + TCP 43 whois)                               | ✅ 完了 |
| 3     | `mmdb-xlsx` 新規作成 (calamine ラッパー)                                   | ✅ 完了 |
| 3.5   | `mmdb-dns` 新規作成 (Cymru TXT + PTR)                                      | ✅ 完了 |
| 3.6   | `build` サブコマンド実装 (ScanGwRecord → MmdbRecord + mmdbctl 呼び出し)    | ✅ 完了 |
| 4     | `mmdb-creator` → `mmdb-cli` リネーム                                       | ✅ 完了 |
| 4.1   | `mmdb-scan` 新規作成 (scan ロジック分離)                                   | ✅ 完了 |
| 4.2   | `mmdb-whois` に import 機能追加                                            | ✅ 完了 |
| 4.3   | `mmdb-xlsx` に import + filter + writer 追加                               | ✅ 完了 |
| 4.4   | `mmdb-core` に build 変換追加                                              | ✅ 完了 |
| 4.5   | `mmdb-cli` を thin client に (libs/ 削除)                                  | ✅ 完了 |
| 4.6   | `build` → `mmdb build` + `mmdb query` 追加 (`mmdb` サブコマンドグループ化) | ✅ 完了 |
| 5     | `mmdb-web` stub 追加                                                       | 🔲 将来 |

## mmdb-cli Module Layout

```
crates/mmdb-cli/src/
├── main.rs              # binary entry point
├── cli.rs               # clap subcommand definitions (Command + MmdbCommand enums)
├── backup.rs            # rotate_backup() — rotating JSONL backup
├── cache.rs             # cache::clear_dir()
├── validate.rs          # validate / validate --init-sheets / validate --ptr
├── build/
│   └── mod.rs           # mmdb build run() — thin wrapper calling mmdb-core + mmdbctl
├── mmdb_query/
│   └── mod.rs           # mmdb query run() — maxminddb direct lookup + vertical table output
├── enrich/
│   └── mod.rs           # enrich run() — JSONL log enrichment via MMDB lookup
├── import/
│   └── mod.rs           # import orchestration (whois + xlsx)
├── scan/
│   └── mod.rs           # scan orchestration thin wrapper calling mmdb-scan
└── telemetry/
    ├── mod.rs           # OTel provider init / shutdown
    ├── conventions.rs   # project-specific semantic conventions
    └── metrics/         # process metrics (OTel semconv)
```

## Rust Crate Dependencies

| Crate              | Purpose                                            |
| ------------------ | -------------------------------------------------- |
| `calamine`         | Excel 読み取り                                     |
| `serde`            | 設定ファイル・NDJSON のシリアライズ/デシリアライズ |
| `serde_json`       | JSON パース / NDJSON 生成                          |
| `maxminddb`        | MMDB ファイル読み取り (enrich サブコマンド)        |
| `tokio`            | async runtime                                      |
| `reqwest`          | HTTP クライアント (RIPE Stat API)                  |
| `clap`             | CLI 引数パース                                     |
| `ipnet`            | CIDR / IP ネットワーク操作                         |
| `anyhow`           | エラーハンドリング                                 |
| `tracing`          | 構造化ログ / トレース                              |
| `hickory-resolver` | DNS PTR reverse lookup (scan enrich フェーズ)      |
| `indicatif`        | scan TUI 進捗バー                                  |
| `regex`            | PTR パターンマッチ / normalize ルール適用          |
| `indexmap`         | xlsx カラム順序保持                                |
| `chrono`           | タイムスタンプ生成 / rotating backup ファイル名    |

## External Tools

| Tool      | Purpose               | Install                                                         |
| --------- | --------------------- | --------------------------------------------------------------- |
| `mmdbctl` | NDJSON -> .mmdb 変換  | `go install github.com/ipinfo/mmdbctl@latest` or binary release |
| `scamper` | ICMP-Paris traceroute | `apt install scamper`                                           |
