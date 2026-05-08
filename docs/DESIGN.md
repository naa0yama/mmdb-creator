# mmdb-creator Design Document

## Background

MaxMind MMDB database を自前で作成するためのツール。
ASN が広報している CIDR リストから最も細かい CIDR 単位の MMDB を構築する。

### Why Rust?

- MMDB の書き込みライブラリは MaxMind 公式では Go (`mmdbwriter`) と Perl (`MaxMind::DB::Writer`) のみ提供
- Rust には公式 writer crate が存在しない (`maxminddb` crate は読み取り専用)
- MMDB の書き込みは `mmdbctl` (Go CLI, IPinfo 製) に委譲し、データ加工を Rust で行う方針を採用
- Excel 操作・whois パースともに Rust で十分実現可能であり、Python に固執する理由がない
- 中間ファイル (NDJSON) を経由するため、言語間の依存が発生しない

## Architecture

```text
+------------------+     +-------------------+
| mmdb-creator     |     | mmdbctl           |
| (Rust CLI)       | --> | (Go CLI)          |
|                  |     |                   |
| Subcommands:     |     | Input:  NDJSON    |
|   whois          |     | Output: .mmdb     |
|   import         |     +-------------------+
|   export         |
+------------------+
```

### Subcommands

| Subcommand | Purpose                                             | Data Source                                                |
| ---------- | --------------------------------------------------- | ---------------------------------------------------------- |
| `import`   | データ収集 (whois + xlsx)                           | `--whois`: RIPE Stat / whois TCP 43, `--xlsx`: Excel files |
| `export`   | 収集データを統合して MMDB を生成                    | data/*.jsonl → NDJSON → mmdbctl                            |
| `scan`     | CIDR の demarc 探索 (scamper ICMP-Paris traceroute) | import の出力データ (data/*.jsonl)                         |

### Data Flow

```text
mmdb-creator import --whois --asn <number>
   |  1. RIPE Stat から広報 CIDR リストを取得
   |     (API レスポンスを data/cache/import/ にキャッシュ)
   |  2. 各 CIDR を whois (TCP 43) に問い合わせ
   |  3. サブアロケーション (CIDR + name) を収集
   v
data/whois-cidr.jsonl  (統合出力)

mmdb-creator import --xlsx --config config.json
   |  1. 設定ファイルに従い data/input/*.xlsx を読み取り
   |  2. シートごとにカラムをマッピング
   |  3. より細かい CIDR (/29 etc.) + 運用情報を出力
   v
data/import.jsonl  (統合出力)

mmdb-creator export --out output.mmdb
   |  1. data/whois-cidr.jsonl + data/import.jsonl を読み込み
   |  2. ロンゲストマッチ優先で最も細かい CIDR を採用
   |     - xlsx に /29 があればそちらを登録
   |     - 該当なければ /28, /27, ... /19 と上位を検索
   |  3. NDJSON 中間ファイルを出力 (diff 確認用、git 管理可能)
   |  4. mmdbctl import で .mmdb を生成
   v
output/merged.jsonl + output/output.mmdb

mmdb-creator scan
   |  1. data/whois-cidr.jsonl から CIDR リストを読み込み
   |  2. CIDR に応じて対象アドレスを決定:
   |     - /32 or 単一アドレス: そのアドレス1つ
   |     - /30: 有効アドレス 2つ (NW, BC 除外)
   |     - /29 以上: 前後3アドレスずつ (NW, BC 除外)
   |  3. 各アドレスに scamper icmp-paris を実施
   |  4. スキャン途中結果を data/cache/scan/scanning.jsonl に逐次書き込み
   |  5. enrich: ASN フィルタ + PTR 解決
   v
data/scanned.jsonl  (統合出力、enrich 済)
```

### Directory Layout

```
data/
  input/              ユーザー持ち込みファイル (xlsx 等、config.toml で参照)
  cache/
    import/           import サブコマンドの API キャッシュ (ripestat-*, whois-cidr-*)
    scan/             scan サブコマンドの途中結果
      scanning.jsonl  スキャン中の一時ファイル (再開可能)
  exsample/           サンプル xlsx (committed)
  whois-cidr.jsonl    import --whois の統合出力
  import.jsonl        import --xlsx の統合出力
  scanned.jsonl       scan の最終出力 (enrich 済)
```

### Merge Strategy (export)

MMDB のロンゲストマッチ特性を活用する:

- whois: 粗い粒度 (e.g., /19) のインターネット公開情報
- xlsx: 細かい粒度 (e.g., /29) の運用情報

export 時の優先順位:

1. xlsx に該当 CIDR があればそのデータを登録 (最も細かい)
2. なければ whois のデータをフォールバックとして登録
3. MMDB 検索時にロンゲストマッチで最も具体的なエントリが引き当たる

## Subcommand: `import`

設定ファイルに ASN と xlsx の両方が定義されていれば、引数なしで全データソースを一括取得する。
`--whois` / `--xlsx` は個別実行したい場合のフィルタ用。

```bash
mmdb-creator import --config config.json           # 設定ファイルの全ソースを実行
mmdb-creator import --config config.json --whois   # whois のみ
mmdb-creator import --config config.json --xlsx    # xlsx のみ
```

### `import --whois`

```bash
mmdb-creator import --config config.json --whois
```

### ASN Announced Prefixes (REST API)

| Source    | Endpoint                                                                   | Note                         |
| --------- | -------------------------------------------------------------------------- | ---------------------------- |
| RIPE Stat | `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}` | 単一参照、レートリミット緩め |

### whois Query (TCP 43)

whois サーバーは設定ファイルで指定する:

```json
{
	"whois": {
		"server": "whois.example.net",
		"timeout_sec": 10
	}
}
```

広報 CIDR (e.g., `133.0.0.0/8`) を whois に問い合わせ、
配下に登録されているサブアロケーション (e.g., `/29` 単位) の CIDR と name を収集する。

#### Why Not RDAP?

RDAP (RFC 7480-7484) はベストマッチの1件のみを返すため、
サブアロケーションの一覧取得にはレガシー whois (TCP 43) が必須。

#### Implementation

whois プロトコル (RFC 3912) は非常にシンプル:

1. TCP port 43 に接続
2. クエリ文字列 + `\r\n` を送信
3. レスポンスを EOF まで読み取り

Rust での実装は ~10行程度。専用 crate は不要。

```rust
async fn whois_query(server: &str, query: &str) -> Result<String> {
    let mut stream = TcpStream::connect((server, 43u16)).await?;
    stream.write_all(format!("{query}\r\n").as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}
```

#### Response Parsing

RPSL パーサーは自前実装 (~180行)。`rpsl-rs` crate は検討したが依存 22MB に対して
必要な機能が少ないため不採用。

パースルール:

- `key:` + 値 (コロン以降の空白を trim)
- 次行が空白始まりなら継続行 (multiline value)
- 空行でオブジェクト区切り
- `%` / `#` 始まりはコメント (スキップ)

抽出対象フィールド:

| Field           | Purpose                 |
| --------------- | ----------------------- |
| `inetnum`       | IP レンジ (CIDR に変換) |
| `netname`       | ネットワーク名          |
| `descr`         | 説明                    |
| `country`       | 国コード                |
| `last-modified` | 最終更新日時            |
| `source`        | データソース RIR        |

remarks 等の定型コメントフィールドは価値がないため無視する。

### `import --xlsx`

```bash
mmdb-creator import --config config.json --xlsx
```

### Excel Reading

#### Crate: `calamine` (read)

- 読み取り専用、`.xlsx` / `.xls` / `.xlsb` / `.ods` 対応
- crates.io 7.5M DL、月次リリース、活発にメンテナンス

#### Crate: `rust_xlsxwriter` (write)

- 書き込み専用、新規 `.xlsx` 作成・シート追加が可能
- Python `XlsxWriter` と同一作者 (jmcnamara)、Issue close率 96%
- 装飾不要のデータ出力用途に最適
- `umya-spreadsheet` (読み書き一体) も検討したが、最終リリースが 8ヶ月前で
  メンテナンスリスクがあるため `calamine` + `rust_xlsxwriter` の2 crate 構成を採用

### Configuration

Excel ファイルごとにシート・カラムのマッピングを設定ファイルで定義する。

```json
{
	"sheets": [
		{
			"filename": "sheets_A.xlsx",
			"excludes_sheets": ["Power"],
			"header_row": 1,
			"columns": [
				{
					"name": "region",
					"sheet_name": "Region",
					"type": "string"
				},
				{
					"name": "cableid",
					"sheet_name": "CableID",
					"type": "integer"
				},
				{
					"name": "demarc_pe",
					"sheet_name": "PE demarc",
					"type": "addresses"
				},
				{
					"name": "demarc_ce",
					"sheet_name": "CE demarc",
					"type": "addresses"
				}
			]
		}
	]
}
```

- `filename`: Excel ファイルパス
- `excludes_sheets`: 読み込みをスキップするシート名リスト
- `header_row`: ヘッダー行番号 (1-indexed)
- `columns[].name`: 出力時のフィールド名
- `columns[].sheet_name`: Excel 上のカラム名 (シートごとに異なる場合がある)
- `columns[].type`: データ型 (`string`, `integer`, `addresses` など)
  - `addresses`: IPv4 と IPv6 の両方を許容するアドレス型

## Subcommand: `export`

```bash
mmdb-creator export --out output.mmdb
```

### Output Files

| File           | Purpose                                                          |
| -------------- | ---------------------------------------------------------------- |
| `output.jsonl` | マージ済みデータの NDJSON。diff で変更点を追跡可能。git 管理向き |
| `output.mmdb`  | mmdbctl で生成した MMDB バイナリ                                 |

JSONL を常に出力しておくことで:

- 前回との diff が取れる (何が変わったか一目瞭然)
- mmdb 生成に失敗しても中間データが残る
- デバッグ・目視確認が容易

### MMDB Writing: mmdbctl

IPinfo の `mmdbctl` CLI を使用して MMDB ファイルを生成する。

#### Why mmdbctl?

- 内部で MaxMind 公式 `mmdbwriter` (Go) を使用しており信頼性が高い
- NDJSON 入力で型情報 (int, float, bool, nested object) を保持できる
- CSV 入力は全て string 型になるため NDJSON 一択

#### NDJSON Input Format

- 1行1 JSON オブジェクト (NDJSON / JSON Lines)
- `range` key に CIDR or 単一アドレス (/32, /128) を指定 → MMDB ツリーのキーになる
- それ以外の key が MMDB のデータフィールドになる

#### Record Schema (merged.jsonl / MMDB)

GeoLite2-City + ASN 互換フィールド + カスタムフィールド:

```json
{
	"range": "192.0.2.0/29",
	"created_at": "2026-05-05T00:00:00Z",
	"updated_at": "2026-05-05T12:00:00Z",

	"continent": {
		"code": "AS"
	},
	"country": {
		"iso_code": "JP"
	},

	"autonomous_system_number": 64496,
	"autonomous_system_organization": "Example Corp",

	"whois": {
		"inetnum": "192.0.2.0 - 192.0.2.7",
		"netname": "EXAMPLE-NET",
		"descr": "Example Network",
		"source": "APNIC",
		"last_modified": "2025-01-15T00:00:00Z"
	},

	"operational": {
		"filename": "sheets_A.xlsx",
		"sheetname": "Tokyo-DC",
		"last_modified": "2026-04-01T00:00:00Z",
		"region": "Tokyo",
		"cableid": 12345,
		"demarc_pe": "198.51.100.1",
		"demarc_ce": "198.51.100.2"
	},

	"routes": {
		"measured_at": "2026-05-05T10:00:00Z",
		"source": "198.51.100.100",
		"destination": "192.0.2.1",
		"hops": [
			{ "ip": "198.51.100.1", "asn": 64497, "ptr": "ae0.cr1.tyo1.example.net" },
			{ "ip": "198.51.100.5", "asn": 64496, "ptr": "ge0.pe1.tyo1.example.net" }
		]
	}
}
```

**GeoLite2 互換フィールド:**

- `continent.code` — whois `country` から静的マッピング (後回し可)
- `country.iso_code` — whois `country` から
- `autonomous_system_number` / `autonomous_system_organization` — RIPE Stat

**カスタムフィールド:**

- `created_at` / `updated_at` — レコードの作成・更新日時
- `whois` — whois 由来データ
- `operational` — xlsx 由来データ (ファイル名・シート名・更新日時を含む)
- `routes` — scan 由来の経路データ

**PTR 解決の戦略:**

- scamper 実行時は IP + RTT のみ収集 (PTR は引かない)
- scan 完了後、全ホップ IP を重複排除して一括で PTR クエリ
- 結果を hops に紐づけて保存

#### Key Options

| Flag      | Default | Note                                           |
| --------- | ------- | ---------------------------------------------- |
| `--ip`    | `6`     | IPv4 データなら `--ip 4` を明示                |
| `--size`  | `32`    | Record size: 24, 28, 32                        |
| `--merge` | `none`  | 重複時: `none` (上書き), `toplevel`, `recurse` |

## Subcommand: `scan`

```bash
mmdb-creator scan
```

import で収集した CIDR データを元に demarc 探索を行う。
実装の詳細設計は `docs/specs/2026-05-06-scan-scamper-design.md` を参照。

### Probe Tool: scamper

`mtr` の代わりに `scamper` デーモンを使用する:

| 比較項目   | mtr (旧)             | scamper (現行)                |
| ---------- | -------------------- | ----------------------------- |
| ECMP 対応  | なし (単一パスのみ)  | ICMP-Paris (フローID固定)     |
| 並列制御   | 1プロセス/ターゲット | 1デーモンで全ターゲットを管理 |
| pps 制御   | 困難                 | `pps` パラメーターで一元管理  |
| プロトコル | ICMP/UDP/TCP         | ICMP-Paris traceroute         |

scamper デーモンを Rust から起動し、Unix ソケット経由でコマンドを送信する。
5000 アドレスに対して `pps=50` で ~10-15 分で完了する想定。

### Target Address Selection

| CIDR                 | 有効アドレス数 | 対象                   |
| -------------------- | -------------- | ---------------------- |
| `/32` (単一アドレス) | 1              | そのアドレス1つ        |
| `/30`                | 2              | 有効アドレス全て (2つ) |
| `/29` 以上           | 6+             | 先頭3つ + 末尾3つ      |

- ネットワークアドレスとブロードキャストアドレスは常に除外
- `/30` は特殊ケース: NW/BC を除くと2アドレスのみなので全数実施
- `/29` 以上は前後3アドレスずつ探索 (demarc は CIDR の端に配置されることが多いため)

### Data Collection (2段階)

**Phase 1: scamper 実行 (並列)**

- scamper デーモンに `trace -P icmp-paris -q <probes> <target>` を投入
- IP + RTT のみ収集 (PTR は引かない → 高速)
- ウィンドウサイズ (`window`) で同時投入数を制御

**Phase 2: PTR 解決 + Team Cymru ASN enrich (一括)**

- Phase 1 で収集した全ホップ IP を重複排除
- Team Cymru DNS (`mmdb-dns` クレート) で ASN を一括取得
- 並列 DNS reverse lookup (PTR) で `hickory-resolver` を使用

### Hop Filtering & Renumbering

scamper の全ホップから **対象 ASN のホップのみ** を抽出し、hop 番号を振り直す:

```
scamper 生出力 (全経路):
  ttl=1: 172.31.160.1   AS???    ← 自ネットワーク (除外)
  ttl=2: 203.0.113.1    AS64497  ← transit (除外)
  ttl=3: 198.51.100.1   AS64496  ← 対象 ASN (採用, hop=1)
  ttl=4: 198.51.100.5   AS64496  ← 対象 ASN (採用, hop=2)
  ttl=5: 192.0.2.1      AS64496  ← destination (採用, hop=3)

フィルタ後 (対象 ASN のみ、hop 振り直し):
  hop=1: 198.51.100.1  AS64496
  hop=2: 198.51.100.5  AS64496
  hop=3: 192.0.2.1     AS64496
```

これにより routes.hops には自 ASN 内の経路のみが格納され、
POP/interface の特定に必要な情報だけが残る。

### Output

`data/scan.jsonl` に結果を保存。

`routes` 構造:

```json
{
	"range": "192.0.2.0/29",
	"routes": {
		"measured_at": "2026-05-05T10:00:00Z",
		"source": "198.51.100.100",
		"destination": "192.0.2.1",
		"hops": [
			{ "hop": 1, "ip": "198.51.100.1", "asn": 64496, "ptr": "ae0.cr1.tyo1.example.net" },
			{ "hop": 2, "ip": "198.51.100.5", "asn": 64496, "ptr": "ge0.pe1.tyo1.example.net" },
			{ "hop": 3, "ip": "192.0.2.1", "asn": 64496, "ptr": null }
		]
	}
}
```

scan の結果は export 時に whois/import データとマージされ、MMDB エントリの
`routes` フィールドとして格納される。

## Rust Crate Dependencies

| Crate              | Purpose                                            |
| ------------------ | -------------------------------------------------- |
| `calamine`         | Excel 読み取り                                     |
| `rust_xlsxwriter`  | Excel 書き出し                                     |
| `serde`            | 設定ファイル・NDJSON のシリアライズ/デシリアライズ |
| `serde_json`       | JSON パース / NDJSON 生成                          |
| `tokio`            | async runtime                                      |
| `reqwest`          | HTTP クライアント (RIPE Stat API)                  |
| `clap`             | CLI 引数パース                                     |
| `ipnet`            | CIDR / IP ネットワーク操作                         |
| `anyhow`           | エラーハンドリング                                 |
| `tracing`          | 構造化ログ / トレース                              |
| `hickory-resolver` | DNS PTR reverse lookup (scan enrich フェーズ)      |
| `indicatif`        | scan TUI 進捗バー                                  |

## External Tools

| Tool      | Purpose               | Install                                                         |
| --------- | --------------------- | --------------------------------------------------------------- |
| `mmdbctl` | NDJSON -> .mmdb 変換  | `go install github.com/ipinfo/mmdbctl@latest` or binary release |
| `scamper` | ICMP-Paris traceroute | `apt install scamper`                                           |
