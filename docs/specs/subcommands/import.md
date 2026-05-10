# Design: `import` Subcommand

## Overview

設定ファイルに ASN と xlsx の両方が定義されていれば、引数なしで全データソースを一括取得する。
`--whois` / `--xlsx` は個別実行したい場合のフィルタ用。

```bash
mmdb-cli import                        # 設定ファイルの全ソースを実行
mmdb-cli import --whois                # whois のみ
mmdb-cli import --xlsx                 # xlsx のみ
mmdb-cli import --force                # キャッシュを削除してフルリラン
mmdb-cli import --ip 198.51.100.0/24  # CIDR 直接指定 (whois のみ、ASN ループなし)
mmdb-cli import --xlsx --ip 198.51.100.0/24  # CIDR フィルタ付き xlsx インポート
```

### Option Conflict Matrix

以下の組み合わせは Clap がパース時点でエラーとして拒否する:

| Flags              | Result      |
| ------------------ | ----------- |
| `--asn` + `--ip`   | parse error |
| `--asn` + `--xlsx` | parse error |
| `--xlsx` + `--asn` | parse error |

有効な組み合わせ:

| Flags           | Whois runs?                      | Xlsx runs?               |
| --------------- | -------------------------------- | ------------------------ |
| (no flags)      | yes (config ASNs)                | yes (all sheets)         |
| `--ip X`        | yes (CIDR X only, no ASN loop)   | no                       |
| `--xlsx`        | no                               | yes (all sheets)         |
| `--xlsx --ip X` | no                               | yes (filtered by CIDR X) |
| `--asn Y`       | yes (ASN Y only, no config ASNs) | no                       |
| `--whois`       | yes (config ASNs)                | no                       |

`--ip X` を指定した場合、設定ファイルの ASN ループは一切実行されない。
`--xlsx --ip X` の場合、xlsx 行を CIDR X に含まれる IP を持つ行のみにフィルタして取り込む。

### --force flag

`--force` を指定すると `data/cache/import/` を削除してから実行する。
共有ヘルパー `cache::clear_dir(path)` を `import/mod.rs` 先頭で呼び出す。

---

## import --whois

### ASN Announced Prefixes (REST API)

| Source    | Endpoint                                                                                      | Note                         |
| --------- | --------------------------------------------------------------------------------------------- | ---------------------------- |
| RIPE Stat | `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=mmdb-cli` | 単一参照、レートリミット緩め |

CLI は以下の入力形式を受け付ける:

```bash
# ASN — カンマ区切り、AS プレフィックスあり/なし両対応 (--ip / --xlsx と併用不可)
mmdb-cli import --whois --asn 64496,64497
mmdb-cli import --whois --asn AS64496,AS64497

# IP / CIDR — カンマ区切り、単一 IP は /32 として扱う (--asn と併用不可)
mmdb-cli import --whois --ip 198.51.100.0/24
```

Data flow:

```
--asn  → [RIPE Stat REST] → 広報 CIDR リスト
                                          ↓
--ip   → (RIPE Stat をスキップ)   → 入力 IP/CIDR をそのまま使用
                                          ↓
                          [TCP 43 whois (rate-limited)]
                                          ↓
                          [RPSL パーサー → WhoisData]
```

### whois Query (TCP 43)

whois サーバーは config.toml で指定する:

```toml
[whois]
server = "whois.apnic.net"
timeout_sec = 10
rate_limit_ms = 2000
max_retries = 3
initial_backoff_ms = 1000
ripe_stat_rate_limit_ms = 1000
```

| Field                     | Default | Scope                   |
| ------------------------- | ------- | ----------------------- |
| `rate_limit_ms`           | 2000    | TCP 43 クエリ間隔       |
| `ripe_stat_rate_limit_ms` | 1000    | RIPE Stat REST API 間隔 |

広報 CIDR を whois に問い合わせ、配下に登録されているサブアロケーションの CIDR と name を収集する。

#### Why Not RDAP?

RDAP (RFC 7480-7484) はベストマッチの1件のみを返すため、
サブアロケーションの一覧取得にはレガシー whois (TCP 43) が必須。

#### Implementation

whois プロトコル (RFC 3912):

```rust
async fn whois_query(server: &str, query: &str) -> Result<String> {
    let mut stream = TcpStream::connect((server, 43u16)).await?;
    stream.write_all(format!("{query}\r\n").as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}
```

RPSL パーサー (~180行、自前実装。`rpsl-rs` crate は依存 22MB に対して必要な機能が少ないため不採用):

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

#### User-Agent

REST API リクエストには必ず User-Agent を付与する:

```rust
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),
    " (", env!("CARGO_PKG_REPOSITORY"), ")"
);
```

RIPE Stat には User-Agent に加えて `sourceapp` クエリパラメーターも付与する。

### mmdb-whois Public API

```rust
/// Query by ASN: fetch announced CIDRs from RIPE Stat, then query whois for each.
pub async fn query_asn(
    client: &WhoisClient,
    asn: u32,
) -> Result<Vec<(IpNet, Result<WhoisData>)>>;

/// Query by prefixes directly: skip RIPE Stat, go straight to TCP 43.
pub async fn query_prefixes(
    client: &WhoisClient,
    prefixes: &[IpNet],
) -> Vec<(IpNet, Result<WhoisData>)>;
```

### Output

`data/whois-cidr.jsonl` — RIPE Stat + whois の統合出力。rotating backup あり (最大 5 世代)。

---

## import --xlsx

### mmdb-xlsx Library Crate

`mmdb-xlsx` は Excel 読み取り専用のライブラリクレート。
JSONL シリアライズ・MMDB 構築は `mmdb-cli` 側の責務。

#### Crates

| Crate             | Purpose                                          |
| ----------------- | ------------------------------------------------ |
| `calamine`        | 読み取り専用。`.xlsx`/`.xls`/`.xlsb`/`.ods` 対応 |
| `rust_xlsxwriter` | 書き込み専用 (xlsx-rows.jsonl 出力用)            |

#### Public API

```rust
/// A typed cell value parsed according to ColumnType.
#[derive(Debug, Clone, PartialEq)]
pub enum CellValue {
    String(String),
    Integer(i64),
    Bool(bool),
    Addresses(Vec<IpNet>),
}

/// A single parsed row from the spreadsheet.
#[derive(Debug, Clone)]
pub struct XlsxRow {
    pub row_index: usize,
    pub fields: IndexMap<String, CellValue>,
}

/// Result of processing one SheetConfig (one xlsx file).
#[derive(Debug)]
pub struct SheetResult {
    pub filename: String,
    pub sheetname: String,
    pub last_modified: Option<String>,
    pub rows: Vec<XlsxRow>,
    pub skipped_count: usize,
}

/// Read all matching sheets from an xlsx file.
pub fn read_xlsx(config: &SheetConfig) -> Result<Vec<SheetResult>>;

/// Inspect an xlsx file and return sheet names and header columns (used by validate --init-sheets).
pub fn inspect_sheets(config: &SheetConfig) -> Result<Vec<SheetInfo>>;
```

#### Column Type Semantics

| `ColumnType` | `CellValue` variant     | Conversion rules                                                                         |
| ------------ | ----------------------- | ---------------------------------------------------------------------------------------- |
| `String`     | `String(s)`             | Cell text as-is, trimmed                                                                 |
| `Integer`    | `Integer(i64)`          | `Data::Int` → direct; `Data::Float` → truncate; `Data::String` → parse                   |
| `Bool`       | `Bool(b)`               | `Data::Bool` → direct; `"true"`/`"1"` → true; `"false"`/`"0"` → false (case-insensitive) |
| `Addresses`  | `Addresses(Vec<IpNet>)` | Normalization pipeline (see below)                                                       |

#### Address Normalization Pipeline

Applied to every cell in an `Addresses`-typed column:

1. **Normalize newlines**: Replace `\r\n`, `\r`, `\n` with `,`
2. **Strip annotations**: Remove parenthetical text via regex `\s*\([^)]*\)` — e.g. `"198.51.100.3 (VIP: .1)"` → `"198.51.100.3"`
3. **Split and trim**: Split by `,`, trim whitespace
4. **Remove empties**: Discard empty strings
5. **Parse each token** (tried in order):
   - **CIDR**: `IpNet::from_str`
   - **Bare IP**: `IpAddr::from_str` → promote to `/32` or `/128`
   - **Range**: detect `-` between two IPs → decompose to minimal CIDRs

Invalid tokens emit a warning but do not fail the cell.

IP range decomposition (`range_to_cidrs`): operates on `u128` for both IPv4 and IPv6;
finds the largest prefix where current address is the network address and broadcast ≤ end.

#### Header Row Handling

`SheetConfig.header_row` is 1-indexed. Data rows start at `header_row` (0-indexed).
Builds `HashMap<String, usize>` from header row. Missing column → `tracing::warn!`,
field set to `CellValue::String("")`.

#### Error Handling

| Level                          | Behavior                                             |
| ------------------------------ | ---------------------------------------------------- |
| Token (within Addresses cell)  | Skip bad token, warn, keep valid ones                |
| Cell (non-Addresses)           | Skip entire row, warn with sheet/row/col/value/error |
| Row with zero valid addresses  | Count as skipped in `skipped_count`                  |
| Sheet (all rows failed)        | Return `Err`                                         |
| File (cannot open / no sheets) | Return `Err`                                         |

### Configuration

```toml
[[sheets]]
filename = "data/input/IPAM.xlsx"
header_row = 3
excludes_sheets = ["Power"]

[[sheets.columns]]
name = "host"
sheet_name = "host"
type = "string"
ptr_field = "device" # PTR capture group name; normalize.device applied at match time

[[sheets.columns]]
name = "port"
sheet_name = "port"
type = "string"
ptr_field = "interface" # normalize.interface applied at match time

[[sheets.columns]]
name = "network"
sheet_name = "Network"
type = "addresses"

[[sheets.columns]]
name = "serviceid"
sheet_name = "ServiceID"
type = "string"
```

- `ptr_field`: optional PTR capture group name for scan enrich matching.
  Must match a key in `[normalize.<name>]`. Validated by `validate` subcommand.

### Output: xlsx-rows.jsonl

One JSON object per xlsx row:

```json
{
	"_source": { "file": "IPAM.xlsx", "sheet": "border1.ty1", "row_index": 3 },
	"host": "border1",
	"site": "ty1",
	"port": "xe-0/0/1",
	"network": ["198.51.100.0/29"],
	"serviceid": "SVC-001"
}
```

- `_source`: provenance metadata (file, sheet, row_index)
- `addresses`-type columns: serialised as arrays of CIDR strings
- Raw xlsx values stored; normalization applied at scan enrich match time
- File is overwritten on each run; rotating backup applied (max 5 generations)

### Normalize Config

`[normalize.<name>]` sections define reusable value normalization rules.
Applied consistently to both PTR-captured values and xlsx column values during scan enrich.

```toml
[normalize.interface]
# Handles vendor-specific interface name formats:
#   Juniper : xe-0/0/1             → xe-0-0-1
#   Cisco   : GigabitEthernet0/0/1 → gi-0-0-1
rules = [
	{ pattern = "GigabitEthernet(\\d+)/(\\d+)/(\\d+)", replacement = "gi-$1-$2-$3" },
	{ pattern = "TenGigabitEthernet(\\d+)/(\\d+)/(\\d+)", replacement = "te-$1-$2-$3" },
	{ pattern = "/", replacement = "-" },
	{ pattern = "\\.", replacement = "-" },
]
case = "lower"
excludes = [
	"^lo\\d*$", # loopback interfaces
	"^mgmt\\d*$", # management interfaces
]

[normalize.device]
case = "lower"

[normalize.facility]
case = "lower"
```

New types in `mmdb-core/src/config.rs`:

```rust
pub struct NormalizeRule { pub pattern: String, pub replacement: String }

#[serde(rename_all = "lowercase")]
pub enum NormalizeCase { #[default] Lower, Upper, None }

pub struct NormalizeConfig {
    #[serde(default)] pub rules: Vec<NormalizeRule>,
    #[serde(default)] pub case: NormalizeCase,
    #[serde(default)] pub excludes: Vec<String>,
}
```

`Config` gains `pub normalize: HashMap<String, NormalizeConfig>`.
Patterns are compiled once at config load time into `CompiledNormalizeConfig`.

---

## File Layout

```
crates/mmdb-xlsx/
├── Cargo.toml
└── src/
    ├── lib.rs       # Public API: read_xlsx, inspect_sheets, SheetResult, XlsxRow, CellValue, SheetInfo
    ├── address.rs   # parse_addresses, range_to_cidrs
    ├── reader.rs    # Calamine workbook reading, header mapping, row iteration
    ├── filter.rs    # CIDR filter logic for xlsx rows
    ├── import.rs    # import orchestration (xlsx → xlsx-rows.jsonl)
    └── writer.rs    # XlsxRow → JSONL serialization
```

```
crates/mmdb-cli/src/import/
└── mod.rs           # import orchestration (whois + xlsx), delegates to mmdb-whois / mmdb-xlsx
```
