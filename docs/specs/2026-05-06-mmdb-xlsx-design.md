# Design: `mmdb-xlsx` Library Crate

## Problem

The `mmdb-creator` binary stubs xlsx import at
`crates/mmdb-creator/src/import/mod.rs:53-56` (logs sheet count only).
Excel reading logic — address parsing, type conversion, normalization —
needs a dedicated library crate so it can be tested independently and
reused by the planned `mmdb-web` binary.
This is Phase 3 of the workspace split plan
(`docs/specs/2026-05-06-workspace-split-design.md`).

## Goals

- Provide a synchronous, read-only library that accepts `SheetConfig` and
  returns row-level records with typed cell values
- Parse all address formats found in real IPAM spreadsheets:
  CIDR, bare IP, comma/newline-separated lists, VIP annotations, IP ranges
- Return **row-granularity** data; fan-out to per-address records is the
  caller's responsibility (mmdb-creator / export)
- Skip unparseable rows gracefully with `tracing::warn!` diagnostics
- Add `Bool` variant to `ColumnType` in mmdb-core

## Non-Goals

- Writing xlsx files (`rust_xlsxwriter` not needed)
- JSONL serialization (stays in mmdb-creator)
- MMDB tree construction or mmdbctl integration
- Async I/O (calamine is synchronous, files are local)
- Auto-detection of column types from xlsx data

## Approach

### Public API

```rust
// crates/mmdb-xlsx/src/lib.rs

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
    /// 0-indexed row number relative to data start.
    pub row_index: usize,
    /// Column values keyed by ColumnMapping.name (config-specified order).
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
///
/// Returns one SheetResult per processed sheet (excludes_sheets filtered out).
///
/// # Errors
///
/// - File cannot be opened
/// - No sheets remain after filtering
/// - ALL data rows in a sheet fail to parse
pub fn read_xlsx(config: &SheetConfig) -> Result<Vec<SheetResult>>;
```

### Column type semantics

| `ColumnType` | `CellValue` variant     | Conversion rules                                                                         |
| ------------ | ----------------------- | ---------------------------------------------------------------------------------------- |
| `String`     | `String(s)`             | Cell text as-is, trimmed                                                                 |
| `Integer`    | `Integer(i64)`          | `Data::Int` → direct; `Data::Float` → truncate; `Data::String` → parse                   |
| `Bool`       | `Bool(b)`               | `Data::Bool` → direct; `"true"`/`"1"` → true; `"false"`/`"0"` → false (case-insensitive) |
| `Addresses`  | `Addresses(Vec<IpNet>)` | Normalization pipeline (see below)                                                       |

### Address normalization pipeline

Applied to every cell in an `Addresses`-typed column.

```
fn parse_addresses(raw: &str) -> (Vec<IpNet>, Vec<AddressWarning>)
```

Steps in order:

1. **Normalize newlines**: Replace `\r\n`, `\r`, `\n` with `,`
2. **Strip annotations**: Remove parenthetical text via regex `\s*\([^)]*\)`
   - `"192.0.2.3 (VIP: .1)"` → `"192.0.2.3"`
3. **Split and trim**: Split by `,`, trim whitespace
4. **Remove empties**: Discard empty strings
5. **Parse each token** as one of (tried in order):
   - **CIDR**: `IpNet::from_str` — `"192.0.2.0/30"` → `192.0.2.0/30`
   - **Bare IP**: `IpAddr::from_str` → promote to `/32` or `/128`
   - **Range**: detect `-` between two IPs → decompose to minimal CIDRs

Invalid tokens emit a warning but do not fail the cell; other valid
addresses are still collected.

### IP range decomposition

```
fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Result<Vec<IpNet>>
```

Algorithm (operates on `u128` for both IPv4 and IPv6):

1. Validate: same address family, start ≤ end
2. While current ≤ end:
   a. Find largest prefix where current is network address and
   broadcast ≤ end
   b. Emit that CIDR
   c. Advance current past broadcast

No external crate needed; < 30 lines.

### Header row handling

`SheetConfig.header_row` is 1-indexed. Calamine rows are 0-indexed.

- Header row index: `header_row - 1`
- Data rows start at: `header_row` (0-indexed)
- All rows before header (type hints, layer groups) are ignored

Build `HashMap<String, usize>` from header row (column name → column index).
Look up each `ColumnMapping.sheet_name` in this map. Missing column →
`tracing::warn!`, field set to `CellValue::String("")`.

### Error handling

| Level                          | Behavior                                             |
| ------------------------------ | ---------------------------------------------------- |
| Token (within Addresses cell)  | Skip bad token, warn, keep valid ones                |
| Cell (non-Addresses)           | Skip entire row, warn with sheet/row/col/value/error |
| Row with zero valid addresses  | Count as skipped in `skipped_count`                  |
| Sheet (all rows failed)        | Return `Err`                                         |
| File (cannot open / no sheets) | Return `Err`                                         |

### File last_modified

Populated from `std::fs::metadata` → `modified()` → ISO 8601 UTC.
If metadata unavailable, set to `None`.

## Config changes (mmdb-core)

Add `Bool` to `ColumnType` in `crates/mmdb-core/src/config.rs:154-161`:

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColumnType {
    String,
    Integer,
    Addresses,
    Bool,       // new
}
```

## File layout

```
crates/mmdb-xlsx/
├── Cargo.toml
└── src/
    ├── lib.rs       # Public API: read_xlsx, SheetResult, XlsxRow, CellValue
    ├── address.rs   # parse_addresses, range_to_cidrs
    └── reader.rs    # Calamine workbook reading, header mapping, row iteration
```

## Dependencies

```toml
[dependencies]
anyhow = { workspace = true }
calamine = { workspace = true }
indexmap = { workspace = true }
ipnet = { workspace = true }
mmdb-core = { workspace = true }
regex = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
```

Workspace-level additions:

- `members`: add `"crates/mmdb-xlsx"`
- `workspace.dependencies`: add `mmdb-xlsx`, `regex`, `indexmap`

mmdb-creator additions:

- `mmdb-xlsx.workspace = true`

## Integration with mmdb-creator

In `crates/mmdb-creator/src/import/mod.rs`, replace the stub:

```rust
if run_xlsx {
    if let Some(ref sheets) = config.sheets {
        for sheet_config in sheets {
            let results = mmdb_xlsx::read_xlsx(sheet_config)?;
            for result in &results {
                tracing::info!(
                    sheet = %result.sheetname,
                    rows = result.rows.len(),
                    skipped = result.skipped_count,
                    "xlsx import complete"
                );
            }
            // TODO: write to data/import.jsonl (fan-out is done here)
        }
    }
}
```

## Testing strategy

### Unit tests — address.rs

| Test                    | Input                                            | Expected                                        |
| ----------------------- | ------------------------------------------------ | ----------------------------------------------- |
| `single_cidr`           | `"192.0.2.0/30"`                                 | `[192.0.2.0/30]`                                |
| `bare_ipv4`             | `"192.0.2.1"`                                    | `[192.0.2.1/32]`                                |
| `bare_ipv6`             | `"2001:db8::1"`                                  | `[2001:db8::1/128]`                             |
| `comma_separated`       | `"192.0.2.0/30, 2001:db8::/64"`                  | `[192.0.2.0/30, 2001:db8::/64]`                 |
| `newline_separated`     | `"192.0.2.0/30\n2001:db8::/64"`                  | `[192.0.2.0/30, 2001:db8::/64]`                 |
| `comma_newline_mix`     | `"192.0.2.0/30,\n2001:db8::/64"`                 | `[192.0.2.0/30, 2001:db8::/64]`                 |
| `crlf`                  | `"192.0.2.0/30\r\n2001:db8::/64"`                | `[192.0.2.0/30, 2001:db8::/64]`                 |
| `vip_annotation`        | `"192.0.2.2, 192.0.2.3 (VIP: .1),\n2001:db8::1"` | `[192.0.2.2/32, 192.0.2.3/32, 2001:db8::1/128]` |
| `range_aligned`         | `"10.0.0.0-10.0.0.7"`                            | `[10.0.0.0/29]`                                 |
| `range_unaligned`       | `"10.0.0.1-10.0.0.3"`                            | `[10.0.0.1/32, 10.0.0.2/31]`                    |
| `empty_string`          | `""`                                             | `[]`                                            |
| `invalid_token_warning` | `"192.0.2.1, not_an_ip"`                         | `[192.0.2.1/32]` + 1 warning                    |

### Unit tests — reader.rs

- `parse_cell_string`: `Data::String("hello")` → `CellValue::String("hello")`
- `parse_cell_integer_from_int`: `Data::Int(42)` → `CellValue::Integer(42)`
- `parse_cell_integer_from_float`: `Data::Float(42.0)` → `CellValue::Integer(42)`
- `parse_cell_bool_true`: `Data::Bool(true)` → `CellValue::Bool(true)`
- `parse_cell_bool_string`: `Data::String("TRUE")` → `CellValue::Bool(true)`
- `parse_cell_bool_zero`: `Data::String("0")` → `CellValue::Bool(false)`
- `build_header_map_correct_indices`: verify header map construction

### Integration test

Use sample file `data/exsample/IPAM_20260401r2.xlsx` with a test `SheetConfig`.
Verify:

- Correct row count (4 data rows)
- `CellValue::Addresses` contains expected `IpNet` values
- `CellValue::Integer` for VLANID (4000)
- `CellValue::Bool` for use column
- Excluded sheets are skipped
- `filename` and `sheetname` populated correctly

## Open questions

None — all design decisions confirmed with user.

## Critical files

| File                                        | Change                                             |
| ------------------------------------------- | -------------------------------------------------- |
| `crates/mmdb-core/src/config.rs`            | Add `Bool` to `ColumnType`                         |
| `crates/mmdb-core/src/config_template.toml` | Document `bool` type                               |
| `Cargo.toml` (workspace root)               | Add `mmdb-xlsx` member, `regex`/`indexmap` deps    |
| `crates/mmdb-xlsx/` (new)                   | New library crate                                  |
| `crates/mmdb-creator/Cargo.toml`            | Add `mmdb-xlsx` dependency                         |
| `crates/mmdb-creator/src/import/mod.rs`     | Replace xlsx stub with `mmdb_xlsx::read_xlsx` call |
