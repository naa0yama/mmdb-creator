# Design: `validate` Subcommand + `--init-sheets`

## Problem

There is no way to check `config.toml` for correctness before running
`import`. Users must manually write `[[sheets.columns]]` entries by
inspecting xlsx files externally, which is error-prone and tedious —
especially when xlsx files have many columns across multiple sheets.

## Goals

- Add `mmdb-creator validate` to check config.toml syntax and semantics
- Add `--init-sheets` flag to auto-generate `[[sheets]]` TOML from xlsx
  files referenced in config, printing to stdout for the user to review
  and paste into config.toml
- Run config validation at program startup (before subcommand dispatch)

## Non-Goals

- Auto-detecting column types (all columns default to `"string"`)
- Writing to config.toml directly (stdout only)
- Validating xlsx file contents beyond header row extraction

## Approach

### CLI changes

```rust
#[derive(Subcommand, Debug)]
pub enum Command {
    // ... existing Import, Export, Scan ...
    /// Validate configuration and optionally scaffold sheet mappings
    Validate {
        /// Read xlsx files from config and generate [[sheets]] TOML to stdout
        #[arg(long)]
        init_sheets: bool,
    },
}
```

### `validate` (no flags)

Performs these checks in order:

1. Config file exists and parses as valid TOML
2. Required fields are present (`[whois].server`)
3. `[[sheets]]` entries (if present):
   - `filename` exists on disk
   - `header_row` >= 1
   - `columns` have unique `name` values
   - `columns` have valid `col_type` values (already enforced by serde)

Print a summary of validation results. Exit 0 on success, 1 on failure.

### `validate --init-sheets`

For each `[[sheets]]` entry in config.toml:

1. Open the xlsx file with calamine
2. Get all sheet names
3. Filter out `excludes_sheets`
4. For each remaining sheet:
   - Read the header row (`header_row`, 1-indexed, default 1)
   - Collect all non-empty column headers
5. Deduplicate column headers across all sheets in the same file
6. Print to stdout as TOML:

```toml
[[sheets]]
filename = "data/exsample/IPAM_20260401r2.xlsx"
header_row = 3
excludes_sheets = []
# Available sheets: ["border1.ty1"]

[[sheets.columns]]
name = "site"
sheet_name = "site"
type = "string"

[[sheets.columns]]
name = "floor"
sheet_name = "floor"
type = "string"

# ... all columns from header row
```

Column output rules:

- `name` = snake_case version of `sheet_name` (lowercase, spaces→underscores)
- `sheet_name` = original header text from xlsx
- `type` = always `"string"` (user edits manually to integer/addresses/bool)
- Available sheet names printed as a TOML comment for excludes_sheets reference

### Startup validation

In `main.rs`, after `Config::load()` and before subcommand dispatch,
call a lightweight validation function. This runs for ALL subcommands,
not just `validate`. On failure, print errors and exit.

### Module placement

- New module: `crates/mmdb-creator/src/validate.rs`
- Reuses `mmdb_xlsx` crate's calamine reading for `--init-sheets`
  (but only needs sheet names and header row — a simpler function)
- Add a new public function to `mmdb-xlsx`:
  `pub fn inspect_sheets(config: &SheetConfig) -> Result<Vec<SheetInfo>>`
  where `SheetInfo { name: String, headers: Vec<String> }`

## Implementation Notes

### New type in mmdb-xlsx

```rust
/// Sheet metadata discovered from an xlsx file.
#[derive(Debug, Clone)]
pub struct SheetInfo {
    /// Sheet name in the workbook.
    pub name: String,
    /// Column headers from the configured header row.
    pub headers: Vec<String>,
}

/// Inspect an xlsx file and return sheet names and header columns.
pub fn inspect_sheets(config: &SheetConfig) -> Result<Vec<SheetInfo>>;
```

### snake_case conversion for column names

```rust
fn to_snake_case(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .replace(' ', "_")
        .replace('-', "_")
}
```

### TOML output format

Use `format!` / `println!` to build TOML output manually (not `toml::to_string`)
because we need control over comments and formatting.

## Testing Strategy

### Unit tests (validate.rs)

- `to_snake_case` conversion: "DEMARC addresses" → "demarc_addresses"
- Config validation: missing server, invalid header_row, duplicate column names

### Integration test

- Run `--init-sheets` with sample xlsx, verify stdout contains expected
  sheet names and column headers
- Run `validate` with valid config, verify exit 0
- Run `validate` with invalid config, verify error messages

## Critical files

| File                                  | Action                                      |
| ------------------------------------- | ------------------------------------------- |
| `crates/mmdb-creator/src/cli.rs`      | Add `Validate` variant                      |
| `crates/mmdb-creator/src/validate.rs` | New: validation + init-sheets logic         |
| `crates/mmdb-creator/src/main.rs`     | Add validate dispatch + startup validation  |
| `crates/mmdb-xlsx/src/lib.rs`         | Add `inspect_sheets`, `SheetInfo` re-export |
| `crates/mmdb-xlsx/src/reader.rs`      | Add `inspect_sheets`, `SheetInfo`           |
