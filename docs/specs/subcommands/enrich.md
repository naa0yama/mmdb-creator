# Design: `enrich` Subcommand

## Overview

Reads an existing JSON/JSONL log file, appends MMDB lookup results to each record, and writes two output files unconditionally:

- `input.enriched.raw.jsonl` — full enriched map structure, no projection
- `input.enriched.jsonl` — field-projected flat output (only when `[enrich]` is configured)

`--init-fields` launches an interactive TUI field selector and writes the `[[enrich.fields]]` table array to `config.toml`.

```bash
# Enrich — writes .enriched.raw.jsonl unconditionally
mmdb-cli enrich --input-enrich-file access.jsonl --input-enrich-ip ip_address

# With [enrich] configured — also writes .enriched.jsonl (projected)
mmdb-cli enrich --input-enrich-file access.jsonl --input-enrich-ip ip_address

# Launch TUI to select fields and write [enrich] to config.toml
mmdb-cli enrich --input-enrich-file access.jsonl --input-enrich-ip ip_address --init-fields
```

---

## Goals

- Read a JSON or JSONL log file and append MMDB lookup results as a `mmdb` field on each record.
- Records whose IP address is not found in the MMDB receive `"mmdb": null`.
- Output format matches the input format (JSON array in → JSON array out; JSONL in → JSONL out).
- Always write `input.enriched.raw.jsonl` (full enriched map).
- When `[enrich]` is configured, also write `input.enriched.jsonl` (projected, flat, type-coerced).
- MMDB file path defaults to `config.mmdb.path` (`[mmdb] path`); override per-run with `--mmdb`.
- IP address field name in input records is specified via `--input-enrich-ip` (required).
- Interactive TUI (`--init-fields`) allows selecting fields with per-field `output_name` and `type`.
- Selected fields are persisted to `config.toml` under `[[enrich.fields]]` via `toml_edit`.
- `--init-fields` pre-populates TUI state from an existing `[enrich]` config.

## Non-Goals

- Streaming / memory-mapped reads of very large files (reads whole file into memory).
- Support for input formats other than JSON array and JSONL.
- Writing enriched output to stdout.
- Recursive directory processing.
- Backward-compatible reading of the old `fields = ["ip", "mmdb.asn"]` string format.
- Per-field `array_join` separator.

---

## Configuration

MMDB path is shared across all subcommands via the `[mmdb]` section:

```toml
[mmdb]
# path = "data/output.mmdb"   # default
```

Optional `[enrich]` section for field projection:

```toml
[enrich]
array_join_sep = "," # default; omitted when "," in TOML output

[[enrich.fields]]
field = "ip_address"
output_name = "IPAddr"
type = "string"

[[enrich.fields]]
field = "mmdb.asn"
output_name = "ASN"
type = "integer"

[[enrich.fields]]
field = "mmdb.tags"
type = "array_join"
```

### `EnrichConfig` fields

| Field            | Type               | Default | Description                                                |
| ---------------- | ------------------ | ------- | ---------------------------------------------------------- |
| `array_join_sep` | `String`           | `","`   | Separator for joining scalar arrays in `array_join` fields |
| `fields`         | `Vec<EnrichField>` | `[]`    | Ordered list of output fields                              |

### `EnrichField` fields

| Field         | Type              | Default    | Description                                                      |
| ------------- | ----------------- | ---------- | ---------------------------------------------------------------- |
| `field`       | `String`          | (required) | Dot-notation source path (e.g. `"mmdb.asn"`)                     |
| `output_name` | `Option<String>`  | `None`     | Column name in processed output; falls back to `field` if absent |
| `field_type`  | `EnrichFieldType` | `String`   | Type coercion applied in processed output                        |

`output_name` is omitted from TOML when `None`. `type` is omitted when default (`string`).

### `EnrichFieldType` variants

| Variant     | TOML value     | Behaviour                                                                  |
| ----------- | -------------- | -------------------------------------------------------------------------- |
| `String`    | `"string"`     | `scalar_to_string(val)` → JSON string                                      |
| `Integer`   | `"integer"`    | `as_i64()` or parse string → JSON number; keep raw on failure              |
| `Bool`      | `"bool"`       | `as_bool()` or parse `"true"/"yes"/"1"` → JSON bool; keep raw on failure   |
| `ArrayJoin` | `"array_join"` | Join scalar array elements with `array_join_sep`; keep raw if object array |

When `[enrich]` is absent from `config.toml`, only `input.enriched.raw.jsonl` is written.

### Object field selection

Selecting an Object-typed field (e.g. `"mmdb.operational"`) includes all descendants in the flat output via prefix matching (`info.path.starts_with("mmdb.operational.")`).

---

## CLI

```rust
Enrich {
    /// Input JSON or JSONL log file to enrich
    #[arg(long)]
    input_enrich_file: PathBuf,
    /// Field name in each record that holds the IP address
    #[arg(long)]
    input_enrich_ip: String,
    /// MMDB file to use (default: config.mmdb.path)
    #[arg(short = 'm', long)]
    mmdb: Option<PathBuf>,
    /// Interactively select MMDB fields to enrich with (writes [enrich] to config.toml)
    #[arg(long)]
    init_fields: bool,
},
```

---

## TUI Operation (`--init-fields`)

The TUI is built with `ratatui` + `crossterm`. It displays a two-pane interface:

```
┌─ Fields [/filter] ─────────────────────────────┐┌─ Preview ──────────────────────────┐
│ [ ] ip_address          string                  ││ Key                 Value           │
│ [x] mmdb.asn            integer  → ASN          ││ ASN                 64496           │
│ [x] mmdb.tags           array_join → tags       ││ tags                a,b             │
│ [ ] mmdb.network        string                  ││                                     │
└─────────────────────────────────────────────────┘└────────────────────────────────────┘
↑↓ move  Spc toggle  / filter  a sep(",")  t type  n rename  Enter confirm  q quit
```

### Key bindings

| Key         | Action                                                         |
| ----------- | -------------------------------------------------------------- |
| `↑` / `k`   | Move cursor up                                                 |
| `↓` / `j`   | Move cursor down                                               |
| `Space`     | Toggle field selection                                         |
| `/`         | Enter filter mode (type to narrow list)                        |
| `a`         | Enter `array_join_sep` input mode                              |
| `t`         | Cycle `type` for cursor field (only if selected)               |
| `n`         | Enter inline `output_name` edit for cursor field (if selected) |
| `Enter`     | Confirm selection and write `config.toml`                      |
| `q` / `Esc` | Quit without writing                                           |

### Type cycle (`t`)

- Source type `list`: `array_join` → `string` → `array_join`
- Source type other: detected → `string` → `integer` → `bool` → `string`

### Pre-populate from existing config

When `--init-fields` is run and `[enrich]` already exists, the TUI pre-populates:

- Checked state from `existing.fields[*].field` paths
- `output_name` from `existing.fields[*].output_name`
- Type overrides from `existing.fields[*].field_type`
- `array_join_sep` from `existing.array_join_sep`

### Object cascade

Selecting an Object-typed field automatically selects all its descendants.
Deselecting it deselects all descendants.

### Flow

1. Open MMDB, read input file, enrich all records.
2. Build `field_infos` = union of enriched records (`union_field_infos`).
3. Merge MMDB schema from `output.jsonl` (or MMDB scan fallback).
4. `run_tui(field_infos, &sample, config.enrich.as_ref())` → `Option<EnrichConfig>`.
5. If `None`: return early (user quit).
6. If `config.enrich.is_some()`: prompt overwrite on stderr + stdin.
7. `Config::write_enrich_section(config_path, &enrich_cfg)` via `toml_edit`.

---

## Field Projection (normal enrich with `[enrich]` configured)

After `enrich_records()` merges MMDB results under `"mmdb"`:

1. Write raw output unconditionally: `input.enriched.raw.jsonl`.
2. If `config.enrich.is_some()`: apply `project_fields(record, &ec.fields, &ec.array_join_sep)` and write `input.enriched.jsonl`.

### `project_fields` behaviour

- Always flat output (dot-notation keys, `output_name` applied as key override).
- Per-field `EnrichFieldType` coercion applied.
- Exact path match OR subtree prefix match (`info.path.starts_with(&format!("{path}."))`).
- Only leaf fields (`type_tag != "object"`) are emitted.

### Output examples

Input record (after MMDB merge):

```json
{
	"ip_address": "198.51.100.1",
	"user_agent": "curl/7.0",
	"mmdb": {
		"network": "198.51.100.0/24",
		"autonomous_system_number": 64496,
		"tags": ["a", "b"]
	}
}
```

Config:

```toml
[[enrich.fields]]
field = "ip_address"
output_name = "IPAddr"

[[enrich.fields]]
field = "mmdb.autonomous_system_number"
output_name = "ASN"
type = "integer"

[[enrich.fields]]
field = "mmdb.tags"
output_name = "tags"
type = "array_join"
```

Processed output (`input.enriched.jsonl`):

```json
{ "IPAddr": "198.51.100.1", "ASN": 64496, "tags": "a,b" }
```

Raw output (`input.enriched.raw.jsonl`):

```json
{
	"ip_address": "198.51.100.1",
	"user_agent": "curl/7.0",
	"mmdb": { "network": "198.51.100.0/24", "autonomous_system_number": 64496, "tags": ["a", "b"] }
}
```

---

## Implementation

### File layout

```
crates/mmdb-cli/src/
  enrich/
    mod.rs      # public run() entry point, two-file output, field projection
    fields.rs   # FieldInfo, flatten_fields, project_fields, coerce_value, get_by_dotpath
    tui.rs      # run_tui, TuiState, draw, event_loop
crates/mmdb-core/src/
  config.rs     # EnrichConfig, EnrichField, EnrichFieldType, Config::write_enrich_section
```

### `run()` steps — normal mode (`init_fields=false`)

1. Open MMDB with `maxminddb::Reader::open_readfile`.
2. Detect input format by extension (`.jsonl` → JSONL; anything else → JSON array).
3. Parse all records into `Vec<serde_json::Value>`.
4. Call `enrich_records()` — for each record: parse IP, look up, merge under `"mmdb"`.
5. Write `input.enriched.raw.jsonl` unconditionally.
6. If `config.enrich.is_some()`: apply `project_fields` per record, write `input.enriched.jsonl`.

### `run()` steps — init-fields mode (`init_fields=true`)

1. Open MMDB, parse input, enrich all records.
2. Build `field_infos` = union of enriched records (`union_field_infos`).
3. Derive `jsonl_path` = `mmdb_path.with_extension("jsonl")`.
4. Merge MMDB schema:
   - If `jsonl_path` exists: `schema_from_output_jsonl(&jsonl_path)`.
   - Else (fallback): `schema_from_mmdb(&reader, 2000)`.
5. Merge schema into `field_infos` (dedup by path, input-native fields first).
6. `run_tui(field_infos, &sample, config.enrich.as_ref())` → `Option<EnrichConfig>`.
7. If `None`: return early (user quit).
8. If `config.enrich.is_some()`: prompt overwrite on stderr + stdin.
9. `Config::write_enrich_section(config_path, &enrich_cfg)` via `toml_edit`.

### `write_enrich_section` (`toml_edit`)

Reads `config.toml` as `DocumentMut`, removes old `[enrich]`, rebuilds with `[[enrich.fields]]`
array-of-tables. Writes back, preserving all comments and formatting in other sections.
`array_join_sep` is omitted when it equals the default `","`.
`type` is omitted for each field when it equals the default `string`.

### MMDB crate

`maxminddb = "0.24"` — standard crate for reading MMDB files in Rust.
