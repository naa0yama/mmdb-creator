# Design: `enrich` Subcommand

## Overview

既存の JSON/JSONL ログファイルを読み込み、各レコードに MMDB ルックアップ結果を付加して出力する。

```bash
mmdb-cli enrich --input-enrich-file access.jsonl --input-enrich-ip ip_address
mmdb-cli enrich --input-enrich-file access.jsonl --input-enrich-ip client_ip
```

---

## Goals

- Read a JSON or JSONL log file and append MMDB lookup results as a `mmdb` field on each record.
- Records whose IP address is not found in the MMDB receive `"mmdb": null`.
- Output format matches the input format (JSON array in → JSON array out; JSONL in → JSONL out).
- Output filename is derived automatically: `input.jsonl` → `input.enriched.jsonl`.
- MMDB file path defaults to `config.mmdb.path` (`[mmdb] path`); override per-run with `--mmdb`.
- IP address field name in input records is specified via `--input-enrich-ip` (required).

## Non-Goals

- Streaming / memory-mapped reads of very large files (reads whole file into memory).
- Support for input formats other than JSON array and JSONL.
- Writing enriched output to stdout.
- Recursive directory processing.

---

## Configuration

MMDB path is shared across all subcommands via the `[mmdb]` section:

```toml
[mmdb]
# path = "data/output.mmdb"   # default
```

The `[enrich]` section and `EnrichConfig` struct have been removed.
Use `--mmdb` on the CLI for a one-off path override.

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
},
```

---

## Implementation

### run() Steps

1. Receive `mmdb_path: &Path` explicitly from the caller (resolved in `main.rs` from
   `--mmdb` or `config.mmdb.path`).
2. Open MMDB with `maxminddb::Reader::open_readfile`.
3. Detect input format by extension (`.jsonl` → JSONL; anything else → JSON array).
4. Parse all records into `Vec<serde_json::Value>`.
5. For each record: parse the IP field, look up in MMDB, merge result under `"mmdb"` key.
6. Compute output path by inserting `.enriched` before the last extension.
7. Write output file in the same format as input.

### Output Record Example

```jsonl
{"ip_address":"198.51.100.1","mmdb":{"range":"198.51.100.0/24","autonomous_system_number":64496}}
{"ip_address":"203.0.113.99","mmdb":null}
```

### MMDB Crate

`maxminddb = "0.24"` — the standard crate for reading MMDB files in Rust.

Alternatives considered:

- **Shell script + `mmdbinspect`**: rejected — cannot be embedded in the binary.
- **Re-use `mmdbctl`**: rejected — `mmdbctl` is a write-path tool with no query mode.

---

## File Layout

```
crates/mmdb-cli/src/
  enrich/
    mod.rs    # public run() entry point
```
