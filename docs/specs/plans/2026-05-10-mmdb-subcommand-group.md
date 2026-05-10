---
absorb_into:
  - docs/specs/subcommands/mmdb.md
  - docs/specs/architecture.md
---

# Design: `mmdb` Subcommand Group

## Problem

The top-level `build` subcommand builds an MMDB file but there is no way to
query its contents from the CLI. Adding a sibling `query` command and grouping
both under a dedicated `mmdb` subcommand makes the MMDB workflow self-contained
and discoverable.

## Goals

- Replace the top-level `build` subcommand with `mmdb build` (identical behavior).
- Add `mmdb query` (alias `q`) to look up one or more IP addresses in an MMDB
  file and print results in a human-readable vertical table.
- No behavioral change to any other subcommand (`import`, `scan`, `validate`,
  `enrich`).

## Non-Goals

- JSON / machine-readable output mode for `query` (not in scope for this change).
- Querying IPv6 addresses (current MMDB is IPv4-only).
- Modifying the MMDB record schema.

## Approach

Use Clap subcommand nesting: `Command::Mmdb { command: MmdbCommand }` where
`MmdbCommand` is a new enum with `Build` and `Query` variants.

For MMDB reading, use the existing `maxminddb` workspace dependency directly
(no subprocess). Deserialize each record as `serde_json::Value`, flatten nested
objects to `parent.child` dot notation, then print as a left-aligned key/value
table.

## Implementation Notes

### CLI structure

```rust
pub enum Command {
    Import { ... },
    Mmdb {
        #[command(subcommand)]
        command: MmdbCommand,
    },
    Scan { ... },
    Validate { ... },
    Enrich { ... },
}

pub enum MmdbCommand {
    Build {
        #[arg(short, long, default_value = "data/output.mmdb")]
        out: PathBuf,
        #[arg(short, long, default_value = "data/scanned.jsonl")]
        input: PathBuf,
    },
    #[command(alias = "q")]
    Query {
        #[arg(short = 'm', long, default_value = "data/output.mmdb")]
        mmdb: PathBuf,
        /// One or more IP addresses to look up
        ips: Vec<String>,
    },
}
```

### File layout

```
crates/mmdb-cli/src/
  cli.rs           # add MmdbCommand enum, move Build variant
  build/
    mod.rs         # unchanged
  mmdb_query/
    mod.rs         # new: pub async fn run(mmdb: &Path, ips: &[String]) -> Result<()>
  main.rs          # route Command::Mmdb { command } -> MmdbCommand dispatch
```

### Query output format

For each IP, print a header line followed by key=value rows, then a blank line.

```
===[ 198.51.100.1 ]=====================================================
range                          198.51.100.0/30
autonomous_system_number       64496
autonomous_system_organization Example Corp
country.iso_code               JP
gateway.ip                     198.51.100.1
gateway.ptr                    xe-0-0-1.rtr0101.dc01.example.net
gateway.device                 rtr0101
gateway.device_role            rtr
gateway.facility               dc01
gateway.interface              xe-0-0-1
gateway.facing                 user
operational.serviceid          SVC-001
=======================================================================
```

If the IP is not found in the MMDB, print `(not found)` between the rule lines.
Invalid IP strings are an error (non-zero exit).

### Flatten algorithm

Recursively walk `serde_json::Value::Object`. For each leaf (non-Object value),
emit `"parent.child" => value.to_string()`. Arrays are printed as
comma-separated values inline.

### Key column width

Compute `max_key_len` across all rows for the current IP, pad keys to that
width with spaces.

## Testing Strategy

- Unit tests for the flatten helper function (nested objects, arrays, empty).
- Unit test: invalid IP string returns an error.
- Integration test skipped (requires a real MMDB file on disk; marked NOTEST).

## Open Questions

None.
