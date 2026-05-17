# Module & Project Structure — mmdb-cli

> **Shared patterns**: See `~/.claude/skills/rust-project-conventions/references/module-structure.md`
> for visibility rules, mod.rs re-export pattern, size limits, CLI design, and clippy configuration.

## Workspace Layout

```
crates/
  mmdb-core/    # Shared types, config schema, external data model
  mmdb-cli/     # CLI binary (main entry point)
  mmdb-dns/     # DNS reverse lookup / AS info (lib)
  mmdb-scan/    # scamper integration / CIDR expansion / enrich (lib)
  mmdb-whois/   # Whois client library (TCP 43 + RIPE Stat)
  mmdb-xlsx/    # Excel (.xlsx) reader library
```

## Crate Purposes

| Crate      | Type | Role                                                                                  |
| ---------- | ---- | ------------------------------------------------------------------------------------- |
| mmdb-core  | lib  | Shared types (`MmdbRecord`, `WhoisData`), config schema (TOML), external data model   |
| mmdb-cli   | bin  | CLI subcommand dispatch (import / mmdb build / mmdb query / scan / validate / enrich) |
| mmdb-dns   | lib  | DNS PTR reverse lookup and AS info resolution                                         |
| mmdb-scan  | lib  | scamper ICMP-Paris probe, CIDR expansion, gateway enrichment                          |
| mmdb-whois | lib  | Whois client: ASN → announced prefixes → TCP 43 queries                               |
| mmdb-xlsx  | lib  | Excel reader: parse `.xlsx` sheets into typed rows                                    |

## Project Source Layout

### mmdb-core

```
crates/mmdb-core/src/
  lib.rs              # Re-exports MmdbRecord, config, external
  config.rs           # Config file schema (serde Deserialize from TOML)
  config_template.toml # Default config template (embedded via include_str!)
  types.rs            # Core data types (MmdbRecord and nested structs)
  external.rs         # External data model (enrichment sources)
  build.rs            # to_mmdb_record: ScanGwRecord → MmdbRecord conversion
```

### mmdb-cli (CLI binary)

```
crates/mmdb-cli/src/
  main.rs             # CLI entry point (#[tokio::main], subcommand dispatch)
  cli.rs              # clap Args + Command enum + MmdbCommand enum
  backup.rs           # Rotating backup for scanned.jsonl / whois-cidr.jsonl
  cache.rs            # Cache directory management
  validate.rs         # validate subcommand implementation
  build/
    mod.rs            # mmdb build: scanned.jsonl → data/output.jsonl → mmdbctl
  mmdb_query/
    mod.rs            # mmdb query: IP lookup in MMDB, vertical table output
  enrich/
    mod.rs            # enrich subcommand: annotate JSONL with MMDB lookup results
  import/
    mod.rs            # import subcommand (whois TCP 43, Excel xlsx)
  scan/
    mod.rs            # scan subcommand: thin wrapper around mmdb-scan
  telemetry/
    mod.rs            # OTel providers init/shutdown helpers
    conventions.rs    # mmdb_creator.* metric/attribute name constants
    metrics/
      mod.rs          # Meters struct (OTel instruments or no-op stub)
      process.rs      # OTel semconv process metrics via sysinfo
crates/mmdb-cli/tests/
  integration_test.rs # Integration tests (assert_cmd)
```

### CLI Subcommand Map

| Invocation            | Module              | Description                               |
| --------------------- | ------------------- | ----------------------------------------- |
| `mmdb-cli import`     | `import/mod.rs`     | Whois + xlsx data collection              |
| `mmdb-cli mmdb build` | `build/mod.rs`      | Build MMDB from scanned.jsonl via mmdbctl |
| `mmdb-cli mmdb query` | `mmdb_query/mod.rs` | IP lookup in MMDB, vertical table output  |
| `mmdb-cli mmdb q`     | `mmdb_query/mod.rs` | Alias for `mmdb query`                    |
| `mmdb-cli scan`       | `scan/mod.rs`       | CIDR probe via scamper                    |
| `mmdb-cli validate`   | `validate.rs`       | Config + xlsx validation                  |
| `mmdb-cli enrich`     | `enrich/mod.rs`     | Annotate JSONL with MMDB lookups          |

### mmdb-whois

```
crates/mmdb-whois/src/
  lib.rs             # Re-exports WhoisClient, PrefixClient; top-level resolve fns
  client.rs          # WhoisClient: TCP port 43 whois queries with retry
  prefix.rs          # PrefixClient: RIPE Stat announced-prefix lookup
  rpsl.rs            # RPSL parser (parse whois text into WhoisData fields)
```

### mmdb-xlsx

```
crates/mmdb-xlsx/src/
  lib.rs             # Re-exports reader API (inspect_sheets, read_xlsx, etc.)
  reader.rs          # XLSX reader: calamine → typed XlsxRow structs
  address.rs         # IP address/range/CIDR parser (parse_addresses, range_to_cidrs)
crates/mmdb-xlsx/tests/
  integration_test.rs  # Integration tests (real xlsx fixture files)
```

## OTel / Tracing Setup

- OTel is enabled by default (`default = ["otel", "process-metrics"]`).
- Set `OTEL_EXPORTER_OTLP_ENDPOINT` env var to activate OTLP export.
- Without the env var (or empty), only the `fmt` layer is active.
- Build without OTel: `mise run build -- --no-default-features`.
- Test tasks automatically set `OTEL_EXPORTER_OTLP_ENDPOINT=""` to prevent OTel panics.
- Feature flags in `Cargo.toml`:
  ```toml
  [features]
  default = ["otel", "process-metrics"]
  otel = [
  	"dep:gethostname",
  	"dep:opentelemetry",
  	"dep:opentelemetry_sdk",
  	"dep:opentelemetry-otlp",
  	"dep:tracing-opentelemetry",
  	"dep:opentelemetry-appender-tracing",
  	"dep:opentelemetry-semantic-conventions",
  ]
  # Collects OTel-semconv process metrics. Requires `otel`. Disable with --no-default-features.
  process-metrics = [
  	"otel",
  	"dep:sysinfo",
  ]
  ```
- `service.instance.id` is set to `gethostname::gethostname()` (CLI: one instance per host).
- `TraceContextPropagator` and `global::set_tracer_provider()` are set at provider init.
- Transport: HTTP/proto (`http-proto` + `reqwest-client`), port 4318.
