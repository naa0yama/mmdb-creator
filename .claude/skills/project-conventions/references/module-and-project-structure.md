# Module & Project Structure — mmdb-creator

> **Shared patterns**: See `~/.claude/skills/rust-project-conventions/references/module-structure.md`
> for visibility rules, mod.rs re-export pattern, size limits, CLI design, and clippy configuration.

## Workspace Layout

```
crates/
  mmdb-core/          # Shared types, config schema, external data model
  mmdb-creator/       # CLI binary (main entry point)
  mmdb-whois/         # Whois client library (TCP 43 + RIPE Stat)
  mmdb-xlsx/          # Excel (.xlsx) reader library
```

## Crate Purposes

| Crate        | Type | Role                                                                                |
| ------------ | ---- | ----------------------------------------------------------------------------------- |
| mmdb-core    | lib  | Shared types (`MmdbRecord`, `WhoisData`), config schema (TOML), external data model |
| mmdb-creator | bin  | CLI subcommand dispatch (import / export / scan / validate)                         |
| mmdb-whois   | lib  | Whois client: ASN → announced prefixes → TCP 43 queries                             |
| mmdb-xlsx    | lib  | Excel reader: parse `.xlsx` sheets into typed rows                                  |

## Project Source Layout

### mmdb-core

```
crates/mmdb-core/src/
  lib.rs             # Re-exports MmdbRecord, config, external
  config.rs          # Config file schema (serde Deserialize from TOML)
  types.rs           # Core data types (MmdbRecord and nested structs)
  external.rs        # External data model (enrichment sources)
```

### mmdb-creator (CLI binary)

```
crates/mmdb-creator/src/
  main.rs            # CLI entry point (#[tokio::main], subcommand dispatch)
  cli.rs             # clap Args + Command enum (Import/Export/Scan/Validate)
  validate.rs        # validate subcommand implementation
  import/
    mod.rs           # Import subcommand (whois TCP 43, Excel xlsx)
  export/
    mod.rs           # Export subcommand (NDJSON merge → mmdbctl)
  scan/
    mod.rs           # Scan subcommand entry point
    daemon.rs        # Background scan daemon
    enrich.rs        # IP enrichment logic
    resume.rs        # Resume from checkpoint
    socket.rs        # Low-level socket I/O
    writer.rs        # NDJSON output writer
  telemetry/
    mod.rs           # OTel providers init/shutdown helpers
    conventions.rs   # mmdb_creator.* metric/attribute name constants
    metrics/
      mod.rs         # Meters struct (OTel instruments or no-op stub)
      process.rs     # OTel semconv process metrics via sysinfo
crates/mmdb-creator/tests/
  integration_test.rs  # Integration tests (assert_cmd)
```

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
