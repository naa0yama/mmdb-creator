# Component: `mmdb-web`

## Purpose

HTML report generation for mmdb-creator. Phase 1 provides static HTML export.
Phase 2 will add an Axum HTTP server.

## Crate Layout

```
crates/mmdb-web/
  src/
    lib.rs              pub mod report
    report/
      mod.rs            pub fn generate(records: &[ScanGwRecord]) -> Result<String>
      sankey.rs         ScanGwRecord → SankeyData { nodes, links }
      template.rs       HTML template (CDN ECharts + DaisyUI, format! injection)
```

## Dependencies (Phase 1)

```toml
mmdb-core.workspace = true
anyhow.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
```

## Public API

```rust
/// Generates an HTML topology report from scan records.
pub fn generate(records: &[ScanGwRecord]) -> anyhow::Result<String>
```

The returned HTML loads ECharts v5 and DaisyUI v4 from CDN. Not self-contained
(requires network access).

## Phase 2 Additions

```toml
# Add to Cargo.toml
axum = { workspace = true }
askama = { workspace = true }
tower-http = { workspace = true }
tokio = { workspace = true }
```

New files:

- `src/routes/mod.rs` — `pub fn routes() -> Router`
- `templates/pages/network/topology.html` — Askama template

The `report::generate()` function remains unchanged; the Axum handler calls it
for server-side rendering.

## Sidebar Category Plan

```
Network
  └─ Topology (Sankey)  ← Phase 1
  └─ (future additions)
```
