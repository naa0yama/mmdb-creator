# Subcommand: `mmdb report`

## Purpose

Generate a self-contained HTML file that visualises the network topology
recorded in `data/scanned.jsonl` as an ECharts Sankey diagram.

## CLI Interface

```
mmdb report [OPTIONS]

Options:
  --input  <PATH>   Input scanned JSONL file  [default: data/scanned.jsonl]
  --output <PATH>   Output HTML file path     [default: data/report.html]
```

## Behaviour

1. Read `data/scanned.jsonl` (or `--input`) line-by-line into `Vec<ScanGwRecord>`.
2. Call `mmdb_web::report::generate(&records)` to produce an HTML string.
3. Write the HTML string to `data/report.html` (or `--output`).
4. Log `tracing::info!` with output path and record count.

Parse errors are fatal (fail-hard pattern, same as `mmdb build`).

## HTML Output

The generated HTML page:

- Loads `ECharts` v5 and `DaisyUI` v4 from CDN (requires network access).
- Renders a Sankey diagram: `Internet` → hop nodes → destination CIDRs.
- Provides a text `<input>` to filter nodes by IP or CIDR string (pure JS).
  - Filter expands selection via BFS: upstream toward `Internet` and downstream
    toward destination CIDRs are included automatically.
  - Clicking a node in the chart sets the filter to that node's name.
  - Clicking the `Internet` node or the clear button (`✕`) resets the filter.
- Provides a "Show host routes" checkbox (unchecked by default) that hides
  `/32` (IPv4) and `/128` (IPv6) destination nodes from the diagram.
- Displays a node count badge (`visible / total`) that updates whenever the
  filter or host-route toggle changes the rendered node set.
- Uses a two-column flex layout: fixed sidebar (Network / Topology) + main area.
- Chart height is computed dynamically so each node gets at least 20 px.

### Sankey Data Model

```rust
struct SankeyNode { name: String }
struct SankeyLink { source: String, target: String, value: usize }
struct SankeyData { nodes: Vec<SankeyNode>, links: Vec<SankeyLink> }
```

### Conversion Rules (`mmdb_web::report::sankey::build`)

1. `"Internet"` is always the leftmost node.
2. Records where `routes` is empty are skipped.
3. Hop node name priority: PTR (if `Some` and `!= "*"`) → IP → `"*"`.
4. Links: `"Internet"` → `routes[0]`, then consecutive hops, then last hop → `record.range`.
5. Duplicate `(source, target)` pairs accumulate value via `saturating_add`.
6. Self-links (`source == target`) are silently dropped — `ECharts` Sankey does
   not support them and will refuse to render.
7. Cycles are broken via BFS from `Internet`: each node is assigned its shortest
   depth, and any back-edge whose target depth ≤ source depth is removed,
   ensuring the graph is a DAG that `ECharts` accepts.

## Phase 2 (Future)

Add `mmdb web` subcommand with Axum HTTP server serving the same topology
via live HTMX updates. The `report::generate()` function is unchanged — the
server calls it directly. See `docs/specs/components/mmdb-web.md`.
