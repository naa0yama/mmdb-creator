# Sankey Diagram Component

## Overview

The Sankey report (`crates/mmdb-web/src/report/`) renders a self-contained HTML
topology page from `scanned.jsonl` records. It uses ECharts for visualization
and DaisyUI for UI components.

## Granularity Selector

Each hop in the network path can be labeled at six granularity levels:

| Level       | JS key        | Label source                                              | Fallback                  |
| ----------- | ------------- | --------------------------------------------------------- | ------------------------- |
| ASN         | `asn`         | `hop.asn` → `"AS{n}"`                                     | PTR → IP → `"*"`          |
| Facility    | `facility`    | `hop.device.facility`                                     | PTR → IP → `"*"`          |
| Device Role | `device_role` | `hop.device.device_role`                                  | PTR → IP → `"*"`          |
| Device      | `device`      | `hop.device.device` (default)                             | PTR → IP → `"*"`          |
| Interface   | `interface`   | `[hop.device.device, hop.device.interface]` (2-node span) | Device → PTR → IP → `"*"` |
| PTR/IP      | `ptr`         | PTR string or IP address                                  | IP → `"*"`                |

### Architecture

**Approach:** All six granularities are pre-computed at report generation time
(Rust side) and embedded as a single JSON object `SANKEY_DATASETS` in the HTML.
JavaScript switches between datasets client-side without a server round-trip.

**Rust types:**

```rust
pub enum SankeyGranularity { Asn, Facility, DeviceRole, Device, Interface, Ptr }

pub struct AllSankeyData {
    pub asn: SankeyData,
    pub facility: SankeyData,
    pub device_role: SankeyData,
    pub device: SankeyData,
    #[serde(rename = "interface")]
    pub iface: SankeyData,
    pub ptr: SankeyData,
}
```

`build_all(records)` calls `build(records, granularity)` for each variant.
`hop_nodes(hop, granularity)` resolves the label(s) with the fallback chain above.
`Interface` granularity may return a 2-element vec `[device, interface]`, expanding
one hop into two consecutive Sankey nodes.

**JavaScript state:**

```js
const SANKEY_DATASETS = { asn: {...}, facility: {...}, device_role: {...}, device: {...}, interface: {...}, ptr: {...} };
let currentData = SANKEY_DATASETS[initKey];  // restored from location.hash
```

The `<select id="granularity">` in the filter bar drives `currentData`.
On change: `location.hash = key` saves the selection; `rebuildIndex(currentData)`
rebuilds adjacency maps; `applyFilter(...)` re-renders the chart.

`hashchange` events allow bookmark/reload restore.

## Invariants

- `"Internet"` node is always leftmost; never affected by granularity.
- Terminal nodes (scanned CIDR strings) are never relabeled.
- Granularity applies only to intermediate hops (`record.routes`).
- Self-links are silently dropped (ECharts rejects them).
- Back-edges that violate DAG ordering are pruned by BFS depth assignment.

## Files

| File                                     | Role                                 |
| ---------------------------------------- | ------------------------------------ |
| `crates/mmdb-web/src/report/sankey.rs`   | Data model, `build()`, `build_all()` |
| `crates/mmdb-web/src/report/mod.rs`      | `generate()` entry point             |
| `crates/mmdb-web/src/report/template.rs` | HTML/JS template with granularity UI |
