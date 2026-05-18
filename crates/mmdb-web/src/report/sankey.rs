//! Sankey diagram data model and conversion logic for `ECharts`.

use std::collections::HashMap;

use indexmap::IndexSet;
use mmdb_core::types::ScanGwRecord;
use serde::Serialize;

/// A node in the Sankey diagram.
#[derive(Debug, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SankeyNode {
    /// Display name of the node.
    pub name: String,
}

/// A directed flow between two nodes.
#[derive(Debug, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SankeyLink {
    /// Name of the source node.
    pub source: String,
    /// Name of the target node.
    pub target: String,
    /// Aggregated flow value (count of paths through this edge).
    pub value: usize,
}

/// Complete Sankey graph data for `ECharts`.
#[derive(Debug, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SankeyData {
    /// Ordered list of unique nodes.
    pub nodes: Vec<SankeyNode>,
    /// Directed links with aggregated flow values.
    pub links: Vec<SankeyLink>,
}

/// Resolves the display name for a single hop.
///
/// Priority:
/// 1. `ptr` when `Some(s)` and `s != "*"`.
/// 2. `ip` when `ptr` is absent or is `"*"`.
/// 3. `"*"` as a fallback for fully non-responding hops.
fn hop_name(ip: Option<&str>, ptr: Option<&str>) -> String {
    match ptr {
        Some(p) if p != "*" => p.to_owned(),
        _ => ip.map_or_else(|| "*".to_owned(), str::to_owned),
    }
}

/// Increments the aggregated link count for a `(source, target)` pair.
fn add_link(source: &str, target: &str, links: &mut HashMap<(String, String), usize>) {
    let key = (source.to_owned(), target.to_owned());
    let count = links.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

/// Builds Sankey diagram data from a slice of [`ScanGwRecord`]s.
///
/// Conversion rules:
/// - "Internet" is always the leftmost node.
/// - Records with no hops are skipped.
/// - Each hop resolves to a PTR name, IP address, or `"*"`.
/// - Links are aggregated: duplicate `(source, target)` pairs accumulate their value.
/// - Node insertion order is preserved.
#[must_use]
pub fn build(records: &[ScanGwRecord]) -> SankeyData {
    const INTERNET: &str = "Internet";

    // IndexSet provides O(1) dedup with insertion-order iteration.
    let mut node_set: IndexSet<String> = IndexSet::new();
    let mut link_map: HashMap<(String, String), usize> = HashMap::new();

    node_set.insert(INTERNET.to_owned());

    for record in records {
        if record.routes.is_empty() {
            continue;
        }

        let hop_names: Vec<String> = record
            .routes
            .iter()
            .map(|h| hop_name(h.ip.as_deref(), h.ptr.as_deref()))
            .collect();

        for name in &hop_names {
            node_set.insert(name.clone());
        }
        node_set.insert(record.range.clone());

        if let Some(first) = hop_names.first() {
            add_link(INTERNET, first, &mut link_map);
        }
        for pair in hop_names.windows(2) {
            if let [src, dst] = pair {
                add_link(src, dst, &mut link_map);
            }
        }
        if let Some(last) = hop_names.last() {
            add_link(last, &record.range, &mut link_map);
        }
    }

    let nodes = node_set
        .into_iter()
        .map(|name| SankeyNode { name })
        .collect();
    let links = link_map
        .into_iter()
        .map(|((source, target), value)| SankeyLink {
            source,
            target,
            value,
        })
        .collect();

    SankeyData { nodes, links }
}

#[cfg(test)]
pub(crate) mod tests {
    use mmdb_core::types::{GatewayInfo, Hop, ScanGwRecord, XlsxMatchStatus};

    use super::*;

    /// Constructs a minimal [`ScanGwRecord`] for testing.
    ///
    /// `hops` is a list of `(ip, ptr)` pairs — both expressed as `&str`.
    pub fn make_record(range: &str, hops: Vec<(&str, Option<&str>)>) -> ScanGwRecord {
        ScanGwRecord {
            range: range.to_owned(),
            gateway: GatewayInfo {
                ip: None,
                ptr: None,
                votes: 0,
                total: 0,
                status: "no_ptr_match".to_owned(),
                device: None,
            },
            routes: hops
                .into_iter()
                .map(|(ip, ptr)| Hop {
                    hop: 1,
                    ip: Some(ip.to_owned()),
                    ptr: ptr.map(str::to_owned),
                    rtt_avg: None,
                    rtt_best: None,
                    rtt_worst: None,
                    icmp_type: None,
                    asn: None,
                })
                .collect(),
            netname: None,
            descr: None,
            as_num: None,
            as_name: None,
            as_descr: None,
            inetnum: None,
            country: None,
            whois_source: None,
            whois_last_modified: None,
            host_ip: None,
            host_ptr: None,
            measured_at: None,
            xlsx: None,
            xlsx_matched: XlsxMatchStatus::default(),
            gateway_found: false,
        }
    }

    #[test]
    fn no_hops_skip() {
        let record = make_record("198.51.100.0/24", vec![]);
        let data = build(&[record]);
        assert_eq!(data.nodes.len(), 1);
        assert_eq!(
            data.nodes.first().map(|n| n.name.as_str()),
            Some("Internet")
        );
        assert!(data.links.is_empty());
    }

    #[test]
    fn duplicate_link_value_sum() {
        let r1 = make_record("198.51.100.0/24", vec![("198.51.100.1", None)]);
        let r2 = make_record("198.51.100.0/24", vec![("198.51.100.1", None)]);
        let data = build(&[r1, r2]);

        let internet_to_hop = data
            .links
            .iter()
            .find(|l| l.source == "Internet" && l.target == "198.51.100.1");
        assert!(internet_to_hop.is_some());
        assert_eq!(internet_to_hop.map(|l| l.value), Some(2));
    }

    #[test]
    fn ptr_fallback_to_ip() {
        let record = make_record("198.51.100.0/24", vec![("198.51.100.1", None)]);
        let data = build(&[record]);
        assert!(data.nodes.iter().any(|n| n.name == "198.51.100.1"));
    }

    #[test]
    fn internet_always_leftmost() {
        let r1 = make_record("198.51.100.0/24", vec![("198.51.100.1", None)]);
        let r2 = make_record("2001:db8::/32", vec![("2001:db8::1", None)]);
        let data = build(&[r1, r2]);
        assert!(!data.links.iter().any(|l| l.target == "Internet"));
    }

    #[test]
    fn star_ptr_uses_ip() {
        let record = make_record("198.51.100.0/24", vec![("198.51.100.2", Some("*"))]);
        let data = build(&[record]);
        assert!(data.nodes.iter().any(|n| n.name == "198.51.100.2"));
        assert!(!data.nodes.iter().any(|n| n.name == "*"));
    }
}
