//! Sankey diagram data model and conversion logic for `ECharts`.

use std::collections::{HashMap, VecDeque};

use indexmap::IndexSet;
use mmdb_core::types::{Hop, ScanGwRecord};
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

/// Granularity level used to label each hop in the Sankey diagram.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::module_name_repetitions)]
pub enum SankeyGranularity {
    /// Label hops by autonomous system number (e.g. `"AS64496"`).
    Asn,
    /// Label hops by facility name from device metadata.
    Facility,
    /// Label hops by device role from device metadata.
    DeviceRole,
    /// Label hops by device name from device metadata.
    #[default]
    Device,
    /// Expand each hop into `[device, "{device}/{interface}"]` nodes when both fields are present.
    Interface,
    /// Label hops by exact PTR string or IP address (original pre-granularity behaviour).
    Ptr,
}

/// Aggregated Sankey data for all supported granularity levels.
#[derive(Debug, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AllSankeyData {
    /// Sankey data grouped by ASN.
    pub asn: SankeyData,
    /// Sankey data grouped by facility.
    pub facility: SankeyData,
    /// Sankey data grouped by device role.
    pub device_role: SankeyData,
    /// Sankey data grouped by device name.
    pub device: SankeyData,
    /// Sankey data with each hop expanded into device + interface nodes.
    #[serde(rename = "interface")]
    pub iface: SankeyData,
    /// Sankey data labelled by exact PTR string or IP address.
    pub ptr: SankeyData,
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

/// Resolves the display labels for a single hop at the given granularity level.
///
/// Returns a one-element `Vec` for most granularities. Returns a two-element
/// `Vec` for [`SankeyGranularity::Interface`] when both `device` and `interface`
/// fields are present, expanding the hop into `[device, "{device}/{interface}"]` nodes.
///
/// Falls back to [`hop_name`] when the requested field is absent.
fn hop_nodes(hop: &Hop, granularity: SankeyGranularity) -> Vec<String> {
    let fallback = || hop_name(hop.ip.as_deref(), hop.ptr.as_deref());
    match granularity {
        SankeyGranularity::Ptr => vec![fallback()],
        SankeyGranularity::Asn => vec![hop.asn.map_or_else(fallback, |n| format!("AS{n}"))],
        SankeyGranularity::Facility => vec![
            hop.device
                .as_ref()
                .and_then(|d| d.facility.as_deref())
                .map_or_else(fallback, str::to_owned),
        ],
        SankeyGranularity::DeviceRole => vec![
            hop.device
                .as_ref()
                .and_then(|d| d.device_role.as_deref())
                .map_or_else(fallback, str::to_owned),
        ],
        SankeyGranularity::Device => vec![
            hop.device
                .as_ref()
                .and_then(|d| d.device.as_deref())
                .map_or_else(fallback, str::to_owned),
        ],
        SankeyGranularity::Interface => {
            let dev_ref = hop.device.as_ref();
            let device_str = dev_ref.and_then(|d| d.device.as_deref());
            let iface_str = dev_ref.and_then(|d| d.interface.as_deref());
            match (device_str, iface_str) {
                // Qualify the interface node with the device name so that
                // identically-named interfaces on different devices (e.g.
                // xe-0-0-0 on medge0306 vs edge0504) remain distinct nodes.
                (Some(dev), Some(iface)) => vec![dev.to_owned(), format!("{dev}/{iface}")],
                (Some(dev), None) => vec![dev.to_owned()],
                _ => vec![fallback()],
            }
        }
    }
}

/// Increments the aggregated link count for a `(source, target)` pair.
///
/// Self-links (`source == target`) are silently dropped because `ECharts` Sankey
/// does not support them and will refuse to render the entire chart.
fn add_link(source: &str, target: &str, links: &mut HashMap<(String, String), usize>) {
    if source == target {
        return;
    }
    let key = (source.to_owned(), target.to_owned());
    let count = links.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

/// Builds Sankey diagram data from a slice of [`ScanGwRecord`]s.
///
/// Conversion rules:
/// - "Internet" is always the leftmost node.
/// - Records with no hops are skipped.
/// - Each hop is labelled according to `granularity`, falling back to PTR/IP/`"*"`.
/// - Links are aggregated: duplicate `(source, target)` pairs accumulate their value.
/// - Node insertion order is preserved.
#[must_use]
pub fn build(records: &[ScanGwRecord], granularity: SankeyGranularity) -> SankeyData {
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
            .flat_map(|h| hop_nodes(h, granularity))
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

    // Assign canonical depth (shortest path from Internet) via BFS, then drop
    // any back-edge whose target depth ≤ source depth.  This breaks all cycles
    // that would cause ECharts to reject the graph as non-DAG.
    let mut depth: HashMap<String, usize> = HashMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    depth.insert(INTERNET.to_owned(), 0);
    queue.push_back(INTERNET.to_owned());
    {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for (src, tgt) in link_map.keys() {
            adj.entry(src.clone()).or_default().push(tgt.clone());
        }
        while let Some(node) = queue.pop_front() {
            let d = depth.get(&node).copied().unwrap_or(0);
            for neighbor in adj.get(&node).into_iter().flatten() {
                if !depth.contains_key(neighbor) {
                    depth.insert(neighbor.clone(), d.saturating_add(1));
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }
    link_map.retain(
        |(src, tgt), _| matches!((depth.get(src), depth.get(tgt)), (Some(ds), Some(dt)) if dt > ds),
    );

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

/// Builds Sankey diagram data for all granularity levels in a single pass.
#[must_use]
pub fn build_all(records: &[ScanGwRecord]) -> AllSankeyData {
    AllSankeyData {
        asn: build(records, SankeyGranularity::Asn),
        facility: build(records, SankeyGranularity::Facility),
        device_role: build(records, SankeyGranularity::DeviceRole),
        device: build(records, SankeyGranularity::Device),
        iface: build(records, SankeyGranularity::Interface),
        ptr: build(records, SankeyGranularity::Ptr),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use mmdb_core::types::{GatewayDevice, GatewayInfo, Hop, ScanGwRecord, XlsxMatchStatus};

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
                    device: None,
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
        let data = build(&[record], SankeyGranularity::Device);
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
        let data = build(&[r1, r2], SankeyGranularity::Device);

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
        let data = build(&[record], SankeyGranularity::Device);
        assert!(data.nodes.iter().any(|n| n.name == "198.51.100.1"));
    }

    #[test]
    fn internet_always_leftmost() {
        let r1 = make_record("198.51.100.0/24", vec![("198.51.100.1", None)]);
        let r2 = make_record("2001:db8::/32", vec![("2001:db8::1", None)]);
        let data = build(&[r1, r2], SankeyGranularity::Device);
        assert!(!data.links.iter().any(|l| l.target == "Internet"));
    }

    #[test]
    fn self_link_dropped() {
        // A hop whose name resolves to the same string as the CIDR must not
        // produce a self-link, which would make ECharts refuse to render.
        let record = make_record(
            "198.51.100.0/24",
            vec![("198.51.100.1", Some("198.51.100.0/24"))],
        );
        let data = build(&[record], SankeyGranularity::Device);
        assert!(
            !data.links.iter().any(|l| l.source == l.target),
            "self-links must be absent"
        );
    }

    #[test]
    fn star_ptr_uses_ip() {
        let record = make_record("198.51.100.0/24", vec![("198.51.100.2", Some("*"))]);
        let data = build(&[record], SankeyGranularity::Device);
        assert!(data.nodes.iter().any(|n| n.name == "198.51.100.2"));
        assert!(!data.nodes.iter().any(|n| n.name == "*"));
    }

    /// Builds a [`Hop`] with all optional fields set to `None` except those provided.
    fn make_hop(ip: Option<&str>, asn: Option<u32>, device: Option<GatewayDevice>) -> Hop {
        Hop {
            hop: 1,
            ip: ip.map(str::to_owned),
            ptr: None,
            rtt_avg: None,
            rtt_best: None,
            rtt_worst: None,
            icmp_type: None,
            asn,
            device,
        }
    }

    #[test]
    fn hop_nodes_asn() {
        let hop = make_hop(Some("198.51.100.1"), Some(64496), None);
        assert_eq!(hop_nodes(&hop, SankeyGranularity::Asn), vec!["AS64496"]);

        // Missing ASN falls back to IP.
        let hop_no_asn = make_hop(Some("198.51.100.1"), None, None);
        assert_eq!(
            hop_nodes(&hop_no_asn, SankeyGranularity::Asn),
            vec!["198.51.100.1"]
        );
    }

    #[test]
    fn hop_nodes_facility() {
        let dev = GatewayDevice {
            interface: None,
            device: None,
            device_role: None,
            facility: Some("colo05".to_owned()),
            facing: None,
            customer_asn: None,
        };
        let hop = make_hop(Some("198.51.100.1"), None, Some(dev));
        assert_eq!(hop_nodes(&hop, SankeyGranularity::Facility), vec!["colo05"]);

        let hop_no_dev = make_hop(Some("198.51.100.1"), None, None);
        assert_eq!(
            hop_nodes(&hop_no_dev, SankeyGranularity::Facility),
            vec!["198.51.100.1"]
        );
    }

    #[test]
    fn hop_nodes_device_role() {
        let dev = GatewayDevice {
            interface: None,
            device: None,
            device_role: Some("rtr".to_owned()),
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let hop = make_hop(Some("198.51.100.1"), None, Some(dev));
        assert_eq!(hop_nodes(&hop, SankeyGranularity::DeviceRole), vec!["rtr"]);

        let hop_no_dev = make_hop(Some("198.51.100.1"), None, None);
        assert_eq!(
            hop_nodes(&hop_no_dev, SankeyGranularity::DeviceRole),
            vec!["198.51.100.1"]
        );
    }

    #[test]
    fn hop_nodes_device() {
        let dev = GatewayDevice {
            interface: None,
            device: Some("rtr0101".to_owned()),
            device_role: None,
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let hop = make_hop(Some("198.51.100.1"), None, Some(dev));
        assert_eq!(hop_nodes(&hop, SankeyGranularity::Device), vec!["rtr0101"]);

        let hop_no_dev = make_hop(Some("198.51.100.1"), None, None);
        assert_eq!(
            hop_nodes(&hop_no_dev, SankeyGranularity::Device),
            vec!["198.51.100.1"]
        );
    }

    #[test]
    fn hop_nodes_ptr() {
        // PTR present → use PTR.
        let mut hop = make_hop(Some("198.51.100.1"), None, None);
        hop.ptr = Some("host.example.net".to_owned());
        assert_eq!(
            hop_nodes(&hop, SankeyGranularity::Ptr),
            vec!["host.example.net"]
        );

        // No PTR → fall back to IP.
        let hop_no_ptr = make_hop(Some("198.51.100.1"), None, None);
        assert_eq!(
            hop_nodes(&hop_no_ptr, SankeyGranularity::Ptr),
            vec!["198.51.100.1"]
        );
    }

    #[test]
    fn hop_nodes_interface_both() {
        // device + interface both present → 2-element vec.
        let dev = GatewayDevice {
            interface: Some("xe-0-0-0".to_owned()),
            device: Some("rtr-example-a".to_owned()),
            device_role: None,
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let hop = make_hop(Some("198.51.100.1"), None, Some(dev));
        assert_eq!(
            hop_nodes(&hop, SankeyGranularity::Interface),
            vec!["rtr-example-a", "rtr-example-a/xe-0-0-0"]
        );
    }

    #[test]
    fn hop_nodes_interface_device_only() {
        // device present but interface absent → 1-element vec (same as Device).
        let dev = GatewayDevice {
            interface: None,
            device: Some("rtr-example-a".to_owned()),
            device_role: None,
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let hop = make_hop(Some("198.51.100.1"), None, Some(dev));
        assert_eq!(
            hop_nodes(&hop, SankeyGranularity::Interface),
            vec!["rtr-example-a"]
        );
    }

    #[test]
    fn hop_nodes_interface_no_device() {
        // No device at all → fallback to IP.
        let hop = make_hop(Some("198.51.100.1"), None, None);
        assert_eq!(
            hop_nodes(&hop, SankeyGranularity::Interface),
            vec!["198.51.100.1"]
        );
    }

    #[test]
    fn build_facility_merges_hops() {
        // Two records with different hop IPs but the same facility should produce
        // a single "colo05" node, not two separate nodes.
        let dev_a = GatewayDevice {
            interface: None,
            device: None,
            device_role: None,
            facility: Some("colo05".to_owned()),
            facing: None,
            customer_asn: None,
        };
        let dev_b = GatewayDevice {
            interface: None,
            device: None,
            device_role: None,
            facility: Some("colo05".to_owned()),
            facing: None,
            customer_asn: None,
        };
        let mut r1 = make_record("198.51.100.0/24", vec![]);
        r1.routes = vec![make_hop(Some("198.51.100.1"), None, Some(dev_a))];
        let mut r2 = make_record("198.51.100.128/25", vec![]);
        r2.routes = vec![make_hop(Some("198.51.100.2"), None, Some(dev_b))];

        let data = build(&[r1, r2], SankeyGranularity::Facility);
        let colo_count = data.nodes.iter().filter(|n| n.name == "colo05").count();
        assert_eq!(colo_count, 1, "facility 'colo05' must appear exactly once");
    }

    #[test]
    fn build_asn_label() {
        let mut record = make_record("198.51.100.0/24", vec![]);
        record.routes = vec![make_hop(Some("198.51.100.1"), Some(64496), None)];

        let data = build(&[record], SankeyGranularity::Asn);
        assert!(
            data.nodes.iter().any(|n| n.name == "AS64496"),
            "node 'AS64496' must be present"
        );
    }

    #[test]
    fn build_interface_expands_hops() {
        // Single hop with device+interface → 4 nodes: Internet, device, interface, CIDR.
        let dev = GatewayDevice {
            interface: Some("xe-0-0-0".to_owned()),
            device: Some("rtr-example-a".to_owned()),
            device_role: None,
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let mut record = make_record("198.51.100.0/24", vec![]);
        record.routes = vec![make_hop(Some("198.51.100.1"), None, Some(dev))];

        let data = build(&[record], SankeyGranularity::Interface);
        let names: Vec<&str> = data.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(
            names.contains(&"rtr-example-a"),
            "device node must be present"
        );
        assert!(
            names.contains(&"rtr-example-a/xe-0-0-0"),
            "interface node must be present as device/interface"
        );
        // Links: Internet→rtr-example-a, rtr-example-a→rtr-example-a/xe-0-0-0, …→CIDR
        assert!(
            data.links
                .iter()
                .any(|l| l.source == "Internet" && l.target == "rtr-example-a"),
            "Internet→device link required"
        );
        assert!(
            data.links
                .iter()
                .any(|l| l.source == "rtr-example-a" && l.target == "rtr-example-a/xe-0-0-0"),
            "device→interface link required"
        );
        assert!(
            data.links
                .iter()
                .any(|l| l.source == "rtr-example-a/xe-0-0-0" && l.target == "198.51.100.0/24"),
            "interface→CIDR link required"
        );
    }

    #[test]
    fn build_interface_multihop() {
        // Two hops: (rtr-example-b, et-0-0-0) then (rtr-example-c, xe-0-0-0).
        let dev_agg = GatewayDevice {
            interface: Some("et-0-0-0".to_owned()),
            device: Some("rtr-example-b".to_owned()),
            device_role: None,
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let dev_edge = GatewayDevice {
            interface: Some("xe-0-0-0".to_owned()),
            device: Some("rtr-example-c".to_owned()),
            device_role: None,
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let mut record = make_record("198.51.100.0/24", vec![]);
        record.routes = vec![
            make_hop(Some("198.51.100.1"), None, Some(dev_agg)),
            make_hop(Some("198.51.100.2"), None, Some(dev_edge)),
        ];

        let data = build(&[record], SankeyGranularity::Interface);
        // Expected chain: Internet → rtr-example-b → rtr-example-b/et-0-0-0 → rtr-example-c → …
        assert!(
            data.links
                .iter()
                .any(|l| l.source == "rtr-example-b/et-0-0-0" && l.target == "rtr-example-c"),
            "rtr-example-b/et-0-0-0→rtr-example-c link required"
        );
    }

    #[test]
    fn build_all_has_all_keys() {
        let record = make_record("198.51.100.0/24", vec![("198.51.100.1", None)]);
        let all = build_all(&[record]);
        assert!(!all.asn.nodes.is_empty(), "asn must have at least one node");
        assert!(
            !all.facility.nodes.is_empty(),
            "facility must have at least one node"
        );
        assert!(
            !all.device_role.nodes.is_empty(),
            "device_role must have at least one node"
        );
        assert!(
            !all.device.nodes.is_empty(),
            "device must have at least one node"
        );
        assert!(
            !all.iface.nodes.is_empty(),
            "interface must have at least one node"
        );
        assert!(!all.ptr.nodes.is_empty(), "ptr must have at least one node");
    }
}
