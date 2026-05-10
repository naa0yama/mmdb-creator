//! Gateway resolution: per-range backbone device identification via PTR patterns.
//!
//! All functions are pure (no I/O) and fully unit-testable.

use std::collections::HashMap;

use ipnet::IpNet;
use mmdb_core::types::{GatewayInfo, Hop, ScanGwRecord, ScanRecord, WhoisData};

use crate::ptr_parse::{self, CompiledPattern};

/// Resolve gateway information for each range in `records`.
///
/// Groups `records` by `range`, applies TTL-axis hop aggregation followed by
/// PTR-pattern gateway identification, and returns one [`ScanGwRecord`] per
/// unique range. Whois metadata is looked up from `whois_index` via
/// longest-prefix match rather than from the scan records themselves.
#[must_use]
pub fn resolve<S: ::std::hash::BuildHasher>(
    records: &[ScanRecord],
    patterns: &[CompiledPattern],
    whois_index: &HashMap<IpNet, WhoisData, S>,
) -> Vec<ScanGwRecord> {
    let mut by_range: HashMap<&str, Vec<&ScanRecord>> = HashMap::new();
    for record in records {
        by_range
            .entry(record.range.as_str())
            .or_default()
            .push(record);
    }

    let mut results: Vec<ScanGwRecord> = by_range
        .into_iter()
        .map(|(range, group)| resolve_range(range, &group, patterns, whois_index))
        .collect();

    results.sort_by(|a, b| {
        let a_net: Option<IpNet> = a.range.parse().ok();
        let b_net: Option<IpNet> = b.range.parse().ok();
        match (a_net, b_net) {
            (Some(an), Some(bn)) => an.cmp(&bn),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.range.cmp(&b.range),
        }
    });

    results
}

/// Find the most-specific whois entry whose prefix contains `target`.
///
/// Returns `None` when `target` is not covered by any entry in `whois_index`.
fn lpm_lookup<'a, S: ::std::hash::BuildHasher>(
    whois_index: &'a HashMap<IpNet, WhoisData, S>,
    target: &IpNet,
) -> Option<&'a WhoisData> {
    whois_index
        .iter()
        .filter(|(net, _)| net.contains(target))
        .max_by_key(|(net, _)| net.prefix_len())
        .map(|(_, data)| data)
}

#[allow(clippy::too_many_lines)]
fn resolve_range<S: ::std::hash::BuildHasher>(
    range: &str,
    records: &[&ScanRecord],
    patterns: &[CompiledPattern],
    whois_index: &HashMap<IpNet, WhoisData, S>,
) -> ScanGwRecord {
    let total = records.len();
    let whois = range
        .parse::<IpNet>()
        .ok()
        .and_then(|n| lpm_lookup(whois_index, &n));
    let netname = whois.map(|w| w.netname.clone());
    let descr = whois.and_then(|w| w.descr.clone());
    let as_num = whois.and_then(|w| w.as_num.clone());
    let as_name = whois.and_then(|w| w.as_name.clone());
    let as_descr = whois.and_then(|w| w.as_descr.clone());
    let inetnum = whois.map(|w| w.inetnum.clone());
    let country = whois.and_then(|w| w.country.clone());
    let whois_source = whois.and_then(|w| w.source.clone());
    let whois_last_modified = whois.and_then(|w| w.last_modified.clone());
    let measured_at = earliest_measured_at(records);
    let agg = aggregate_hops(records);

    // No hops at all.
    if agg.is_empty() {
        return ScanGwRecord {
            range: range.to_owned(),
            netname,
            descr,
            as_num,
            as_name,
            as_descr,
            inetnum,
            country,
            whois_source,
            whois_last_modified,
            gateway: GatewayInfo {
                ip: None,
                ptr: None,
                votes: 0,
                total,
                status: String::from("no_hops"),
                device: None,
            },
            routes: Vec::new(),
            host_ip: None,
            host_ptr: None,
            measured_at,
            xlsx: None,
            xlsx_matched: false,
            gateway_found: false,
        };
    }

    // Find gateway hop index (last hop whose PTR matches a pattern).
    let hops: Vec<&Hop> = agg.iter().map(|(h, _)| h).collect();
    let Some(idx) = ptr_candidate_index(&hops, patterns) else {
        let routes = agg.into_iter().map(|(h, _)| h).collect();
        return ScanGwRecord {
            range: range.to_owned(),
            netname,
            descr,
            as_num,
            as_name,
            as_descr,
            inetnum,
            country,
            whois_source,
            whois_last_modified,
            gateway: GatewayInfo {
                ip: None,
                ptr: None,
                votes: 0,
                total,
                status: String::from("no_ptr_match"),
                device: None,
            },
            routes,
            host_ip: None,
            host_ptr: None,
            measured_at,
            xlsx: None,
            xlsx_matched: false,
            gateway_found: false,
        };
    };

    // Slice routes up to and including the gateway, then build the inservice record.
    // `idx` < agg.len() is guaranteed: ptr_candidate_index iterates `hops` which was
    // built from `agg`, so the index is always valid.
    match agg.get(..=idx).and_then(<[_]>::split_last) {
        Some(((gw_hop, gw_votes), prefix)) => {
            let device = gw_hop
                .ptr
                .as_deref()
                .and_then(|p| ptr_parse::parse(p, patterns));
            let routes = prefix
                .iter()
                .map(|(h, _)| h.clone())
                .chain(std::iter::once(gw_hop.clone()))
                .collect();
            ScanGwRecord {
                range: range.to_owned(),
                netname,
                descr,
                as_num,
                as_name,
                as_descr,
                inetnum,
                country,
                whois_source,
                whois_last_modified,
                gateway: GatewayInfo {
                    ip: gw_hop.ip.clone(),
                    ptr: gw_hop.ptr.clone(),
                    votes: *gw_votes,
                    total,
                    status: String::from("inservice"),
                    device,
                },
                routes,
                host_ip: None,
                host_ptr: None,
                measured_at,
                xlsx: None,
                xlsx_matched: false,
                gateway_found: false,
            }
        }
        None => ScanGwRecord {
            range: range.to_owned(),
            netname,
            descr,
            as_num,
            as_name,
            as_descr,
            inetnum,
            country,
            whois_source,
            whois_last_modified,
            gateway: GatewayInfo {
                ip: None,
                ptr: None,
                votes: 0,
                total,
                status: String::from("no_ptr_match"),
                device: None,
            },
            routes: agg.into_iter().map(|(h, _)| h).collect(),
            host_ip: None,
            host_ptr: None,
            measured_at,
            xlsx: None,
            xlsx_matched: false,
            gateway_found: false,
        },
    }
}

/// Aggregate hops across all traces by TTL position using majority vote.
///
/// For each TTL position, the IP seen in the most traces wins. Returns
/// `(winning_hop, vote_count)` pairs sorted by hop position. Hops with
/// `ip: None` are skipped.
fn aggregate_hops(records: &[&ScanRecord]) -> Vec<(Hop, usize)> {
    // position → ip → (count, hop_ref)
    let mut by_pos: HashMap<u32, HashMap<String, (usize, &Hop)>> = HashMap::new();

    for record in records {
        for hop in &record.routes.hops {
            let Some(ref ip) = hop.ip else { continue };
            let ip_map = by_pos.entry(hop.hop).or_default();
            let entry = ip_map.entry(ip.clone()).or_insert((0, hop));
            entry.0 = entry.0.saturating_add(1);
        }
    }

    let mut positions: Vec<u32> = by_pos.keys().copied().collect();
    positions.sort_unstable();

    positions
        .into_iter()
        .filter_map(|pos| {
            let ip_map = by_pos.get(&pos)?;
            let max_votes = ip_map.values().map(|(c, _)| *c).max()?;
            let (votes, hop) = ip_map.values().find(|(c, _)| *c == max_votes)?;
            Some(((*hop).clone(), *votes))
        })
        .collect()
}

/// Walk hops from last to first; return the index of the first hop whose PTR
/// matches a configured pattern.
fn ptr_candidate_index(hops: &[&Hop], patterns: &[CompiledPattern]) -> Option<usize> {
    hops.iter()
        .enumerate()
        .rev()
        .find(|(_, h)| {
            h.ptr
                .as_deref()
                .is_some_and(|ptr| ptr_parse::parse(ptr, patterns).is_some())
        })
        .map(|(i, _)| i)
}

fn earliest_measured_at(records: &[&ScanRecord]) -> Option<String> {
    records
        .iter()
        .map(|r| r.routes.measured_at.as_str())
        .min()
        .map(std::borrow::ToOwned::to_owned)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use mmdb_core::{
        config::PtrPattern,
        types::{Hop, RouteData, ScanRecord, WhoisData},
    };

    fn compiled_patterns() -> Vec<CompiledPattern> {
        let p = PtrPattern {
            domain: Some(String::from("example.ad.jp")),
            regex: String::from(
                r"(?x)
                  ^(?:(?P<facing>user(?:\.virtual)?|virtual)\.)?
                  (?:as(?P<customer_asn>\d+)\.)?
                  (?P<interface>(?:ge|xe|et)-[\d-]+)
                  (?:\.[a-z]+\d+)?\.
                  (?P<device>(?P<device_role>[a-z]+)\d+)\.
                  (?P<facility>[a-z0-9]+)\.
                  example\.ad\.jp$",
            ),
            excludes: vec![],
        };
        ptr_parse::compile(&[p]).unwrap()
    }

    fn hop(n: u32, ip: &str, ptr: Option<&str>) -> Hop {
        Hop {
            hop: n,
            ip: Some(ip.to_owned()),
            rtt_avg: Some(1.0),
            rtt_best: Some(0.9),
            rtt_worst: Some(1.1),
            icmp_type: Some(11),
            asn: None,
            ptr: ptr.map(str::to_owned),
        }
    }

    fn null_hop(n: u32) -> Hop {
        Hop {
            hop: n,
            ip: None,
            rtt_avg: None,
            rtt_best: None,
            rtt_worst: None,
            icmp_type: None,
            asn: None,
            ptr: None,
        }
    }

    fn record(range: &str, hops: Vec<Hop>) -> ScanRecord {
        ScanRecord {
            range: range.to_owned(),
            routes: RouteData {
                version: String::from("0.1"),
                measured_at: String::from("2026-01-01T00:00:00Z"),
                source: String::from("198.51.100.254"),
                destination: String::from("198.51.100.1"),
                stop_reason: String::from("COMPLETED"),
                hops,
            },
        }
    }

    fn whois_for(range: &str, netname: &str, descr: &str) -> HashMap<IpNet, WhoisData> {
        let mut m = HashMap::new();
        m.insert(
            range.parse().unwrap(),
            WhoisData {
                inetnum: range.to_owned(),
                netname: netname.to_owned(),
                descr: Some(descr.to_owned()),
                country: Some(String::from("JP")),
                source: Some(String::from("APNIC")),
                last_modified: Some(String::from("2025-01-01T00:00:00Z")),
                as_num: None,
                as_name: None,
                as_descr: None,
            },
        );
        m
    }

    fn record_at(range: &str, hops: Vec<Hop>, measured_at: &str) -> ScanRecord {
        let mut r = record(range, hops);
        r.routes.measured_at = measured_at.to_owned();
        r
    }

    const GW_PTR: &str = "user.ge-0-0-0.rtr0101.dc01.example.ad.jp";
    const GW_PTR2: &str = "user.ge-0-0-1.rtr0102.dc01.example.ad.jp";

    // --- lpm_lookup ---

    #[test]
    fn lpm_lookup_exact_match() {
        let whois = whois_for("198.51.100.0/24", "EXACT-NET", "Exact match");
        let target: IpNet = "198.51.100.0/24".parse().unwrap();
        let result = lpm_lookup(&whois, &target);
        assert!(result.is_some());
        assert_eq!(result.unwrap().netname, "EXACT-NET");
    }

    #[test]
    fn lpm_lookup_subnet_matches_supernet() {
        // whois has /24, target is /30 — should still match via containment
        let whois = whois_for("198.51.100.0/24", "SUPER-NET", "Supernet");
        let target: IpNet = "198.51.100.0/30".parse().unwrap();
        let result = lpm_lookup(&whois, &target);
        assert!(result.is_some());
        assert_eq!(result.unwrap().netname, "SUPER-NET");
    }

    #[test]
    fn lpm_lookup_prefers_longer_prefix() {
        let mut whois = whois_for("198.51.100.0/24", "BROAD-NET", "Broad");
        whois.insert(
            "198.51.100.0/28".parse().unwrap(),
            WhoisData {
                inetnum: "198.51.100.0/28".to_owned(),
                netname: "NARROW-NET".to_owned(),
                descr: None,
                country: None,
                source: None,
                last_modified: None,
                as_num: None,
                as_name: None,
                as_descr: None,
            },
        );
        let target: IpNet = "198.51.100.0/30".parse().unwrap();
        let result = lpm_lookup(&whois, &target);
        assert_eq!(result.unwrap().netname, "NARROW-NET");
    }

    #[test]
    fn lpm_lookup_no_match_returns_none() {
        let whois = whois_for("198.51.100.0/24", "OTHER-NET", "Other");
        let target: IpNet = "203.0.113.0/30".parse().unwrap();
        assert!(lpm_lookup(&whois, &target).is_none());
    }

    // --- aggregate_hops ---

    #[test]
    fn aggregate_hops_single_trace() {
        let records = [record(
            "198.51.100.0/29",
            vec![hop(1, "198.51.100.10", None), hop(2, "198.51.100.11", None)],
        )];
        let refs: Vec<&ScanRecord> = records.iter().collect();
        let agg = aggregate_hops(&refs);
        assert_eq!(agg.len(), 2);
        assert_eq!(agg[0].0.ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(agg[0].1, 1);
    }

    #[test]
    fn aggregate_hops_consensus() {
        let records = [
            record("198.51.100.0/29", vec![hop(1, "198.51.100.10", None)]),
            record("198.51.100.0/29", vec![hop(1, "198.51.100.10", None)]),
        ];
        let refs: Vec<&ScanRecord> = records.iter().collect();
        let agg = aggregate_hops(&refs);
        assert_eq!(agg[0].1, 2); // both traces agreed
    }

    #[test]
    fn aggregate_hops_majority_wins() {
        // 3 traces at TTL 1: 2×A, 1×B → A wins
        let records = [
            record("198.51.100.0/29", vec![hop(1, "198.51.100.10", None)]),
            record("198.51.100.0/29", vec![hop(1, "198.51.100.10", None)]),
            record("198.51.100.0/29", vec![hop(1, "198.51.100.99", None)]),
        ];
        let refs: Vec<&ScanRecord> = records.iter().collect();
        let agg = aggregate_hops(&refs);
        assert_eq!(agg[0].0.ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(agg[0].1, 2);
    }

    #[test]
    fn aggregate_hops_null_hops_skipped() {
        let records = [
            record("198.51.100.0/29", vec![hop(1, "198.51.100.10", None)]),
            record("198.51.100.0/29", vec![null_hop(1)]),
        ];
        let refs: Vec<&ScanRecord> = records.iter().collect();
        let agg = aggregate_hops(&refs);
        // only 1 trace contributed at TTL 1
        assert_eq!(agg[0].0.ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(agg[0].1, 1);
    }

    #[test]
    fn aggregate_hops_empty_when_no_hops() {
        let records = [record("198.51.100.0/29", vec![])];
        let refs: Vec<&ScanRecord> = records.iter().collect();
        assert!(aggregate_hops(&refs).is_empty());
    }

    // --- ptr_candidate_index ---

    #[test]
    fn ptr_candidate_index_matches_last() {
        let patterns = compiled_patterns();
        let h1 = hop(1, "198.51.100.10", None);
        let h2 = hop(2, "198.51.100.11", Some(GW_PTR));
        let hops: Vec<&Hop> = vec![&h1, &h2];
        assert_eq!(ptr_candidate_index(&hops, &patterns), Some(1));
    }

    #[test]
    fn ptr_candidate_index_skips_no_ptr() {
        let patterns = compiled_patterns();
        let h1 = hop(1, "198.51.100.10", Some(GW_PTR));
        let h2 = hop(2, "198.51.100.11", None);
        let hops: Vec<&Hop> = vec![&h1, &h2];
        // last hop has no PTR → finds h1 at index 0
        assert_eq!(ptr_candidate_index(&hops, &patterns), Some(0));
    }

    #[test]
    fn ptr_candidate_index_no_match() {
        let patterns = compiled_patterns();
        let h = hop(1, "198.51.100.10", Some("host.docs.example.com"));
        let hops: Vec<&Hop> = vec![&h];
        assert!(ptr_candidate_index(&hops, &patterns).is_none());
    }

    // --- resolve status ---

    #[test]
    fn resolve_status_no_hops() {
        let patterns = compiled_patterns();
        let records = [record("198.51.100.0/29", vec![])];
        let results = resolve(&records, &patterns, &HashMap::new());
        assert_eq!(results[0].gateway.status, "no_hops");
        assert!(results[0].routes.is_empty());
    }

    #[test]
    fn resolve_status_no_ptr_match() {
        let patterns = compiled_patterns();
        let records = [record(
            "198.51.100.0/29",
            vec![hop(1, "198.51.100.10", Some("host.docs.example.com"))],
        )];
        let results = resolve(&records, &patterns, &HashMap::new());
        assert_eq!(results[0].gateway.status, "no_ptr_match");
        assert_eq!(results[0].routes.len(), 1); // all aggregated hops present
    }

    #[test]
    fn resolve_status_inservice() {
        let patterns = compiled_patterns();
        let records = [record(
            "198.51.100.0/29",
            vec![hop(1, "198.51.100.10", Some(GW_PTR))],
        )];
        let results = resolve(&records, &patterns, &HashMap::new());
        assert_eq!(results[0].gateway.status, "inservice");
        assert_eq!(results[0].gateway.ip.as_deref(), Some("198.51.100.10"));
    }

    #[test]
    fn resolve_routes_sliced_to_gateway() {
        let patterns = compiled_patterns();
        // 3 hops: transit, gateway, customer host
        let records = [record(
            "198.51.100.0/29",
            vec![
                hop(1, "198.51.100.1", None),
                hop(2, "198.51.100.10", Some(GW_PTR)),
                hop(3, "198.51.100.11", Some("host.customer.example.com")),
            ],
        )];
        let results = resolve(&records, &patterns, &HashMap::new());
        // routes should stop at hop 2 (the gateway), not include hop 3
        assert_eq!(results[0].routes.len(), 2);
        assert_eq!(results[0].routes[1].ip.as_deref(), Some("198.51.100.10"));
    }

    #[test]
    fn resolve_gateway_device_populated() {
        let patterns = compiled_patterns();
        let records = [record(
            "198.51.100.0/29",
            vec![hop(1, "198.51.100.10", Some(GW_PTR))],
        )];
        let results = resolve(&records, &patterns, &HashMap::new());
        let dev = results[0].gateway.device.as_ref().unwrap();
        assert_eq!(dev.device_role.as_deref(), Some("rtr"));
        assert_eq!(dev.facility.as_deref(), Some("dc01"));
    }

    #[test]
    fn resolve_majority_vote_across_traces() {
        let patterns = compiled_patterns();
        // 4 traces: 3 agree on GW_PTR, 1 disagrees
        let records = [
            record(
                "198.51.100.0/29",
                vec![hop(1, "198.51.100.10", Some(GW_PTR))],
            ),
            record(
                "198.51.100.0/29",
                vec![hop(1, "198.51.100.10", Some(GW_PTR))],
            ),
            record(
                "198.51.100.0/29",
                vec![hop(1, "198.51.100.10", Some(GW_PTR))],
            ),
            record(
                "198.51.100.0/29",
                vec![hop(1, "198.51.100.11", Some(GW_PTR2))],
            ),
        ];
        let results = resolve(&records, &patterns, &HashMap::new());
        assert_eq!(results[0].gateway.ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(results[0].gateway.votes, 3);
        assert_eq!(results[0].gateway.total, 4);
    }

    #[test]
    fn resolve_netname_descr_propagated() {
        let patterns = compiled_patterns();
        let records = [record("198.51.100.0/29", vec![])];
        let whois = whois_for("198.51.100.0/29", "EXAMPLE-NET", "Example Network");
        let results = resolve(&records, &patterns, &whois);
        assert_eq!(results[0].netname.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(results[0].descr.as_deref(), Some("Example Network"));
    }

    #[test]
    fn resolve_whois_fields_propagated() {
        let patterns = compiled_patterns();
        let records = [record("198.51.100.0/29", vec![])];
        let whois = whois_for("198.51.100.0/29", "EXAMPLE-NET", "Example Network");
        let results = resolve(&records, &patterns, &whois);
        assert_eq!(results[0].inetnum.as_deref(), Some("198.51.100.0/29"));
        assert_eq!(results[0].country.as_deref(), Some("JP"));
        assert_eq!(results[0].whois_source.as_deref(), Some("APNIC"));
        assert_eq!(
            results[0].whois_last_modified.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
    }

    #[test]
    fn resolve_whois_lpm_subnet() {
        // whois has /24, scan range is /30 — LPM should match the /24
        let patterns = compiled_patterns();
        let records = [record("198.51.100.0/30", vec![])];
        let whois = whois_for("198.51.100.0/24", "SUPER-NET", "Supernet");
        let results = resolve(&records, &patterns, &whois);
        assert_eq!(results[0].netname.as_deref(), Some("SUPER-NET"));
        assert_eq!(results[0].country.as_deref(), Some("JP"));
        assert_eq!(results[0].whois_source.as_deref(), Some("APNIC"));
    }

    #[test]
    fn resolve_groups_by_range() {
        let patterns = compiled_patterns();
        let records = [
            record(
                "198.51.100.0/25",
                vec![hop(1, "198.51.100.10", Some(GW_PTR))],
            ),
            record(
                "198.51.100.128/25",
                vec![hop(1, "198.51.100.200", Some(GW_PTR2))],
            ),
        ];
        let results = resolve(&records, &patterns, &HashMap::new());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].range, "198.51.100.0/25");
        assert_eq!(results[1].range, "198.51.100.128/25");
    }

    #[test]
    fn resolve_measured_at_earliest() {
        let patterns = compiled_patterns();
        let records = [
            record_at("198.51.100.0/29", vec![], "2026-05-01T10:00:00Z"),
            record_at("198.51.100.0/29", vec![], "2026-05-01T09:00:00Z"),
        ];
        let results = resolve(&records, &patterns, &HashMap::new());
        assert_eq!(
            results[0].measured_at.as_deref(),
            Some("2026-05-01T09:00:00Z")
        );
    }
}
