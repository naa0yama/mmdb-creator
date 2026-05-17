//! Scan resume logic: CIDR target expansion and completed-target tracking.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use anyhow::{Context as _, Result};
use ipnet::{IpNet, Ipv4Net};
use mmdb_core::types::ScanRecord;

/// Expand a list of CIDRs into `(parent_cidr, target_ip)` pairs for scanning.
///
/// When `full` is `false` (default), the gateway-heuristic sample is used:
/// - /32  → the single host address
/// - /31  → both addresses
/// - /30  → first and last usable (2 addresses)
/// - /29  → all 6 usable addresses (≤ 7 threshold, returned in full)
/// - /28+ → first 4 usable + last 3 usable (up to 7 total, de-duplicated)
///
/// The 4+3 asymmetry ensures an odd total so hop-level majority voting never
/// ties at exactly 50%.  The leading `.1`–`.4` addresses cover the VRRP GW
/// and redundant router pair; `.4` is typically unassigned but its traceroute
/// hops still contribute valid path evidence.
///
/// When `full` is `true`, every usable host address in each CIDR is included.
/// /32, /31, /30, and /29 produce the same result as the default mode.
///
/// IPv6 CIDRs are silently skipped (Phase 1 is IPv4 only).
#[must_use]
pub fn expand_cidrs(cidrs: &[IpNet], full: bool) -> Vec<(IpNet, IpAddr)> {
    let mut out = Vec::new();
    for &cidr in cidrs {
        let IpNet::V4(net) = cidr else {
            continue;
        };
        let pairs = select_targets(net, full);
        for ip in pairs {
            out.push((cidr, IpAddr::V4(ip)));
        }
    }
    out
}

/// Read an existing `scan.jsonl` and collect the set of already-scanned destination IPs.
///
/// Lines that fail to parse are silently skipped so a partially-written file does not
/// prevent resumption.
///
/// # Errors
///
/// Returns an error only if the file exists but cannot be opened.
// NOTEST(io): reads scan JSONL file from filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn load_completed(path: &Path) -> Result<HashSet<IpAddr>> {
    if !path.exists() {
        return Ok(HashSet::new());
    }

    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read scan resume file {}", path.display()))?;

    let mut done = HashSet::new();
    for line in raw.lines() {
        let Ok(record) = serde_json::from_str::<ScanRecord>(line) else {
            continue;
        };
        if let Ok(ip) = record.routes.destination.parse::<IpAddr>() {
            done.insert(ip);
        }
    }
    Ok(done)
}

/// Return only the targets not already in `done`.
#[must_use]
pub fn compute_remaining<'a, S: ::std::hash::BuildHasher>(
    targets: &'a [(IpNet, IpAddr)],
    done: &HashSet<IpAddr, S>,
) -> Vec<&'a (IpNet, IpAddr)> {
    targets
        .iter()
        .filter(|(_, ip)| !done.contains(ip))
        .collect()
}

// ---- target selection helpers ----

const EMPTY_V4: &[Ipv4Addr] = &[];

fn select_targets(net: Ipv4Net, full: bool) -> Vec<Ipv4Addr> {
    let prefix_len = net.prefix_len();

    if prefix_len == 32 {
        return vec![net.network()];
    }

    if prefix_len == 31 {
        return vec![net.network(), net.broadcast()];
    }

    let hosts: Vec<Ipv4Addr> = net.hosts().collect();

    if prefix_len == 30 {
        // /30 usable hosts: exactly 2 addresses
        return hosts;
    }

    // /28 and wider: full mode returns all hosts; default samples first 4 + last 3.
    // Threshold of 7 means /29 (6 hosts) is returned in full.
    if full || hosts.len() <= 7 {
        return hosts;
    }

    let first4 = hosts.get(..4).unwrap_or(EMPTY_V4).to_vec();
    let last_start = hosts.len().saturating_sub(3);
    let last3 = hosts.get(last_start..).unwrap_or(EMPTY_V4).to_vec();

    // De-duplicate (overlap is impossible when hosts.len() > 7, but guard anyway).
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(7);
    for ip in first4.into_iter().chain(last3) {
        if seen.insert(ip) {
            result.push(ip);
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn expand_slash32_gives_one_address() {
        let pairs = expand_cidrs(&[net("192.0.2.1/32")], false);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1, v4("192.0.2.1"));
    }

    #[test]
    fn expand_slash31_gives_two_addresses() {
        let pairs = expand_cidrs(&[net("192.0.2.0/31")], false);
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn expand_slash30_gives_two_usable_addresses() {
        let pairs = expand_cidrs(&[net("192.0.2.0/30")], false);
        // /30 hosts(): 192.0.2.1, 192.0.2.2
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].1, v4("192.0.2.1"));
        assert_eq!(pairs[1].1, v4("192.0.2.2"));
    }

    #[test]
    fn expand_slash29_gives_all_six_addresses() {
        let pairs = expand_cidrs(&[net("192.0.2.0/29")], false);
        // /29 hosts(): 192.0.2.1..192.0.2.6 (6 usable, ≤ 7 threshold → all returned)
        assert_eq!(pairs.len(), 6);
    }

    #[test]
    fn expand_slash24_gives_first4_plus_last3() {
        let pairs = expand_cidrs(&[net("192.0.2.0/24")], false);
        assert_eq!(pairs.len(), 7);
        // First 4 usable: .1, .2, .3, .4
        assert_eq!(pairs[0].1, v4("192.0.2.1"));
        assert_eq!(pairs[1].1, v4("192.0.2.2"));
        assert_eq!(pairs[2].1, v4("192.0.2.3"));
        assert_eq!(pairs[3].1, v4("192.0.2.4"));
        // Last 3 usable: .252, .253, .254 (broadcast .255 is excluded by hosts())
        assert_eq!(pairs[4].1, v4("192.0.2.252"));
        assert_eq!(pairs[5].1, v4("192.0.2.253"));
        assert_eq!(pairs[6].1, v4("192.0.2.254"));
    }

    #[test]
    fn expand_slash24_unique_targets() {
        // Verify no duplicates.
        let pairs = expand_cidrs(&[net("198.51.100.0/24")], false);
        let ips: HashSet<_> = pairs.iter().map(|(_, ip)| ip).collect();
        assert_eq!(pairs.len(), ips.len());
    }

    #[test]
    fn expand_ipv6_skipped() {
        let pairs = expand_cidrs(&[net("2001:db8::/48")], false);
        assert!(pairs.is_empty());
    }

    #[test]
    fn expand_full_slash24_gives_all_hosts() {
        let pairs = expand_cidrs(&[net("198.51.100.0/24")], true);
        // /24 has 254 usable hosts (.1–.254)
        assert_eq!(pairs.len(), 254);
        assert_eq!(pairs[0].1, v4("198.51.100.1"));
        assert_eq!(pairs[253].1, v4("198.51.100.254"));
    }

    #[test]
    fn expand_full_slash28_gives_all_hosts() {
        let pairs = expand_cidrs(&[net("198.51.100.0/28")], true);
        // /28 has 14 usable hosts (.1–.14)
        assert_eq!(pairs.len(), 14);
    }

    #[test]
    fn expand_full_slash29_same_as_default() {
        // /29 has exactly 6 usable hosts (≤ 7 threshold) — full and default produce the same result
        let default_pairs = expand_cidrs(&[net("198.51.100.0/29")], false);
        let full_pairs = expand_cidrs(&[net("198.51.100.0/29")], true);
        assert_eq!(default_pairs.len(), full_pairs.len());
        assert_eq!(default_pairs.len(), 6);
    }

    #[test]
    fn expand_slash28_gives_first4_plus_last3() {
        let pairs = expand_cidrs(&[net("198.51.100.0/28")], false);
        // /28 has 14 usable hosts (.1–.14); default → first 4 + last 3 = 7
        assert_eq!(pairs.len(), 7);
        assert_eq!(pairs[0].1, v4("198.51.100.1"));
        assert_eq!(pairs[3].1, v4("198.51.100.4"));
        assert_eq!(pairs[4].1, v4("198.51.100.12"));
        assert_eq!(pairs[6].1, v4("198.51.100.14"));
    }

    #[test]
    fn expand_full_slash30_unchanged() {
        let default_pairs = expand_cidrs(&[net("198.51.100.0/30")], false);
        let full_pairs = expand_cidrs(&[net("198.51.100.0/30")], true);
        assert_eq!(default_pairs.len(), full_pairs.len());
    }

    #[test]
    fn compute_remaining_filters_done() {
        let cidr = net("192.0.2.0/30");
        let targets = expand_cidrs(&[cidr], false);
        let mut done = HashSet::new();
        done.insert(targets[0].1);
        let remaining = compute_remaining(&targets, &done);
        assert_eq!(remaining.len(), targets.len() - 1);
    }

    #[test]
    fn compute_remaining_all_done() {
        let cidr = net("192.0.2.0/30");
        let targets = expand_cidrs(&[cidr], false);
        let done: HashSet<IpAddr> = targets.iter().map(|(_, ip)| *ip).collect();
        let remaining = compute_remaining(&targets, &done);
        assert!(remaining.is_empty());
    }

    #[test]
    fn compute_remaining_none_done() {
        let cidr = net("192.0.2.0/30");
        let targets = expand_cidrs(&[cidr], false);
        let done = HashSet::new();
        let remaining = compute_remaining(&targets, &done);
        assert_eq!(remaining.len(), targets.len());
    }
}
