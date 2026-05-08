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
/// Selection rules:
/// - /32  → the single host address
/// - /31  → both addresses
/// - /30  → first and last usable (2 addresses)
/// - /29+ → first 3 usable + last 3 usable (up to 6 total, de-duplicated)
///
/// IPv6 CIDRs are silently skipped (Phase 1 is IPv4 only).
#[must_use]
pub fn expand_cidrs(cidrs: &[IpNet]) -> Vec<(IpNet, IpAddr)> {
    let mut out = Vec::new();
    for &cidr in cidrs {
        let IpNet::V4(net) = cidr else {
            continue;
        };
        let pairs = select_targets(net);
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
pub fn compute_remaining<'a>(
    targets: &'a [(IpNet, IpAddr)],
    done: &HashSet<IpAddr>,
) -> Vec<&'a (IpNet, IpAddr)> {
    targets
        .iter()
        .filter(|(_, ip)| !done.contains(ip))
        .collect()
}

// ---- target selection helpers ----

const EMPTY_V4: &[Ipv4Addr] = &[];

fn select_targets(net: Ipv4Net) -> Vec<Ipv4Addr> {
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

    // /29 and wider: first 3 usable + last 3 usable.
    if hosts.len() <= 6 {
        return hosts;
    }

    let first3 = hosts.get(..3).unwrap_or(EMPTY_V4).to_vec();
    let last_start = hosts.len().saturating_sub(3);
    let last3 = hosts.get(last_start..).unwrap_or(EMPTY_V4).to_vec();

    // De-duplicate (first3 and last3 can overlap for very small networks).
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(6);
    for ip in first3.into_iter().chain(last3) {
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
        let pairs = expand_cidrs(&[net("192.0.2.1/32")]);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1, v4("192.0.2.1"));
    }

    #[test]
    fn expand_slash31_gives_two_addresses() {
        let pairs = expand_cidrs(&[net("192.0.2.0/31")]);
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn expand_slash30_gives_two_usable_addresses() {
        let pairs = expand_cidrs(&[net("192.0.2.0/30")]);
        // /30 hosts(): 192.0.2.1, 192.0.2.2
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].1, v4("192.0.2.1"));
        assert_eq!(pairs[1].1, v4("192.0.2.2"));
    }

    #[test]
    fn expand_slash29_gives_six_addresses() {
        let pairs = expand_cidrs(&[net("192.0.2.0/29")]);
        // /29 hosts(): 192.0.2.1..192.0.2.6 (6 usable)
        assert_eq!(pairs.len(), 6);
    }

    #[test]
    fn expand_slash24_gives_first3_plus_last3() {
        let pairs = expand_cidrs(&[net("192.0.2.0/24")]);
        assert_eq!(pairs.len(), 6);
        // First 3 usable: .1, .2, .3
        assert_eq!(pairs[0].1, v4("192.0.2.1"));
        assert_eq!(pairs[1].1, v4("192.0.2.2"));
        assert_eq!(pairs[2].1, v4("192.0.2.3"));
        // Last 3 usable: .252, .253, .254 (broadcast .255 is excluded by hosts())
        assert_eq!(pairs[3].1, v4("192.0.2.252"));
        assert_eq!(pairs[4].1, v4("192.0.2.253"));
        assert_eq!(pairs[5].1, v4("192.0.2.254"));
    }

    #[test]
    fn expand_slash24_unique_targets() {
        // Verify no duplicates.
        let pairs = expand_cidrs(&[net("10.0.0.0/24")]);
        let ips: HashSet<_> = pairs.iter().map(|(_, ip)| ip).collect();
        assert_eq!(pairs.len(), ips.len());
    }

    #[test]
    fn expand_ipv6_skipped() {
        let pairs = expand_cidrs(&[net("2001:db8::/48")]);
        assert!(pairs.is_empty());
    }

    #[test]
    fn compute_remaining_filters_done() {
        let cidr = net("192.0.2.0/30");
        let targets = expand_cidrs(&[cidr]);
        let mut done = HashSet::new();
        done.insert(targets[0].1);
        let remaining = compute_remaining(&targets, &done);
        assert_eq!(remaining.len(), targets.len() - 1);
    }

    #[test]
    fn compute_remaining_all_done() {
        let cidr = net("192.0.2.0/30");
        let targets = expand_cidrs(&[cidr]);
        let done: HashSet<IpAddr> = targets.iter().map(|(_, ip)| *ip).collect();
        let remaining = compute_remaining(&targets, &done);
        assert!(remaining.is_empty());
    }

    #[test]
    fn compute_remaining_none_done() {
        let cidr = net("192.0.2.0/30");
        let targets = expand_cidrs(&[cidr]);
        let done = HashSet::new();
        let remaining = compute_remaining(&targets, &done);
        assert_eq!(remaining.len(), targets.len());
    }
}
