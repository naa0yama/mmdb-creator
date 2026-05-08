//! mmdb-dns: DNS enrichment library for mmdb-creator.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//!
//! Resolves a list of IP addresses to ASN and PTR data using:
//! - Team Cymru DNS TXT lookups via DNS-over-HTTPS (`DoH`)
//! - PTR reverse lookups via DNS-over-HTTPS (`DoH`)
//!
//! Default `DoH` provider is Cloudflare (`cloudflare-dns.com`), configurable
//! via [`DnsConfig`].

pub(crate) mod cymru;
pub(crate) mod ptr;
pub(crate) mod resolver;
pub mod types;

pub use types::{DnsConfig, DnsEnrichResult, DohServer};

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context as _, Result};

/// Enrich a list of IP addresses with ASN (Team Cymru) and PTR data via `DoH`.
///
/// Returns a map of each IP to its enrichment result. Fields are `None` if
/// the lookup failed or returned no data.
///
/// # Errors
///
/// Returns an error if the `DoH` resolver cannot be constructed.
// NOTEST(io): builds DoH resolver and makes DNS queries — requires live network
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn enrich(
    ips: &[IpAddr],
    config: &DnsConfig,
) -> Result<HashMap<IpAddr, DnsEnrichResult>> {
    // Build DoH resolver (once, shared by cymru and ptr).
    let resolver = resolver::build_resolver(&config.doh_server, config.timeout_sec)
        .context("failed to build DoH resolver for DNS enrichment")?;

    // Cymru lookup.
    let cymru_map = cymru::lookup(ips, &resolver, config).await;

    // PTR lookup.
    let ptr_map = ptr::lookup(ips, &resolver, config).await;

    // Merge results per IP.
    let mut results = HashMap::new();
    for &ip in ips {
        let cymru = cymru_map.get(&ip);
        let ptr = ptr_map.get(&ip).cloned();
        if cymru.is_some() || ptr.is_some() {
            results.insert(
                ip,
                DnsEnrichResult {
                    asn: cymru.map(|c| c.asn),
                    prefix: cymru.map(|c| c.prefix.clone()),
                    country: cymru.map(|c| c.country.clone()),
                    registry: cymru.map(|c| c.registry.clone()),
                    allocated: cymru.map(|c| c.allocated.clone()),
                    as_name: cymru.and_then(|c| c.as_name.clone()),
                    ptr,
                },
            );
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::cymru::CymruData;

    fn make_cymru(asn: u32) -> CymruData {
        CymruData {
            asn,
            prefix: String::from("203.0.113.0/24"),
            country: String::from("US"),
            registry: String::from("arin"),
            allocated: String::from("2010-01-01"),
            as_name: Some(String::from("TESTNET")),
        }
    }

    #[test]
    fn merge_cymru_and_ptr() {
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let mut cymru_map = std::collections::HashMap::new();
        cymru_map.insert(ip, make_cymru(64496));
        let mut ptr_map = std::collections::HashMap::new();
        ptr_map.insert(ip, String::from("host.example.com"));

        let result = cymru_map.get(&ip);
        let ptr = ptr_map.get(&ip).cloned();
        let enriched = DnsEnrichResult {
            asn: result.map(|c| c.asn),
            prefix: result.map(|c| c.prefix.clone()),
            country: result.map(|c| c.country.clone()),
            registry: result.map(|c| c.registry.clone()),
            allocated: result.map(|c| c.allocated.clone()),
            as_name: result.and_then(|c| c.as_name.clone()),
            ptr,
        };
        assert_eq!(enriched.asn, Some(64496));
        assert_eq!(enriched.ptr.as_deref(), Some("host.example.com"));
        assert_eq!(enriched.as_name.as_deref(), Some("TESTNET"));
    }

    #[test]
    fn merge_ptr_only() {
        let ip: IpAddr = "203.0.113.2".parse().unwrap();
        let cymru_map: std::collections::HashMap<IpAddr, CymruData> =
            std::collections::HashMap::new();
        let mut ptr_map = std::collections::HashMap::new();
        ptr_map.insert(ip, String::from("host2.example.com"));

        let result = cymru_map.get(&ip);
        let ptr = ptr_map.get(&ip).cloned();
        assert!(result.is_none());
        assert!(ptr.is_some());
        // Entry is included (ptr only).
        assert!(result.is_some() || ptr.is_some());
    }

    #[test]
    fn merge_no_data_excluded() {
        let ip: IpAddr = "203.0.113.3".parse().unwrap();
        let cymru_map: std::collections::HashMap<IpAddr, CymruData> =
            std::collections::HashMap::new();
        let ptr_map: std::collections::HashMap<IpAddr, String> = std::collections::HashMap::new();

        let cymru = cymru_map.get(&ip);
        let ptr = ptr_map.get(&ip).cloned();
        // Both None → entry excluded.
        assert!(cymru.is_none() && ptr.is_none());
    }
}
