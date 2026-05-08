//! mmdb-whois: whois client library for mmdb-creator.
//!
//! Resolves ASN or IP/CIDR inputs into [`WhoisData`] by:
//!
//! 1. **ASN mode**: fetching announced prefixes from RIPE Stat, then querying
//!    each prefix via TCP port 43 whois.
//! 2. **Prefix mode**: querying supplied IPs/CIDRs directly via TCP port 43,
//!    skipping the RIPE Stat lookup.

pub mod client;
pub mod prefix;
pub mod rpsl;

pub use client::WhoisClient;
pub use prefix::PrefixClient;

use anyhow::Result;
use ipnet::IpNet;
use mmdb_core::{config::WhoisConfig, types::WhoisData};

/// Resolve an ASN to its announced prefixes and query whois for each, with AS fields embedded.
///
/// Execution order: announced-prefixes (1) → aut-num via RIPE Stat (3) → TCP 43 per CIDR (2).
/// AS fields (`as_num`, `as_name`, `as_descr`) are embedded into each [`WhoisData`] at query
/// time and persisted in the cache, so no post-processing enrichment step is needed.
///
/// # Errors
///
/// Returns an error if the RIPE Stat lookups fail. Individual TCP 43 query failures are
/// returned as `Err` entries in the result vector rather than aborting the entire batch.
pub async fn query_asn(
    whois: &WhoisClient,
    prefix_client: &PrefixClient,
    asn: u32,
) -> Result<Vec<(IpNet, Result<WhoisData>)>> {
    // Step 1: get announced prefixes.
    let prefixes = prefix_client.announced_prefixes(asn).await?;

    // Step 3: fetch aut-num data once (cached per ASN).
    let autnum = prefix_client.query_autnum(asn).await?;

    // Step 2: query TCP 43 per CIDR, embedding AS fields into each record.
    Ok(whois.query_all(&prefixes, Some(&autnum)).await)
}

/// Parse a comma-separated list of ASN strings into `u32` values.
///
/// Accepts both `"64496"` and `"AS64496"` formats.
///
/// # Errors
///
/// Returns an error if any entry cannot be parsed as a valid ASN number.
pub fn parse_asns(raw: &[String]) -> Result<Vec<u32>> {
    raw.iter()
        .map(|s| {
            let digits = s.trim().trim_start_matches("AS").trim_start_matches("as");
            digits
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("invalid ASN: {s:?} (expected number or AS<number>)"))
        })
        .collect()
}

/// Parse a comma-separated list of IP/CIDR strings into [`IpNet`] values.
///
/// Single IP addresses (without prefix length) are treated as host routes
/// (`/32` for IPv4, `/128` for IPv6).
///
/// # Errors
///
/// Returns an error if any entry cannot be parsed as a valid IP address or prefix.
pub fn parse_prefixes(raw: &[String]) -> Result<Vec<IpNet>> {
    raw.iter()
        .map(|s| {
            let s = s.trim();
            // Try CIDR first, then fall back to host address.
            s.parse::<IpNet>().or_else(|_| {
                s.parse::<std::net::IpAddr>()
                    .map(IpNet::from)
                    .map_err(|_| anyhow::anyhow!("invalid IP or CIDR: {s:?}"))
            })
        })
        .collect()
}

/// Build a [`WhoisClient`] and [`PrefixClient`] from config.
///
/// # Errors
///
/// Returns an error if the HTTP client for prefix resolution cannot be built.
pub fn clients_from_config(cfg: &WhoisConfig) -> Result<(WhoisClient, PrefixClient)> {
    Ok((
        WhoisClient::from_config(cfg),
        PrefixClient::from_config(cfg)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_asns_strips_prefix() {
        let raw = [
            "AS64496".to_owned(),
            "64497".to_owned(),
            "as64498".to_owned(),
        ];
        let asns = parse_asns(&raw).unwrap();
        assert_eq!(asns, [64_496, 64_497, 64_498]);
    }

    #[test]
    fn parse_asns_rejects_invalid() {
        let raw = ["not_a_number".to_owned()];
        assert!(parse_asns(&raw).is_err());
    }

    #[test]
    fn parse_prefixes_accepts_cidr() {
        let raw = ["192.0.2.0/24".to_owned()];
        let nets = parse_prefixes(&raw).unwrap();
        assert_eq!(nets.first().unwrap().to_string(), "192.0.2.0/24");
    }

    #[test]
    fn parse_prefixes_promotes_host_to_slash32() {
        let raw = ["192.0.2.1".to_owned()];
        let nets = parse_prefixes(&raw).unwrap();
        assert_eq!(nets.first().unwrap().prefix_len(), 32);
    }

    #[test]
    fn parse_prefixes_accepts_ipv6() {
        let raw = ["2001:db8::1".to_owned()];
        let nets = parse_prefixes(&raw).unwrap();
        assert_eq!(nets.first().unwrap().prefix_len(), 128);
    }

    #[test]
    fn parse_prefixes_rejects_invalid() {
        let raw = ["not_an_ip".to_owned()];
        assert!(parse_prefixes(&raw).is_err());
    }
}
