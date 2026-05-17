//! IP address parsing and CIDR decomposition utilities.
//!
//! Provides [`parse_addresses`] for flexible multi-format IP address parsing
//! and [`range_to_cidrs`] for decomposing IP ranges into minimal CIDR sets.

// Consumed by reader.rs — remove when fully integrated
#![allow(dead_code)]

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

use anyhow::{Context as _, bail};
use ipnet::IpNet;
use regex::Regex;

// -------------------------------------------------------------------------------------------------
// Lazy regex
// -------------------------------------------------------------------------------------------------

static ANNOTATION_RE: OnceLock<Regex> = OnceLock::new();

/// Returns a compiled regex that matches parenthetical annotations.
///
/// Example: `" (VIP: .1)"` → removed.
fn annotation_re() -> &'static Regex {
    ANNOTATION_RE.get_or_init(|| {
        // REASON: pattern is a compile-time constant; failure would be a programming error.
        #[allow(clippy::unwrap_used)]
        Regex::new(r"\s*\([^)]*\)").unwrap()
    })
}

// -------------------------------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------------------------------

/// Parse a raw multi-format IP address string into a list of [`IpNet`] values.
///
/// The input may contain CIDRs, bare IP addresses, and IP ranges (e.g. `10.0.0.0-10.0.0.7`),
/// separated by commas and/or line endings. Parenthetical annotations (e.g. `(VIP: .1)`) are
/// stripped before parsing.
///
/// Returns a tuple `(addresses, warning_count)` where `warning_count` is the number of tokens
/// that could not be parsed. Each invalid token is logged via [`tracing::warn!`].
///
/// # Examples
///
/// ```ignore
/// let (nets, warns) = parse_addresses("10.0.0.0/24, 192.168.1.1");
/// assert_eq!(warns, 0);
/// assert_eq!(nets.len(), 2);
/// ```
pub fn parse_addresses(raw: &str) -> (Vec<IpNet>, usize) {
    // Step 1: normalise line endings → commas
    let normalised = raw.replace("\r\n", ",").replace(['\r', '\n'], ",");

    // Step 2: strip parenthetical annotations
    let stripped = annotation_re().replace_all(&normalised, "");

    // Step 3-4: split by comma, trim, remove empty tokens
    let tokens: Vec<&str> = stripped
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    let mut addresses: Vec<IpNet> = Vec::with_capacity(tokens.len());
    let mut warning_count: usize = 0;

    for token in tokens {
        // Try CIDR first
        if let Ok(net) = IpNet::from_str(token) {
            addresses.push(net);
            continue;
        }

        // Try bare IP address
        if let Ok(addr) = IpAddr::from_str(token) {
            let bits = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            // REASON: prefix length is always valid for the corresponding address family.
            #[allow(clippy::unwrap_used)]
            addresses.push(IpNet::new(addr, bits).unwrap());
            continue;
        }

        // Try IP range (e.g. "10.0.0.0-10.0.0.7")
        if token.contains('-') {
            let mut parts = token.splitn(2, '-');
            let left = parts.next().unwrap_or("").trim();
            let right = parts.next().unwrap_or("").trim();

            if let (Ok(start), Ok(end)) = (IpAddr::from_str(left), IpAddr::from_str(right)) {
                match range_to_cidrs(start, end) {
                    Ok(cidrs) => {
                        addresses.extend(cidrs);
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(token, error = %e, "failed to parse address token");
                        warning_count = warning_count.saturating_add(1);
                        continue;
                    }
                }
            }
        }

        // Unparseable token
        tracing::warn!(token, "failed to parse address token");
        warning_count = warning_count.saturating_add(1);
    }

    (addresses, warning_count)
}

/// Decompose an IP address range into a minimal set of CIDRs.
///
/// Both `start` and `end` must belong to the same address family, and `start` must be
/// less than or equal to `end`.
///
/// # Errors
///
/// Returns an error if `start` and `end` are from different address families, or if
/// `start` is greater than `end`.
///
/// # Examples
///
/// ```ignore
/// use std::net::IpAddr;
/// let start: IpAddr = "10.0.0.0".parse().unwrap();
/// let end: IpAddr   = "10.0.0.7".parse().unwrap();
/// let cidrs = range_to_cidrs(start, end).unwrap();
/// assert_eq!(cidrs, ["10.0.0.0/29".parse::<ipnet::IpNet>().unwrap()]);
/// ```
pub fn range_to_cidrs(start: IpAddr, end: IpAddr) -> anyhow::Result<Vec<IpNet>> {
    // Validate address-family match
    let is_v6 = match (&start, &end) {
        (IpAddr::V4(_), IpAddr::V4(_)) => false,
        (IpAddr::V6(_), IpAddr::V6(_)) => true,
        _ => bail!("address family mismatch: start={start}, end={end}"),
    };

    let start_n = addr_to_u128(start);
    let end_n = addr_to_u128(end);

    if start_n > end_n {
        bail!("start address {start} is greater than end address {end}");
    }

    let max_len: u32 = u32::from(max_prefix_len(is_v6));
    let mut result: Vec<IpNet> = Vec::new();
    let mut current = start_n;

    while current <= end_n {
        let mut prefix_len = max_len;

        // Grow the prefix (decrease prefix_len) while the *candidate* prefix:
        //   1. Has `current` aligned to its block boundary, AND
        //   2. The block's broadcast address fits within end_n.
        // We check the candidate prefix_len-1 each iteration; if it passes we commit.
        while prefix_len > 0 {
            let candidate = prefix_len.saturating_sub(1);

            // Alignment mask for candidate prefix: the network bits must all be set.
            // For candidate /N, host_bits = max_len - N, mask covers the top N bits.
            let candidate_host_bits = max_len.saturating_sub(candidate);
            // Guard against overflow: 1u128 << 128 is undefined.
            let align_mask: u128 = if candidate_host_bits >= 128 {
                0u128 // /0 — any address is "aligned"
            } else {
                // REASON: candidate_host_bits < 128, shift is valid.
                #[allow(clippy::arithmetic_side_effects)]
                let host_mask = (1u128 << candidate_host_bits).wrapping_sub(1);
                !host_mask
            };

            // Check alignment
            if current & align_mask != current {
                break;
            }

            // Check that the broadcast address of candidate fits within end_n
            let broadcast: u128 = if candidate_host_bits >= 128 {
                u128::MAX
            } else {
                // REASON: candidate_host_bits < 128, shift is valid.
                #[allow(clippy::arithmetic_side_effects)]
                let host_mask = (1u128 << candidate_host_bits).wrapping_sub(1);
                current | host_mask
            };

            if broadcast > end_n {
                break;
            }

            // candidate fits — commit and try to grow further
            prefix_len = candidate;
        }

        let addr = u128_to_addr(current, is_v6);
        // REASON: prefix_len <= max_len which is at most 128, fitting u8.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
        let prefix_u8 = prefix_len as u8;
        result.push(
            IpNet::new(addr, prefix_u8)
                .context("constructed invalid CIDR prefix (unreachable: prefix_len is bounded)")?,
        );

        // Advance current past this block
        let host_bits = max_len.saturating_sub(prefix_len);
        let block_size: u128 = if host_bits >= 128 {
            // /0 covers the entire space; we are done.
            break;
        } else {
            // REASON: host_bits < 128, shift is valid.
            #[allow(clippy::arithmetic_side_effects)]
            {
                1u128 << host_bits
            }
        };

        current = match current.checked_add(block_size) {
            Some(n) => n,
            None => break, // wrapped past u128::MAX, range exhausted
        };
    }

    Ok(result)
}

// -------------------------------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------------------------------

/// Convert an [`IpAddr`] to a `u128` for arithmetic comparisons.
fn addr_to_u128(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

/// Convert a `u128` back to an [`IpAddr`].
///
/// For IPv4, the caller must guarantee that `n` fits in 32 bits.
fn u128_to_addr(n: u128, is_v6: bool) -> IpAddr {
    if is_v6 {
        IpAddr::V6(std::net::Ipv6Addr::from(n))
    } else {
        // REASON: The caller only passes values derived from IPv4 start/end addresses, so
        // truncating to the low 32 bits is always correct.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
        IpAddr::V4(std::net::Ipv4Addr::from(n as u32))
    }
}

/// Returns the maximum prefix length for the given address family.
const fn max_prefix_len(is_v6: bool) -> u8 {
    if is_v6 { 128 } else { 32 }
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ipnet::IpNet;

    use super::{parse_addresses, range_to_cidrs};

    // ---- parse_addresses ----

    #[test]
    fn single_cidr() {
        let (nets, warns) = parse_addresses("192.0.2.0/24");
        assert_eq!(warns, 0);
        assert_eq!(nets, vec!["192.0.2.0/24".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn bare_ipv4() {
        let (nets, warns) = parse_addresses("192.0.2.1");
        assert_eq!(warns, 0);
        assert_eq!(nets, vec!["192.0.2.1/32".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn bare_ipv6() {
        let (nets, warns) = parse_addresses("2001:db8::1");
        assert_eq!(warns, 0);
        assert_eq!(nets, vec!["2001:db8::1/128".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn comma_separated() {
        let (nets, warns) = parse_addresses("192.0.2.0/24, 10.0.0.0/8");
        assert_eq!(warns, 0);
        assert_eq!(nets.len(), 2);
    }

    #[test]
    fn newline_lf() {
        let (nets, warns) = parse_addresses("192.0.2.1\n192.0.2.2");
        assert_eq!(warns, 0);
        assert_eq!(nets.len(), 2);
    }

    #[test]
    fn newline_crlf() {
        let (nets, warns) = parse_addresses("192.0.2.1\r\n192.0.2.2");
        assert_eq!(warns, 0);
        assert_eq!(nets.len(), 2);
    }

    #[test]
    fn comma_newline_mix() {
        let (nets, warns) = parse_addresses("192.0.2.1,\n192.0.2.2\r\n192.0.2.3");
        assert_eq!(warns, 0);
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn vip_annotation() {
        // The annotation "(VIP: .1)" must be stripped before parsing.
        let (nets, warns) = parse_addresses("192.0.2.2, 192.0.2.3 (VIP: .1),\n2001:db8::1");
        assert_eq!(warns, 0);
        assert_eq!(nets.len(), 3);
        assert!(nets.contains(&"192.0.2.2/32".parse::<IpNet>().unwrap()));
        assert!(nets.contains(&"192.0.2.3/32".parse::<IpNet>().unwrap()));
        assert!(nets.contains(&"2001:db8::1/128".parse::<IpNet>().unwrap()));
    }

    #[test]
    fn empty_string() {
        let (nets, warns) = parse_addresses("");
        assert_eq!(warns, 0);
        assert!(nets.is_empty());
    }

    #[test]
    fn invalid_token_warning() {
        let (nets, warns) = parse_addresses("192.0.2.1, not_an_ip");
        assert_eq!(warns, 1);
        assert_eq!(nets, vec!["192.0.2.1/32".parse::<IpNet>().unwrap()]);
    }

    // ---- range_to_cidrs ----

    #[test]
    fn range_aligned_slash29() {
        let start = "10.0.0.0".parse().unwrap();
        let end = "10.0.0.7".parse().unwrap();
        let cidrs = range_to_cidrs(start, end).unwrap();
        assert_eq!(cidrs, vec!["10.0.0.0/29".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn range_unaligned() {
        // 10.0.0.1–10.0.0.3 → [10.0.0.1/32, 10.0.0.2/31]
        let start = "10.0.0.1".parse().unwrap();
        let end = "10.0.0.3".parse().unwrap();
        let cidrs = range_to_cidrs(start, end).unwrap();
        assert_eq!(
            cidrs,
            vec![
                "10.0.0.1/32".parse::<IpNet>().unwrap(),
                "10.0.0.2/31".parse::<IpNet>().unwrap(),
            ]
        );
    }

    #[test]
    fn range_single_ip() {
        let start = "10.0.0.5".parse().unwrap();
        let end = "10.0.0.5".parse().unwrap();
        let cidrs = range_to_cidrs(start, end).unwrap();
        assert_eq!(cidrs, vec!["10.0.0.5/32".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn range_ipv6() {
        // 2001:db8::0 – 2001:db8::f → [2001:db8::/124]
        let start = "2001:db8::".parse().unwrap();
        let end = "2001:db8::f".parse().unwrap();
        let cidrs = range_to_cidrs(start, end).unwrap();
        assert_eq!(cidrs, vec!["2001:db8::/124".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn range_mismatched_families() {
        let start = "10.0.0.1".parse().unwrap();
        let end = "2001:db8::1".parse().unwrap();
        let result = range_to_cidrs(start, end);
        assert!(result.is_err());
    }
}
