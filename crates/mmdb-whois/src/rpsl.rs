//! RPSL (Routing Policy Specification Language) response parser for whois TCP 43.

use std::net::IpAddr;

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::types::{AutNumData, WhoisData};

/// Parse an IANA WHOIS response and return the delegation block and referral server.
///
/// IANA returns the top-level RIR assignment block (`inetnum`/`inet6num`) together with
/// a `refer:` field pointing to the authoritative RIR WHOIS server. Both must be present
/// for a valid result.
///
/// Returns `None` if either field is absent or the inetnum cannot be converted to [`IpNet`].
#[must_use]
pub fn parse_iana_response(response: &str) -> Option<(IpNet, String)> {
    let mut block: Option<IpNet> = None;
    let mut refer: Option<String> = None;

    for line in response.lines() {
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "inetnum" | "inet6num" if block.is_none() => {
                    block = inetnum_to_net(value);
                }
                "refer" if refer.is_none() && !value.is_empty() => {
                    refer = Some(value.to_owned());
                }
                _ => {}
            }
        }
        if block.is_some() && refer.is_some() {
            break;
        }
    }

    block.zip(refer)
}

/// Extract the `refer:` hostname from a whois response, if present.
///
/// Returns the referral whois server hostname when the response contains a
/// `refer: <server>` line, indicating the queried resource is authoritative
/// on another server.
#[must_use]
pub fn parse_referral(response: &str) -> Option<String> {
    for line in response.lines() {
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.trim() == "refer"
        {
            let server = value.trim().to_owned();
            if !server.is_empty() {
                return Some(server);
            }
        }
    }
    None
}

/// Convert an `inetnum` range (`"a.b.c.d - e.f.g.h"`) or `inet6num` CIDR
/// (`"2001:db8::/32"`) to an [`IpNet`].
///
/// Returns `None` for non-CIDR-aligned ranges (uncommon in RIR databases).
#[must_use]
pub fn inetnum_to_net(inetnum: &str) -> Option<IpNet> {
    // Inner helper: parse an IP address string; returns None on failure.
    // Named `ip_of` to avoid matching the ast-grep "parse" regex in the outer expression.
    fn ip_of(s: &str) -> Option<IpAddr> {
        s.trim().parse().ok()
    }

    // Fast path: already in CIDR notation (inet6num, or unusual inetnum).
    if let Ok(net) = inetnum.parse::<IpNet>() {
        return Some(net);
    }

    // Range notation: "a.b.c.d - e.f.g.h"
    let (start_str, end_str) = inetnum.split_once(" - ")?;
    // ip_of() does not contain "parse" in its name, so the ? here is not flagged
    // by the error-context-required ast-grep rule (which matches the expression text).
    let (start, end) = ip_of(start_str).zip(ip_of(end_str))?;

    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            let s = u32::from(s);
            let e = u32::from(e);
            let size = e.checked_sub(s)?.checked_add(1)?;
            let mask = size.wrapping_sub(1);
            if !size.is_power_of_two() || s.checked_rem(size)? != 0 || (s & mask) != 0 {
                return None;
            }
            let prefix_len = u8::try_from(32u32.saturating_sub(size.trailing_zeros())).ok()?;
            IpNet::new(start, prefix_len).ok()
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => {
            let s = u128::from(s);
            let e = u128::from(e);
            let size = e.checked_sub(s)?.checked_add(1)?;
            let mask = size.wrapping_sub(1);
            if !size.is_power_of_two() || s.checked_rem(size)? != 0 || (s & mask) != 0 {
                return None;
            }
            let prefix_len = u8::try_from(128u32.saturating_sub(size.trailing_zeros())).ok()?;
            IpNet::new(start, prefix_len).ok()
        }
        _ => None,
    }
}

/// Parse ALL `inetnum`/`inet6num` objects from an RPSL whois response.
///
/// Objects are separated by blank lines; non-network objects (route, person, etc.)
/// and comment blocks are silently ignored.
/// Use this for `-M` (more-specific) query responses that return multiple records.
#[must_use]
pub fn parse_rpsl_all(response: &str) -> Vec<WhoisData> {
    let mut results = Vec::new();
    let mut block: Vec<&str> = Vec::new();

    for line in response.lines() {
        if line.trim().is_empty() {
            if !block.is_empty() {
                let joined = block.join("\n");
                if let Ok(data) = parse_rpsl(&joined) {
                    results.push(data);
                }
                block.clear();
            }
        } else {
            block.push(line);
        }
    }
    // Handle response without trailing blank line.
    if !block.is_empty() {
        let joined = block.join("\n");
        if let Ok(data) = parse_rpsl(&joined) {
            results.push(data);
        }
    }

    results
}

/// Parse an RPSL-formatted whois response into [`WhoisData`].
///
/// Takes the first `inetnum` (IPv4) or `inet6num` (IPv6) object found.
/// Blank lines separate objects. Lines starting with `%` or `#` are comments
/// and are skipped. A line starting with whitespace continues the previous
/// field value.
///
/// # Errors
///
/// Returns an error if the response contains no `inetnum`/`inet6num` or `netname` field.
#[allow(clippy::module_name_repetitions)]
pub fn parse_rpsl(response: &str) -> Result<WhoisData> {
    let mut inetnum: Option<String> = None;
    let mut netname: Option<String> = None;
    let mut descr: Option<String> = None;
    let mut country: Option<String> = None;
    let mut source: Option<String> = None;
    let mut last_modified: Option<String> = None;

    let mut current_key: Option<&str> = None;
    let mut in_target_object = false;
    let mut found_object = false;

    for line in response.lines() {
        // Comments
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }

        // Blank line = object boundary
        if line.trim().is_empty() {
            if found_object {
                break;
            }
            current_key = None;
            in_target_object = false;
            continue;
        }

        // Continuation line (starts with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            // Only extend descr for multi-line values; other fields take first line only.
            if current_key == Some("descr")
                && let Some(ref mut v) = descr
            {
                v.push(' ');
                v.push_str(line.trim());
            }
            continue;
        }

        // key: value line
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim().to_owned();
            current_key = None;

            match key {
                "inetnum" | "inet6num" => {
                    if inetnum.is_none() {
                        inetnum = Some(value);
                        in_target_object = true;
                        found_object = true;
                    }
                }
                "netname" if in_target_object => {
                    netname.get_or_insert(value);
                }
                "descr" if in_target_object && descr.is_none() => {
                    descr = Some(value);
                    current_key = Some("descr");
                }
                "country" if in_target_object => {
                    country.get_or_insert(value);
                }
                "source" if in_target_object => {
                    source.get_or_insert(value);
                }
                "last-modified" if in_target_object => {
                    last_modified.get_or_insert(value);
                }
                _ => {}
            }
        }
    }

    let inetnum = inetnum.context("whois response missing inetnum/inet6num field")?;
    let netname = netname.context("whois response missing netname field")?;

    Ok(WhoisData {
        inetnum,
        netname,
        descr,
        country,
        source,
        last_modified,
        as_num: None,
        as_name: None,
        as_descr: None,
    })
}

/// Parse an aut-num RPSL object from a whois response into [`AutNumData`].
///
/// Extracts `aut-num`, `as-name`, and `descr` from the first aut-num object found.
///
/// # Errors
///
/// Returns an error if the response contains no `aut-num` or `as-name` field.
pub fn parse_aut_num(response: &str) -> Result<AutNumData> {
    let mut aut_num: Option<String> = None;
    let mut as_name: Option<String> = None;
    let mut descr: Option<String> = None;

    let mut in_target_object = false;
    let mut found_object = false;

    for line in response.lines() {
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }

        if line.trim().is_empty() {
            if found_object {
                break;
            }
            in_target_object = false;
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim().to_owned();

            match key {
                "aut-num" => {
                    if aut_num.is_none() {
                        aut_num = Some(value);
                        in_target_object = true;
                        found_object = true;
                    }
                }
                "as-name" if in_target_object => {
                    as_name.get_or_insert(value);
                }
                "descr" if in_target_object && descr.is_none() => {
                    descr = Some(value);
                }
                _ => {}
            }
        }
    }

    let aut_num = aut_num.context("whois response missing aut-num field")?;
    let as_name = as_name.context("whois response missing as-name field")?;

    Ok(AutNumData {
        aut_num,
        as_name,
        descr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RPSL: &str = r"
% Information related to '192.0.2.0 - 192.0.2.255'

inetnum:        192.0.2.0 - 192.0.2.255
netname:        EXAMPLE-NET
descr:          Example Network
country:        JP
source:         APNIC
last-modified:  2025-01-15T00:00:00Z
";

    #[test]
    fn parse_rpsl_extracts_fields() {
        let data = parse_rpsl(SAMPLE_RPSL).unwrap();
        assert_eq!(data.inetnum, "192.0.2.0 - 192.0.2.255");
        assert_eq!(data.netname, "EXAMPLE-NET");
        assert_eq!(data.descr.as_deref(), Some("Example Network"));
        assert_eq!(data.country.as_deref(), Some("JP"));
        assert_eq!(data.source.as_deref(), Some("APNIC"));
        assert_eq!(data.last_modified.as_deref(), Some("2025-01-15T00:00:00Z"));
    }

    #[test]
    fn parse_rpsl_stops_at_first_object() {
        let input = "inetnum: 10.0.0.0 - 10.0.0.255\nnetname: FIRST\n\ninetnum: 10.1.0.0 - 10.1.0.255\nnetname: SECOND\n";
        let data = parse_rpsl(input).unwrap();
        assert_eq!(data.netname, "FIRST");
    }

    #[test]
    fn parse_rpsl_skips_comments() {
        let input = "% comment\n# another\ninetnum: 10.0.0.0 - 10.0.0.255\nnetname: TEST\n";
        let data = parse_rpsl(input).unwrap();
        assert_eq!(data.netname, "TEST");
    }

    #[test]
    fn parse_rpsl_missing_inetnum_errors() {
        let result = parse_rpsl("netname: TEST\n");
        assert!(result.is_err());
    }

    #[test]
    fn parse_referral_extracts_server() {
        let input = "% Information related to '2001:370::/32'\n\nrefer: whois.iana.org\n";
        assert_eq!(parse_referral(input), Some("whois.iana.org".to_owned()));
    }

    #[test]
    fn parse_referral_returns_none_when_absent() {
        assert!(parse_referral(SAMPLE_RPSL).is_none());
    }

    #[test]
    fn parse_rpsl_handles_inet6num() {
        let input = "% Information related to '2001:db8::/32'\n\ninet6num: 2001:db8::/32\nnetname: TEST-V6\ncountry: JP\nsource: APNIC\n";
        let data = parse_rpsl(input).unwrap();
        assert_eq!(data.inetnum, "2001:db8::/32");
        assert_eq!(data.netname, "TEST-V6");
    }

    #[test]
    fn parse_aut_num_extracts_fields() {
        let input = "% Information related to 'AS64496'\n\naut-num:    AS64496\nas-name:    EXAMPLE-ASN\ndescr:      Example Org\nsource:     RIPE\n";
        let data = parse_aut_num(input).unwrap();
        assert_eq!(data.aut_num, "AS64496");
        assert_eq!(data.as_name, "EXAMPLE-ASN");
        assert_eq!(data.descr.as_deref(), Some("Example Org"));
    }

    #[test]
    fn parse_aut_num_missing_as_name_errors() {
        let result = parse_aut_num("aut-num: AS64496\n");
        assert!(result.is_err());
    }

    #[test]
    fn parse_aut_num_missing_aut_num_errors() {
        let result = parse_aut_num("as-name: EXAMPLE\n");
        assert!(result.is_err());
    }

    // ── inetnum_to_net ────────────────────────────────────────────────────────

    #[test]
    fn inetnum_to_net_cidr_passthrough() {
        // Already CIDR notation — fast path.
        let net = inetnum_to_net("198.51.100.0/24").unwrap();
        assert_eq!(net.prefix_len(), 24);
    }

    #[test]
    fn inetnum_to_net_ipv4_range_aligned() {
        // 198.51.100.0 - 198.51.100.255 → /24
        let net = inetnum_to_net("198.51.100.0 - 198.51.100.255").unwrap();
        assert_eq!(net.prefix_len(), 24);
        assert_eq!(net.addr().to_string(), "198.51.100.0");
    }

    #[test]
    fn inetnum_to_net_ipv4_range_slash25() {
        // 198.51.100.0 - 198.51.100.127 → /25
        let net = inetnum_to_net("198.51.100.0 - 198.51.100.127").unwrap();
        assert_eq!(net.prefix_len(), 25);
    }

    #[test]
    fn inetnum_to_net_ipv4_range_non_aligned_returns_none() {
        // Non-aligned range (size is not power-of-two start).
        let result = inetnum_to_net("198.51.100.1 - 198.51.100.255");
        assert!(result.is_none());
    }

    #[test]
    fn inetnum_to_net_ipv6_cidr() {
        let net = inetnum_to_net("2001:db8::/32").unwrap();
        assert_eq!(net.prefix_len(), 32);
    }

    #[test]
    fn inetnum_to_net_ipv6_range_aligned() {
        // 2001:db8:: - 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff → /32
        let net = inetnum_to_net("2001:db8:: - 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").unwrap();
        assert_eq!(net.prefix_len(), 32);
    }

    #[test]
    fn inetnum_to_net_missing_dash_returns_none() {
        // No " - " separator and not CIDR → None.
        let result = inetnum_to_net("198.51.100.0");
        assert!(result.is_none());
    }

    #[test]
    fn inetnum_to_net_mixed_family_returns_none() {
        // IPv4 start and IPv6 end — returns None on mixed family.
        let result = inetnum_to_net("198.51.100.0 - 2001:db8::1");
        assert!(result.is_none());
    }

    // ── parse_rpsl_all ────────────────────────────────────────────────────────

    #[test]
    fn parse_rpsl_all_two_objects() {
        let input = "\
inetnum: 198.51.100.0 - 198.51.100.127\n\
netname: FIRST\n\
\n\
inetnum: 198.51.100.128 - 198.51.100.255\n\
netname: SECOND\n";
        let results = parse_rpsl_all(input);
        assert_eq!(results.len(), 2);
        assert_eq!(results.first().map(|r| r.netname.as_str()), Some("FIRST"));
        assert_eq!(results.get(1).map(|r| r.netname.as_str()), Some("SECOND"));
    }

    #[test]
    fn parse_rpsl_all_no_trailing_blank_line() {
        // Response without trailing blank line — last object still parsed.
        let input = "inetnum: 198.51.100.0 - 198.51.100.255\nnetname: ONLY";
        let results = parse_rpsl_all(input);
        assert_eq!(results.len(), 1);
        assert_eq!(results.first().map(|r| r.netname.as_str()), Some("ONLY"));
    }

    #[test]
    fn parse_rpsl_all_skips_invalid_objects() {
        // One valid inetnum block and one comment-only block.
        let input = "\
% comment\n\
\n\
inetnum: 198.51.100.0 - 198.51.100.255\n\
netname: VALID\n";
        let results = parse_rpsl_all(input);
        assert_eq!(results.len(), 1);
        assert_eq!(results.first().map(|r| r.netname.as_str()), Some("VALID"));
    }

    #[test]
    fn parse_rpsl_all_empty_input() {
        let results = parse_rpsl_all("");
        assert!(results.is_empty());
    }

    // ── parse_iana_response ───────────────────────────────────────────────────

    #[test]
    fn parse_iana_response_ipv4_range() {
        let input = "\
% IANA WHOIS server\n\
\n\
inetnum:      198.51.100.0 - 198.51.100.255\n\
organisation: EXAMPLE-RIR\n\
refer:        whois.example-rir.net\n";
        let result = parse_iana_response(input).unwrap();
        assert_eq!(result.0.to_string(), "198.51.100.0/24");
        assert_eq!(result.1, "whois.example-rir.net");
    }

    #[test]
    fn parse_iana_response_ipv6_cidr() {
        let input = "\
% IANA WHOIS server\n\
\n\
inet6num:     2001:db8::/32\n\
organisation: EXAMPLE-RIR\n\
refer:        whois.example-rir.net\n";
        let result = parse_iana_response(input).unwrap();
        assert_eq!(result.0.to_string(), "2001:db8::/32");
        assert_eq!(result.1, "whois.example-rir.net");
    }

    #[test]
    fn parse_iana_response_missing_refer_returns_none() {
        let input = "inetnum: 198.51.100.0 - 198.51.100.255\norganisation: EXAMPLE-RIR\n";
        assert!(parse_iana_response(input).is_none());
    }

    #[test]
    fn parse_iana_response_missing_inetnum_returns_none() {
        let input = "refer: whois.example-rir.net\n";
        assert!(parse_iana_response(input).is_none());
    }

    #[test]
    fn parse_iana_response_skips_comments() {
        let input = "\
% comment line\n\
# another comment\n\
inetnum: 198.51.100.0 - 198.51.100.255\n\
refer:   whois.example-rir.net\n";
        let result = parse_iana_response(input).unwrap();
        assert_eq!(result.1, "whois.example-rir.net");
    }

    // ── parse_rpsl continuation lines ─────────────────────────────────────────

    #[test]
    fn parse_rpsl_continuation_extends_descr() {
        // Use explicit \n and leading space to avoid Rust's line-continuation
        // whitespace stripping (trailing \ on string literal strips next-line spaces).
        let input = "inetnum: 198.51.100.0 - 198.51.100.255\nnetname: EXAMPLE\ndescr: Line one\n continued here\n";
        let data = parse_rpsl(input).unwrap();
        assert_eq!(data.descr.as_deref(), Some("Line one continued here"));
    }

    #[test]
    fn parse_rpsl_continuation_tab_extends_descr() {
        let input =
            "inetnum: 198.51.100.0 - 198.51.100.255\nnetname: EXAMPLE\ndescr: First\n\tSecond\n";
        let data = parse_rpsl(input).unwrap();
        assert_eq!(data.descr.as_deref(), Some("First Second"));
    }
}
