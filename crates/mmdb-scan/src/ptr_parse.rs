//! PTR hostname pattern matching for backbone device identification.
//!
//! All functions are pure (no I/O) and fully unit-testable.

use std::fmt::Write as _;

use anyhow::{Context as _, Result};
use mmdb_core::{config::PtrPattern, types::GatewayDevice};
use regex::Regex;

/// A compiled PTR pattern ready for matching.
#[derive(Debug)]
pub struct CompiledPattern {
    /// Optional domain suffix filter.
    pub domain: Option<String>,
    regex: Regex,
    /// Compiled exclude patterns applied before regex matching.
    pub excludes: Vec<Regex>,
}

impl CompiledPattern {
    /// Returns `true` if `ptr` matches any compiled exclude pattern.
    #[must_use]
    pub fn is_excluded(&self, ptr: &str) -> bool {
        self.excludes.iter().any(|re| re.is_match(ptr))
    }
}

/// Compile a list of [`PtrPattern`]s into [`CompiledPattern`]s.
///
/// When `PtrPattern.regex` contains a `{name}` placeholder, the regex is
/// expanded before compilation (see [`expand_placeholders`]).
/// Raw regex strings (no `{`) are passed to `Regex::new` unchanged.
///
/// # Errors
///
/// Returns an error if any regex fails to compile.
pub fn compile(patterns: &[PtrPattern]) -> Result<Vec<CompiledPattern>> {
    patterns
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let regex_str = if p.regex.contains('{') {
                expand_placeholders(&p.regex, p.domain.as_deref())
            } else {
                p.regex.clone()
            };
            let regex = Regex::new(&regex_str)
                .with_context(|| format!("invalid ptr_pattern[{i}] regex: {}", p.regex))?;
            let excludes = p
                .excludes
                .iter()
                .enumerate()
                .map(|(j, exc)| {
                    Regex::new(exc).with_context(|| {
                        format!("invalid ptr_pattern[{i}].excludes[{j}] regex: {exc}")
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(CompiledPattern {
                domain: p.domain.clone(),
                regex,
                excludes,
            })
        })
        .collect()
}

/// Expand `{name}` placeholders in a PTR pattern regex.
///
/// Each `{name}` is replaced with `(?P<name>[^.]+)`. Non-placeholder segments
/// (including `.` separators) are escaped with [`regex::escape`]. If `domain`
/// is set it is appended as `\.` + escaped domain + `$`. The result is
/// anchored with `^` at the start.
///
/// Strings with no `{` are returned unchanged (backward-compat fast path is
/// handled by the caller).
#[must_use]
pub fn expand_placeholders(regex_str: &str, domain: Option<&str>) -> String {
    let mut out = String::from("^");
    let mut rest = regex_str;
    while let Some(open) = rest.find('{') {
        // Escape the literal segment before the placeholder (may include '.').
        let literal = &rest[..open];
        if !literal.is_empty() {
            out.push_str(&regex::escape(literal));
        }
        #[allow(clippy::arithmetic_side_effects)]
        let after_open = &rest[open + 1..];
        rest = after_open;
        if let Some(close) = rest.find('}') {
            let name = &rest[..close];
            let _ = write!(out, "(?P<{name}>[^.]+)");
            #[allow(clippy::arithmetic_side_effects)]
            let after_close = &rest[close + 1..];
            rest = after_close;
        }
    }
    // Escape any remaining literal text after the last placeholder.
    if !rest.is_empty() {
        out.push_str(&regex::escape(rest));
    }
    if let Some(d) = domain {
        out.push_str(r"\.");
        out.push_str(&regex::escape(d));
    }
    out.push('$');
    out
}

/// Try to match `ptr` against the compiled patterns and extract device info.
///
/// Patterns are evaluated in order. The first entry whose domain filter passes
/// and whose regex matches wins. Returns `None` when no pattern matches or
/// `ptr` is empty.
#[must_use]
pub fn parse(ptr: &str, patterns: &[CompiledPattern]) -> Option<GatewayDevice> {
    if ptr.is_empty() {
        return None;
    }
    for p in patterns {
        if let Some(ref domain) = p.domain
            && !ptr.ends_with(domain.as_str())
        {
            continue;
        }
        if let Some(caps) = p.regex.captures(ptr) {
            let customer_asn = named(&caps, "customer_asn")
                .as_deref()
                .and_then(|s| s.parse::<u32>().ok());
            let facing_raw = named(&caps, "facing");
            let facing = normalise_facing(facing_raw.as_deref(), customer_asn.is_some());
            return Some(GatewayDevice {
                interface: named(&caps, "interface"),
                device: named(&caps, "device"),
                device_role: named(&caps, "device_role"),
                facility: named(&caps, "facility"),
                facing,
                customer_asn,
            });
        }
    }
    None
}

/// Extract a named capture group as `Option<String>`; returns `None` when the
/// group is absent or empty.
fn named(caps: &regex::Captures<'_>, name: &str) -> Option<String> {
    caps.name(name)
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Normalise the raw `facing` capture group to a canonical string value.
fn normalise_facing(raw: Option<&str>, has_asn: bool) -> Option<String> {
    match (raw, has_asn) {
        (Some(r), _) if r.starts_with("user") && r.contains("virtual") => {
            Some(String::from("user_virtual"))
        }
        (Some(r), _) if r.starts_with("user") => Some(String::from("user")),
        (Some(r), _) if r.starts_with("virtual") => Some(String::from("virtual")),
        (None, true) => Some(String::from("bgp_peer")),
        (None, false) => Some(String::from("network")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmdb_core::config::PtrPattern;

    fn pattern(domain: Option<&str>, regex: &str) -> CompiledPattern {
        let p = PtrPattern {
            domain: domain.map(str::to_owned),
            regex: regex.to_owned(),
            excludes: vec![],
        };
        compile(&[p]).unwrap().remove(0)
    }

    fn bbtower_pattern() -> CompiledPattern {
        pattern(
            Some("example.ad.jp"),
            r"(?x)
              ^(?:(?P<facing>user(?:\.virtual)?|virtual)\.)?
              (?:as(?P<customer_asn>\d+)\.)?
              (?P<interface>(?:ge|xe|et)-[\d-]+)
              (?:\.[a-z]+\d+)?\.
              (?P<device>(?P<device_role>[a-z]+)\d+)\.
              (?P<facility>[a-z0-9]+)\.
              example\.ad\.jp$",
        )
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_user_virtual_xe() {
        let patterns = vec![bbtower_pattern()];
        let dev = parse(
            "user.virtual.xe-0-0-1.rtr0101.dc01.example.ad.jp",
            &patterns,
        )
        .unwrap();
        assert_eq!(dev.interface.as_deref(), Some("xe-0-0-1"));
        assert_eq!(dev.device.as_deref(), Some("rtr0101"));
        assert_eq!(dev.device_role.as_deref(), Some("rtr"));
        assert_eq!(dev.facility.as_deref(), Some("dc01"));
        assert_eq!(dev.facing.as_deref(), Some("user_virtual"));
        assert!(dev.customer_asn.is_none());
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_user_ge() {
        let patterns = vec![bbtower_pattern()];
        let dev = parse("user.ge-0-0-0.rtr0201.dc01.example.ad.jp", &patterns).unwrap();
        assert_eq!(dev.facing.as_deref(), Some("user"));
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_network_facing() {
        let patterns = vec![bbtower_pattern()];
        let dev = parse("ge-0-0-0.rtr0201.dc01.example.ad.jp", &patterns).unwrap();
        assert_eq!(dev.facing.as_deref(), Some("network"));
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_bgp_peer() {
        let patterns = vec![bbtower_pattern()];
        let dev = parse("as64496.xe-0-1-0.rtr0301.dc01.example.ad.jp", &patterns).unwrap();
        assert_eq!(dev.facing.as_deref(), Some("bgp_peer"));
        assert_eq!(dev.customer_asn, Some(64496));
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_domain_filter_miss() {
        let patterns = vec![bbtower_pattern()];
        assert!(parse("ge-0-0-0.rtr0201.dc01.docs.example.com", &patterns).is_none());
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_domain_filter_hit() {
        let patterns = vec![bbtower_pattern()];
        assert!(parse("ge-0-0-0.rtr0201.dc01.example.ad.jp", &patterns).is_some());
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_no_patterns() {
        assert!(parse("ge-0-0-0.rtr0201.dc01.example.ad.jp", &[]).is_none());
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_first_match_wins() {
        let first = pattern(
            Some("example.ad.jp"),
            r"^(?P<device>first\d+)\.example\.ad\.jp$",
        );
        let second = pattern(
            Some("example.ad.jp"),
            r"^(?P<device>second\d+)\.example\.ad\.jp$",
        );
        let patterns = vec![first, second];
        let dev = parse("first01.example.ad.jp", &patterns).unwrap();
        assert_eq!(dev.device.as_deref(), Some("first01"));
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn parse_empty_ptr() {
        let patterns = vec![bbtower_pattern()];
        assert!(parse("", &patterns).is_none());
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn compile_invalid_regex_returns_error() {
        let p = PtrPattern {
            domain: None,
            regex: String::from("[invalid"),
            excludes: vec![],
        };
        assert!(compile(&[p]).is_err());
    }

    // --- {placeholder} expansion tests ---

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn expand_single_placeholder() {
        let result = expand_placeholders("{device}", None);
        assert_eq!(result, "^(?P<device>[^.]+)$");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn expand_multiple_placeholders() {
        let result = expand_placeholders("{interface}.{device}.{facility}", None);
        assert_eq!(
            result,
            "^(?P<interface>[^.]+)\\.(?P<device>[^.]+)\\.(?P<facility>[^.]+)$"
        );
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn expand_with_domain() {
        let result = expand_placeholders("{interface}.{device}.{facility}", Some("example.net"));
        assert_eq!(
            result,
            r"^(?P<interface>[^.]+)\.(?P<device>[^.]+)\.(?P<facility>[^.]+)\.example\.net$"
        );
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn expand_raw_regex_unchanged_via_compile() {
        // Raw regex (no '{') must compile and match unchanged.
        let p = PtrPattern {
            domain: None,
            regex: r"^(?P<device>rtr\d+)$".to_owned(),
            excludes: vec![],
        };
        let compiled = compile(&[p]).unwrap();
        let dev = parse("rtr0101", &compiled);
        assert_eq!(dev.unwrap().device.as_deref(), Some("rtr0101"));
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn placeholder_pattern_matches() {
        // {interface}.{device}.{facility} with domain example.net
        let p = PtrPattern {
            domain: Some("example.net".to_owned()),
            regex: "{interface}.{device}.{facility}".to_owned(),
            excludes: vec![],
        };
        let compiled = compile(&[p]).unwrap();
        let dev = parse("xe-0-0-1.rtr0101.dc01.example.net", &compiled);
        let dev = dev.unwrap();
        assert_eq!(dev.interface.as_deref(), Some("xe-0-0-1"));
        assert_eq!(dev.device.as_deref(), Some("rtr0101"));
        assert_eq!(dev.facility.as_deref(), Some("dc01"));
    }
}
