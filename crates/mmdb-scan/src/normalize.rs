//! Compiled normalisation pipelines built from `[normalize.*]` config.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use mmdb_core::config::{NormalizeCase, NormalizeConfig};
use regex::Regex;

// -------------------------------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------------------------------

/// A single compiled substitution rule.
#[derive(Debug)]
pub struct CompiledNormalizeRule {
    /// Compiled regex pattern used for matching and substitution.
    pub regex: Regex,
    /// Replacement string applied when the regex matches.
    pub replacement: String,
}

/// A compiled normalisation pipeline for one named field.
#[derive(Debug)]
pub struct CompiledNormalizeConfig {
    /// Ordered substitution rules applied sequentially.
    pub rules: Vec<CompiledNormalizeRule>,
    /// Case transformation applied after all rules.
    pub case: NormalizeCase,
    /// Compiled exclude patterns matched against the normalised field value.
    pub excludes: Vec<Regex>,
}

impl CompiledNormalizeConfig {
    /// Returns `true` if the normalised `value` matches any compiled exclude pattern.
    #[must_use]
    pub fn is_excluded(&self, value: &str) -> bool {
        self.excludes.iter().any(|re| re.is_match(value))
    }
}

// -------------------------------------------------------------------------------------------------
// Public functions
// -------------------------------------------------------------------------------------------------

/// Compile all entries in the `[normalize.*]` config map.
///
/// # Errors
///
/// Returns an error if any `pattern` field fails to compile as a regex.
pub fn compile_all<S: ::std::hash::BuildHasher>(
    map: &HashMap<String, NormalizeConfig, S>,
) -> Result<HashMap<String, CompiledNormalizeConfig>> {
    let mut out = HashMap::with_capacity(map.len());
    for (name, cfg) in map {
        let compiled = compile_one(cfg)
            .with_context(|| format!("failed to compile normalize rules for '{name}'"))?;
        out.insert(name.clone(), compiled);
    }
    Ok(out)
}

/// Apply a compiled normalisation pipeline to `input`.
///
/// Rules are applied sequentially; then case normalisation is applied.
#[must_use]
pub fn apply(config: &CompiledNormalizeConfig, input: &str) -> String {
    let mut s = input.to_owned();
    for rule in &config.rules {
        let replaced = rule.regex.replace_all(&s, rule.replacement.as_str());
        s = replaced.into_owned();
    }
    match config.case {
        NormalizeCase::Lower => s.to_lowercase(),
        NormalizeCase::Upper => s.to_uppercase(),
        NormalizeCase::None => s,
    }
}

// -------------------------------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------------------------------

fn compile_one(cfg: &NormalizeConfig) -> Result<CompiledNormalizeConfig> {
    let mut rules = Vec::with_capacity(cfg.rules.len());
    for rule in &cfg.rules {
        let regex = Regex::new(&rule.pattern)
            .with_context(|| format!("invalid regex pattern '{}'", rule.pattern))?;
        rules.push(CompiledNormalizeRule {
            regex,
            replacement: rule.replacement.clone(),
        });
    }
    let excludes = cfg
        .excludes
        .iter()
        .enumerate()
        .map(|(k, exc)| {
            Regex::new(exc).with_context(|| format!("invalid normalize excludes[{k}] regex: {exc}"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CompiledNormalizeConfig {
        rules,
        case: cfg.case,
        excludes,
    })
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use mmdb_core::config::{NormalizeCase, NormalizeConfig, NormalizeRule};

    use super::{apply, compile_all};

    fn make_config(rules: &[(&str, &str)], case: NormalizeCase) -> NormalizeConfig {
        NormalizeConfig {
            rules: rules
                .iter()
                .map(|(p, r)| NormalizeRule {
                    pattern: (*p).to_owned(),
                    replacement: (*r).to_owned(),
                })
                .collect(),
            case,
            excludes: vec![],
        }
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn apply_slash_to_dash() {
        let map = std::collections::HashMap::from([(
            "interface".to_owned(),
            make_config(&[("/", "-")], NormalizeCase::Lower),
        )]);
        let compiled = compile_all(&map).unwrap();
        let result = apply(compiled.get("interface").unwrap(), "xe-0/0/1");
        assert_eq!(result, "xe-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn apply_rules_sequential() {
        // GigabitEthernet0/0/1 → gi-0-0-1
        let map = std::collections::HashMap::from([(
            "interface".to_owned(),
            make_config(
                &[
                    (r"GigabitEthernet(\d+)/(\d+)/(\d+)", "gi-$1-$2-$3"),
                    ("/", "-"),
                ],
                NormalizeCase::Lower,
            ),
        )]);
        let compiled = compile_all(&map).unwrap();
        let result = apply(compiled.get("interface").unwrap(), "GigabitEthernet0/0/1");
        assert_eq!(result, "gi-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn apply_case_upper() {
        let map = std::collections::HashMap::from([(
            "device".to_owned(),
            make_config(&[], NormalizeCase::Upper),
        )]);
        let compiled = compile_all(&map).unwrap();
        let result = apply(compiled.get("device").unwrap(), "rtr0101");
        assert_eq!(result, "RTR0101");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn apply_case_none() {
        let map = std::collections::HashMap::from([(
            "device".to_owned(),
            make_config(&[], NormalizeCase::None),
        )]);
        let compiled = compile_all(&map).unwrap();
        let result = apply(compiled.get("device").unwrap(), "RTR0101");
        assert_eq!(result, "RTR0101");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn apply_case_lower() {
        let map = std::collections::HashMap::from([(
            "facility".to_owned(),
            make_config(&[], NormalizeCase::Lower),
        )]);
        let compiled = compile_all(&map).unwrap();
        let result = apply(compiled.get("facility").unwrap(), "DC01");
        assert_eq!(result, "dc01");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn compile_all_invalid_regex_returns_error() {
        let map = std::collections::HashMap::from([(
            "bad".to_owned(),
            make_config(&[("[invalid", "x")], NormalizeCase::None),
        )]);
        assert!(compile_all(&map).is_err());
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn apply_no_rules_passthrough() {
        let map = std::collections::HashMap::from([(
            "device".to_owned(),
            make_config(&[], NormalizeCase::Lower),
        )]);
        let compiled = compile_all(&map).unwrap();
        let result = apply(compiled.get("device").unwrap(), "rtr0101.dc01");
        assert_eq!(result, "rtr0101.dc01");
    }

    // ── interface normalize: compile + detection tests ────────────────────────

    /// Returns the [normalize.interface] rule set matching config.toml.
    ///
    /// Rule ordering is critical: patterns that are substrings of longer names
    /// must come AFTER the longer names (e.g. `GigabitEthernet` after all
    /// `*GigabitEthernet` variants).
    fn interface_config() -> NormalizeConfig {
        make_config(
            &[
                // GigabitEthernet family — longest first
                (r"(?i)HundredGigabitEthernet(\d+(?:[/\.]\d+)*)", "hu-$1"),
                (r"(?i)FortyGigabitEthernet(\d+(?:[/\.]\d+)*)", "fo-$1"),
                (r"(?i)TenGigabitEthernet(\d+(?:[/\.]\d+)*)", "te-$1"),
                (r"(?i)FiveGigabitEthernet(\d+(?:[/\.]\d+)*)", "fi5g-$1"),
                (r"(?i)TwoGigabitEthernet(\d+(?:[/\.]\d+)*)", "tw-$1"),
                (r"(?i)XGigabitEthernet(\d+(?:[/\.]\d+)*)", "xe-$1"),
                (r"(?i)GigaEthernet(\d+(?:[/\.]\d+)*)", "gi-$1"),
                (r"(?i)GigabitEthernet(\d+(?:[/\.]\d+)*)", "gi-$1"),
                // GigE family — longest first
                (r"(?i)FourHundredGigE(\d+(?:[/\.]\d+)*)", "fh-$1"),
                (r"(?i)TwoHundredGigE(\d+(?:[/\.]\d+)*)", "th-$1"),
                (r"(?i)TwentyFiveGigE(\d+(?:[/\.]\d+)*)", "twe-$1"),
                (r"(?i)HundredGigE(\d+(?:[/\.]\d+)*)", "hu-$1"),
                (r"(?i)FiftyGigE(\d+(?:[/\.]\d+)*)", "fi50g-$1"),
                (r"(?i)FortyGigE(\d+(?:[/\.]\d+)*)", "fo-$1"),
                (r"(?i)TenGigE(\d+(?:[/\.]\d+)*)", "te-$1"),
                (r"(?i)GigE(\d+(?:[/\.]\d+)*)", "gi-$1"),
                // FastEthernet
                (r"(?i)FastEthernet(\d+(?:[/\.]\d+)*)", "fa-$1"),
                // Huawei VRP — longer before shorter
                (r"(?i)MultiGE(\d+(?:[/\.]\d+)*)", "mge-$1"),
                (r"(?i)800GE(\d+(?:[/\.]\d+)*)", "800ge-$1"),
                (r"(?i)400GE(\d+(?:[/\.]\d+)*)", "400ge-$1"),
                (r"(?i)200GE(\d+(?:[/\.]\d+)*)", "200ge-$1"),
                (r"(?i)100GE(\d+(?:[/\.]\d+)*)", "hu-$1"),
                (r"(?i)40GE(\d+(?:[/\.]\d+)*)", "40ge-$1"),
                (r"(?i)25GE(\d+(?:[/\.]\d+)*)", "25ge-$1"),
                (r"(?i)10GE(\d+(?:[/\.]\d+)*)", "xe-$1"),
                (r"(?i)5GE(\d+(?:[/\.]\d+)*)", "fi5g-$1"),
                (r"(?i)GE(\d+(?:[/\.]\d+)*)", "ge-$1"),
                // Cisco abbreviated forms — word boundary prevents mid-word match
                (r"(?i)\bHu(\d+(?:[/\.]\d+)*)", "hu-$1"),
                (r"(?i)\bFo(\d+(?:[/\.]\d+)*)", "fo-$1"),
                (r"(?i)\bTwe(\d+(?:[/\.]\d+)*)", "twe-$1"),
                (r"(?i)\bTe(\d+(?:[/\.]\d+)*)", "te-$1"),
                (r"(?i)\bTw(\d+(?:[/\.]\d+)*)", "tw-$1"),
                (r"(?i)\bGi(\d+(?:[/\.]\d+)*)", "gi-$1"),
                (r"(?i)\bFa(\d+(?:[/\.]\d+)*)", "fa-$1"),
                // Separator fallback
                ("/", "-"),
                (r"\.", "-"),
            ],
            NormalizeCase::Lower,
        )
    }

    fn norm_if(input: &str) -> String {
        let map = std::collections::HashMap::from([("interface".to_owned(), interface_config())]);
        let compiled = compile_all(&map).unwrap();
        apply(compiled.get("interface").unwrap(), input)
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn interface_rules_compile() {
        let map = std::collections::HashMap::from([("interface".to_owned(), interface_config())]);
        assert!(compile_all(&map).is_ok());
    }

    // ── Juniper Junos (already DNS-safe; only separator needed) ──────────────

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn juniper_ge_slash() {
        assert_eq!(norm_if("ge-0/0/0"), "ge-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn juniper_xe_slash() {
        assert_eq!(norm_if("xe-0/0/1"), "xe-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn juniper_et_slash() {
        assert_eq!(norm_if("et-0/0/2"), "et-0-0-2");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn juniper_mge_slash() {
        assert_eq!(norm_if("mge-0/0/3"), "mge-0-0-3");
    }

    // ── Cisco IOS/IOS-XE/IOS-XR full names ──────────────────────────────────

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_fast_ethernet() {
        assert_eq!(norm_if("FastEthernet0/1"), "fa-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_gigabit_ethernet() {
        assert_eq!(norm_if("GigabitEthernet0/0/1"), "gi-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_two_gig() {
        assert_eq!(norm_if("TwoGigabitEthernet0/0/1"), "tw-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_five_gig_full() {
        assert_eq!(norm_if("FiveGigabitEthernet0/0/1"), "fi5g-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_ten_gig_full() {
        assert_eq!(norm_if("TenGigabitEthernet0/0/1"), "te-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_ten_gige() {
        assert_eq!(norm_if("TenGigE0/0/1"), "te-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_twenty_five_gig() {
        assert_eq!(norm_if("TwentyFiveGigE0/0/1"), "twe-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_forty_gig_full() {
        assert_eq!(norm_if("FortyGigabitEthernet0/0/1"), "fo-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_forty_gige() {
        assert_eq!(norm_if("FortyGigE0/0/1"), "fo-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_fifty_gig() {
        assert_eq!(norm_if("FiftyGigE0/0/1"), "fi50g-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_hundred_gig_full() {
        assert_eq!(norm_if("HundredGigabitEthernet0/0/1"), "hu-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_hundred_gige() {
        assert_eq!(norm_if("HundredGigE0/0/1"), "hu-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_two_hundred_gig() {
        assert_eq!(norm_if("TwoHundredGigE0/0/1"), "th-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_four_hundred_gig() {
        assert_eq!(norm_if("FourHundredGigE0/0/1"), "fh-0-0-1");
    }

    // ── Cisco abbreviated forms ───────────────────────────────────────────────

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_abbrev_gi() {
        assert_eq!(norm_if("Gi0/0/1"), "gi-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_abbrev_te() {
        assert_eq!(norm_if("Te0/0/1"), "te-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_abbrev_fo() {
        assert_eq!(norm_if("Fo0/0/1"), "fo-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_abbrev_hu() {
        assert_eq!(norm_if("Hu0/0/1"), "hu-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn cisco_abbrev_twe() {
        assert_eq!(norm_if("Twe0/0/1"), "twe-0-0-1");
    }

    // ── Huawei VRP ────────────────────────────────────────────────────────────

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_ge() {
        assert_eq!(norm_if("GE0/0/0"), "ge-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_xge() {
        assert_eq!(norm_if("XGigabitEthernet0/0/0"), "xe-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_10ge() {
        assert_eq!(norm_if("10GE0/0/0"), "xe-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_5ge() {
        assert_eq!(norm_if("5GE0/0/0"), "fi5g-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_multige() {
        assert_eq!(norm_if("MultiGE0/0/0"), "mge-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_25ge() {
        assert_eq!(norm_if("25GE0/0/0"), "25ge-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_40ge() {
        assert_eq!(norm_if("40GE0/0/0"), "40ge-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_100ge() {
        assert_eq!(norm_if("100GE0/0/0"), "hu-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_200ge() {
        assert_eq!(norm_if("200GE0/0/0"), "200ge-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_400ge() {
        assert_eq!(norm_if("400GE0/0/0"), "400ge-0-0-0");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn huawei_800ge() {
        assert_eq!(norm_if("800GE0/0/0"), "800ge-0-0-0");
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn case_insensitive_match() {
        assert_eq!(norm_if("GIGABITETHERNET0/0/1"), "gi-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn four_component_address() {
        // rack/slot/card/port format
        assert_eq!(norm_if("GigabitEthernet1/0/0/1"), "gi-1-0-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn two_component_address() {
        assert_eq!(norm_if("GigabitEthernet0/1"), "gi-0-1");
    }

    #[cfg_attr(miri, ignore)] // regex compilation is too slow under Miri
    #[test]
    fn already_dns_safe_passthrough() {
        // PTR-side value: already normalized, should be unchanged
        assert_eq!(norm_if("gi-0-0-1"), "gi-0-0-1");
        assert_eq!(norm_if("xe-0-0-1"), "xe-0-0-1");
    }
}
