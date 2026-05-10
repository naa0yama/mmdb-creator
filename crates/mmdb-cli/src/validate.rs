//! Validate subcommand: config validation and sheet scaffolding.

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead as _, BufReader};
use std::path::Path;

use anyhow::{Context as _, Result};
use mmdb_core::config::Config;
use mmdb_core::types::ScanGwRecord;

use mmdb_scan::normalize::{self, CompiledNormalizeConfig};
use mmdb_scan::ptr_parse::{self, CompiledPattern};

/// Collect all validation errors from `config`.
///
/// Checks:
/// - `whois.server` is not empty
/// - each `sheets[n].filename` exists on disk
/// - each `sheets[n].header_row >= 1`
/// - column names within each sheet are unique
/// - each `sheets[n].columns[m].ptr_field` references a key in `normalize`
/// - each `normalize.<name>.rules[k].pattern` is a valid regex
/// - each `{name}` placeholder in `scan.ptr_patterns[k].regex` exists in `normalize`
///
/// Returns an empty `Vec` when the config is valid.
fn collect_config_errors(config: &Config) -> Vec<String> {
    let mut errors = Vec::new();

    if let Some(whois) = &config.whois
        && whois.server.trim().is_empty()
    {
        errors.push("whois.server is empty".to_owned());
    }

    if let Some(sheets) = &config.sheets {
        for (idx, sheet) in sheets.iter().enumerate() {
            if !sheet.filename.exists() {
                errors.push(format!(
                    "sheets[{idx}].filename '{}' does not exist",
                    sheet.filename.display()
                ));
            }

            if sheet.header_row < 1 {
                errors.push(format!("sheets[{idx}].header_row must be >= 1"));
            }

            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for col in &sheet.columns {
                if !seen.insert(col.name.as_str()) {
                    errors.push(format!(
                        "sheets[{idx}].columns: duplicate name '{}'",
                        col.name
                    ));
                }
                if let Some(ref ptr_field) = col.ptr_field
                    && !config.normalize.contains_key(ptr_field.as_str())
                {
                    errors.push(format!(
                        "sheets[{idx}].columns '{}': ptr_field '{ptr_field}' has no \
                         corresponding [normalize.{ptr_field}] section",
                        col.name
                    ));
                }
            }
        }
    }

    // Validate normalize rule patterns and excludes.
    for (name, cfg) in &config.normalize {
        for (k, rule) in cfg.rules.iter().enumerate() {
            if let Err(e) = regex::Regex::new(&rule.pattern) {
                errors.push(format!(
                    "normalize.{name}.rules[{k}].pattern '{}' is not a valid regex: {e}",
                    rule.pattern
                ));
            }
        }
        for (k, exc) in cfg.excludes.iter().enumerate() {
            if let Err(e) = regex::Regex::new(exc) {
                errors.push(format!(
                    "normalize.{name}.excludes[{k}] '{exc}' is not a valid regex: {e}"
                ));
            }
        }
    }

    // Validate {placeholder} names and excludes in scan.ptr_patterns.
    if let Some(scan) = &config.scan {
        for (i, pattern) in scan.ptr_patterns.iter().enumerate() {
            let names = extract_placeholder_names(&pattern.regex);
            for name in names {
                if !config.normalize.contains_key(name.as_str()) {
                    errors.push(format!(
                        "scan.ptr_patterns[{i}].regex: placeholder '{{{name}}}' has no \
                         corresponding [normalize.{name}] section"
                    ));
                }
            }
            for (j, exc) in pattern.excludes.iter().enumerate() {
                if let Err(e) = regex::Regex::new(exc) {
                    errors.push(format!(
                        "scan.ptr_patterns[{i}].excludes[{j}] '{exc}' is not a valid regex: {e}"
                    ));
                }
            }
        }
    }

    errors
}

/// Extract all `{name}` placeholder names from a regex string.
fn extract_placeholder_names(regex_str: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = regex_str;
    while let Some(open) = rest.find('{') {
        #[allow(clippy::arithmetic_side_effects)]
        let after_open = &rest[open + 1..];
        rest = after_open;
        if let Some(close) = rest.find('}') {
            names.push(rest[..close].to_owned());
            #[allow(clippy::arithmetic_side_effects)]
            let after_close = &rest[close + 1..];
            rest = after_close;
        }
    }
    names
}

/// Re-apply current config to `scanned_path` and print unique unmatched PTR hostnames.
///
/// Reads every `ScanGwRecord` from `scanned_path`, collects all non-null PTR strings,
/// applies the four-step filter (domain → pattern.excludes → regex → normalize.excludes),
/// and prints the PTRs that matched a configured domain but failed the regex.
///
/// # Errors
///
/// Returns an error if `scanned_path` does not exist or cannot be opened.
// NOTEST(io): reads scanned.jsonl and writes to stdout
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::print_stdout)]
pub fn run_ptr(config: &Config, scanned_path: &Path) -> Result<()> {
    let file = std::fs::File::open(scanned_path).with_context(|| {
        format!(
            "{} not found — run 'scan' or 'scan --enrich-only' first",
            scanned_path.display()
        )
    })?;

    let mut ptrs: BTreeSet<String> = BTreeSet::new();
    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| format!("read error at line {lineno}"))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ScanGwRecord>(&line) {
            Ok(record) => {
                if let Some(p) = record.gateway.ptr {
                    ptrs.insert(p);
                }
                for hop in record.routes {
                    if let Some(p) = hop.ptr {
                        ptrs.insert(p);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(lineno, error = %e, "skipping malformed scanned.jsonl line");
            }
        }
    }

    let scan_cfg = config.scan.clone().unwrap_or_default();
    let patterns =
        ptr_parse::compile(&scan_cfg.ptr_patterns).context("failed to compile ptr_patterns")?;
    let norm_map =
        normalize::compile_all(&config.normalize).context("failed to compile normalize rules")?;

    let unmatched = filter_unmatched_ptrs(&ptrs, &patterns, &norm_map);

    for ptr in &unmatched {
        println!("{ptr}");
    }
    if !unmatched.is_empty() {
        println!();
    }
    println!("ptr_unmatched: {}", unmatched.len());

    Ok(())
}

/// Apply the four-step filter and return sorted unmatched PTR hostnames.
///
/// Steps:
/// 1. Domain filter — PTR must end with a configured `[[scan.ptr_patterns]].domain`.
/// 2. Pattern excludes — PTR matches `pattern.excludes` → skip silently.
/// 3. Regex match — `ptr_parse::parse` returns `None` → **report**.
/// 4. Normalize excludes — a captured field value matches its `[normalize.<name>].excludes`
///    → skip silently (was matched, consciously excluded).
fn filter_unmatched_ptrs(
    ptrs: &BTreeSet<String>,
    patterns: &[CompiledPattern],
    norm_map: &HashMap<String, CompiledNormalizeConfig>,
) -> Vec<String> {
    let mut unmatched = Vec::new();

    'ptr: for ptr in ptrs {
        // Step 1: find the first pattern whose domain suffix matches.
        let Some(matched_pattern) = patterns
            .iter()
            .find(|p| p.domain.as_deref().is_none_or(|d| ptr.ends_with(d)))
        else {
            continue 'ptr; // no domain match — out of scope
        };

        // Step 2: pattern-level excludes.
        if matched_pattern.is_excluded(ptr) {
            continue 'ptr;
        }

        // Step 3: regex match.
        let Some(device) = ptr_parse::parse(ptr, std::slice::from_ref(matched_pattern)) else {
            unmatched.push(ptr.clone());
            continue 'ptr;
        };

        // Step 4: normalize.excludes on captured fields.
        let fields: &[(&str, Option<&str>)] = &[
            ("interface", device.interface.as_deref()),
            ("device", device.device.as_deref()),
            ("device_role", device.device_role.as_deref()),
            ("facility", device.facility.as_deref()),
        ];
        for (field_name, value) in fields {
            if let (Some(cfg), Some(val)) = (norm_map.get(*field_name), value) {
                let normalised = normalize::apply(cfg, val);
                if cfg.is_excluded(&normalised) {
                    continue 'ptr;
                }
            }
        }
    }

    unmatched
}

/// Run config validation and optionally emit an `--init-sheets` TOML scaffold.
///
/// # Errors
///
/// Returns an error if the config fails validation (missing files, bad `header_row`,
/// duplicate column names, or empty whois server).
// NOTEST(io): writes validation results to stdout — depends on terminal/stdout
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::print_stdout)]
pub fn run(config: &Config, init_sheets: bool) -> Result<()> {
    let errors = collect_config_errors(config);

    if !errors.is_empty() {
        println!("Config validation failed:");
        for e in &errors {
            println!("  - {e}");
        }
        return Err(anyhow::anyhow!("config validation failed"));
    }

    tracing::info!("config validation passed");
    println!("✓ config is valid");

    if init_sheets {
        print_init_sheets(config);
    }

    Ok(())
}

/// Emit a TOML scaffold for all `[[sheets]]` entries to stdout.
// NOTEST(io): calls mmdb_xlsx::inspect_sheets (Excel file I/O) and writes to stdout
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::print_stdout)]
fn print_init_sheets(config: &Config) {
    let sheets = match config.sheets.as_deref() {
        None | Some([]) => {
            tracing::warn!("no [[sheets]] entries found; nothing to scaffold");
            println!("warning: no [[sheets]] entries found; nothing to scaffold");
            return;
        }
        Some(s) => s,
    };

    for sheet_config in sheets {
        let sheet_infos = match mmdb_xlsx::inspect_sheets(sheet_config) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    filename = %sheet_config.filename.display(),
                    error = %e,
                    "failed to inspect sheets; skipping"
                );
                println!(
                    "warning: failed to inspect '{}': {e}",
                    sheet_config.filename.display()
                );
                continue;
            }
        };

        let available: Vec<String> = sheet_infos.iter().map(|s| s.name.clone()).collect();
        let excludes = &sheet_config.excludes_sheets;

        let available_toml = format_toml_string_array(&available);
        let excludes_toml = format_toml_string_array(excludes);

        println!();
        println!("# ============================================================");
        println!("# File: {}", sheet_config.filename.display());
        println!("# Available sheets: {available_toml}");
        println!("# Excluded sheets:  {excludes_toml}");
        println!("# Paste this block into config.toml and edit 'type' for each column.");
        println!("# ============================================================");
        println!();
        println!("[[sheets]]");
        println!("filename = \"{}\"", sheet_config.filename.display());
        println!("header_row = {}", sheet_config.header_row);
        println!("excludes_sheets = {excludes_toml}");

        let mut seen_headers: std::collections::HashSet<String> = std::collections::HashSet::new();

        for sheet_info in &sheet_infos {
            println!();
            println!("# --- Sheet: {} ---", sheet_info.name);

            for header in &sheet_info.headers {
                if !seen_headers.insert(header.clone()) {
                    continue;
                }
                let name = to_snake_case(header);
                println!();
                println!("[[sheets.columns]]");
                println!("name = \"{name}\"");
                println!("sheet_name = \"{header}\"");
                println!("type = \"string\"");
            }
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

/// Convert a column header string to `snake_case`.
///
/// Spaces, hyphens, slashes, and other non-alphanumeric characters are replaced
/// with underscores. Consecutive underscores are collapsed into one.
fn to_snake_case(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .split('_')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// Format a `&[String]` as a TOML inline array, e.g. `["a", "b"]`.
fn format_toml_string_array(items: &[String]) -> String {
    let inner = items
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mmdb_core::config::{ColumnMapping, ColumnType, Config, SheetConfig, WhoisConfig};

    use super::{collect_config_errors, format_toml_string_array, to_snake_case};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn base_config() -> Config {
        Config {
            whois: None,
            sheets: None,
            scan: None,
            enrich: None,
            normalize: std::collections::HashMap::new(),
        }
    }

    fn whois_config(server: &str) -> WhoisConfig {
        WhoisConfig {
            server: server.to_owned(),
            timeout_sec: 10,
            asn: vec![],
            rate_limit_ms: 2000,
            max_retries: 3,
            initial_backoff_ms: 1000,
            ripe_stat_rate_limit_ms: 1000,
            cache_dir: String::from("data/cache"),
            cache_ttl_secs: 7200,
            http_max_retries: 3,
            http_retry_delay_secs: 2,
        }
    }

    fn sheet(filename: impl Into<PathBuf>, header_row: u32) -> SheetConfig {
        SheetConfig {
            filename: filename.into(),
            header_row,
            excludes_sheets: vec![],
            columns: vec![],
        }
    }

    fn col(name: &str) -> ColumnMapping {
        ColumnMapping {
            name: name.to_owned(),
            sheet_name: name.to_owned(),
            col_type: ColumnType::String,
            ptr_field: None,
        }
    }

    // ── collect_config_errors ─────────────────────────────────────────────────

    #[test]
    fn empty_config_has_no_errors() {
        assert!(collect_config_errors(&base_config()).is_empty());
    }

    #[test]
    fn nonempty_whois_server_is_valid() {
        let cfg = Config {
            whois: Some(whois_config("whois.example.com")),
            ..base_config()
        };
        assert!(collect_config_errors(&cfg).is_empty());
    }

    #[test]
    fn empty_whois_server_is_an_error() {
        let cfg = Config {
            whois: Some(whois_config("")),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert_eq!(errors, ["whois.server is empty"]);
    }

    #[test]
    fn whitespace_only_whois_server_is_an_error() {
        let cfg = Config {
            whois: Some(whois_config("   ")),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert_eq!(errors, ["whois.server is empty"]);
    }

    #[test]
    fn missing_sheet_file_is_an_error() {
        let cfg = Config {
            sheets: Some(vec![sheet("/nonexistent/mmdb-test-file.xlsx", 1)]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("does not exist")),
            "expected 'does not exist' in {errors:?}"
        );
    }

    #[test]
    fn existing_sheet_file_passes() {
        // "." always exists; use it as a stand-in for a real xlsx path.
        let cfg = Config {
            sheets: Some(vec![sheet(".", 1)]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            !errors.iter().any(|e| e.contains("does not exist")),
            "unexpected file error in {errors:?}"
        );
    }

    #[test]
    fn header_row_zero_is_an_error() {
        let cfg = Config {
            sheets: Some(vec![sheet(".", 0)]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("header_row must be >= 1")),
            "expected header_row error in {errors:?}"
        );
    }

    #[test]
    fn header_row_one_is_valid() {
        let cfg = Config {
            sheets: Some(vec![sheet(".", 1)]),
            ..base_config()
        };
        assert!(collect_config_errors(&cfg).is_empty());
    }

    #[test]
    fn duplicate_column_names_are_an_error() {
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col("region"), col("region")],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("duplicate name 'region'")),
            "expected duplicate-name error in {errors:?}"
        );
    }

    #[test]
    fn unique_column_names_are_valid() {
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col("region"), col("site")],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        assert!(collect_config_errors(&cfg).is_empty());
    }

    #[test]
    fn multiple_errors_are_all_reported() {
        let cfg = Config {
            whois: Some(whois_config("")),
            sheets: Some(vec![SheetConfig {
                columns: vec![col("x"), col("x")],
                ..sheet(".", 0)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert_eq!(errors.len(), 3, "expected 3 errors, got {errors:?}");
    }

    // ── normalize validation ──────────────────────────────────────────────────

    fn col_with_ptr_field(name: &str, ptr_field: &str) -> ColumnMapping {
        ColumnMapping {
            ptr_field: Some(ptr_field.to_owned()),
            ..col(name)
        }
    }

    fn normalize_map(
        keys: &[&str],
    ) -> std::collections::HashMap<String, mmdb_core::config::NormalizeConfig> {
        keys.iter()
            .map(|k| {
                (
                    (*k).to_owned(),
                    mmdb_core::config::NormalizeConfig::default(),
                )
            })
            .collect()
    }

    #[test]
    fn ptr_field_references_valid_normalize_key() {
        let cfg = Config {
            normalize: normalize_map(&["interface"]),
            sheets: Some(vec![SheetConfig {
                columns: vec![col_with_ptr_field("port", "interface")],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        assert!(collect_config_errors(&cfg).is_empty());
    }

    #[test]
    fn ptr_field_missing_normalize_key_is_an_error() {
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col_with_ptr_field("port", "interface")],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("ptr_field 'interface'")),
            "expected ptr_field error in {errors:?}"
        );
    }

    #[test]
    fn normalize_invalid_regex_is_an_error() {
        use mmdb_core::config::{NormalizeConfig, NormalizeRule};
        let cfg = Config {
            normalize: std::collections::HashMap::from([(
                "interface".to_owned(),
                NormalizeConfig {
                    rules: vec![NormalizeRule {
                        pattern: "[invalid".to_owned(),
                        replacement: "x".to_owned(),
                    }],
                    ..Default::default()
                },
            )]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("is not a valid regex")),
            "expected invalid regex error in {errors:?}"
        );
    }

    #[test]
    fn placeholder_with_missing_normalize_key_is_an_error() {
        use mmdb_core::config::{PtrPattern, ScanConfig};
        let cfg = Config {
            scan: Some(ScanConfig {
                ptr_patterns: vec![PtrPattern {
                    domain: None,
                    regex: "{interface}.{device}".to_owned(),
                    excludes: vec![],
                }],
                ..ScanConfig::default()
            }),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("placeholder '{interface}'")),
            "expected placeholder error in {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("placeholder '{device}'")),
            "expected placeholder error in {errors:?}"
        );
    }

    #[test]
    fn placeholder_with_valid_normalize_keys_is_valid() {
        use mmdb_core::config::{PtrPattern, ScanConfig};
        let cfg = Config {
            normalize: normalize_map(&["interface", "device"]),
            scan: Some(ScanConfig {
                ptr_patterns: vec![PtrPattern {
                    domain: None,
                    regex: "{interface}.{device}".to_owned(),
                    excludes: vec![],
                }],
                ..ScanConfig::default()
            }),
            ..base_config()
        };
        assert!(collect_config_errors(&cfg).is_empty());
    }

    // ── to_snake_case ─────────────────────────────────────────────────────────

    #[test]
    fn snake_case_simple() {
        assert_eq!(to_snake_case("site"), "site");
    }

    #[test]
    fn snake_case_space() {
        assert_eq!(to_snake_case("DEMARC addresses"), "demarc_addresses");
    }

    #[test]
    fn snake_case_hyphen() {
        assert_eq!(to_snake_case("lan-address-1"), "lan_address_1");
    }

    #[test]
    fn snake_case_consecutive_spaces() {
        assert_eq!(to_snake_case("lan  address  1"), "lan_address_1");
    }

    #[test]
    fn snake_case_trim() {
        assert_eq!(to_snake_case("  site  "), "site");
    }

    #[test]
    fn snake_case_mixed_separators() {
        assert_eq!(to_snake_case("PE addresses"), "pe_addresses");
    }

    // ── format_toml_string_array ─────────────────────────────────────────────

    #[test]
    fn format_toml_array_empty() {
        assert_eq!(format_toml_string_array(&[]), "[]");
    }

    #[test]
    fn format_toml_array_single_item() {
        let items = vec![String::from("Sheet1")];
        assert_eq!(format_toml_string_array(&items), r#"["Sheet1"]"#);
    }

    #[test]
    fn format_toml_array_multiple_items() {
        let items = vec![String::from("Sheet1"), String::from("Sheet2")];
        assert_eq!(format_toml_string_array(&items), r#"["Sheet1", "Sheet2"]"#);
    }

    // ── excludes validation ───────────────────────────────────────────────────

    #[test]
    fn normalize_invalid_excludes_regex_is_an_error() {
        use mmdb_core::config::NormalizeConfig;
        let mut normalize = std::collections::HashMap::new();
        normalize.insert(
            "interface".to_owned(),
            NormalizeConfig {
                rules: vec![],
                case: mmdb_core::config::NormalizeCase::Lower,
                excludes: vec!["[invalid".to_owned()],
            },
        );
        let cfg = Config {
            normalize,
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("normalize.interface.excludes[0]")),
            "expected excludes error in {errors:?}"
        );
    }

    #[test]
    fn ptr_pattern_invalid_excludes_regex_is_an_error() {
        use mmdb_core::config::{PtrPattern, ScanConfig};
        let cfg = Config {
            scan: Some(ScanConfig {
                ptr_patterns: vec![PtrPattern {
                    domain: None,
                    regex: r"^(?P<device>rtr\d+)$".to_owned(),
                    excludes: vec!["[invalid".to_owned()],
                }],
                ..ScanConfig::default()
            }),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("scan.ptr_patterns[0].excludes[0]")),
            "expected excludes error in {errors:?}"
        );
    }

    #[test]
    fn valid_excludes_pass_validation() {
        use mmdb_core::config::{NormalizeConfig, PtrPattern, ScanConfig};
        let mut normalize = std::collections::HashMap::new();
        normalize.insert(
            "interface".to_owned(),
            NormalizeConfig {
                rules: vec![],
                case: mmdb_core::config::NormalizeCase::Lower,
                excludes: vec![r"^lo\d*$".to_owned(), r"^mgmt\d*$".to_owned()],
            },
        );
        let cfg = Config {
            normalize,
            scan: Some(ScanConfig {
                ptr_patterns: vec![PtrPattern {
                    domain: Some("example.com".to_owned()),
                    regex: r"^(?P<interface>[^.]+)\.(?P<device>[^.]+)".to_owned(),
                    excludes: vec![r"\.ad\.example\.com$".to_owned()],
                }],
                ..ScanConfig::default()
            }),
            ..base_config()
        };
        assert!(collect_config_errors(&cfg).is_empty());
    }

    // ── filter_unmatched_ptrs ─────────────────────────────────────────────────

    mod filter_tests {
        use std::collections::{BTreeSet, HashMap};

        use mmdb_core::config::{NormalizeCase, NormalizeConfig, PtrPattern};

        use super::super::{filter_unmatched_ptrs, normalize, ptr_parse};

        fn make_patterns(domain: &str, regex: &str) -> Vec<ptr_parse::CompiledPattern> {
            ptr_parse::compile(&[PtrPattern {
                domain: Some(domain.to_owned()),
                regex: regex.to_owned(),
                excludes: vec![],
            }])
            .unwrap()
        }

        fn make_patterns_with_excludes(
            domain: &str,
            regex: &str,
            excludes: &[&str],
        ) -> Vec<ptr_parse::CompiledPattern> {
            ptr_parse::compile(&[PtrPattern {
                domain: Some(domain.to_owned()),
                regex: regex.to_owned(),
                excludes: excludes.iter().map(|s| (*s).to_owned()).collect(),
            }])
            .unwrap()
        }

        fn make_norm_map(
            field: &str,
            excludes: &[&str],
        ) -> HashMap<String, normalize::CompiledNormalizeConfig> {
            let cfg = NormalizeConfig {
                rules: vec![],
                case: NormalizeCase::Lower,
                excludes: excludes.iter().map(|s| (*s).to_owned()).collect(),
            };
            normalize::compile_all(&HashMap::from([(field.to_owned(), cfg)])).unwrap()
        }

        fn ptrs(list: &[&str]) -> BTreeSet<String> {
            list.iter().map(|s| (*s).to_owned()).collect()
        }

        #[test]
        fn domain_match_regex_fail_is_reported() {
            let patterns = make_patterns(
                "example.com",
                r"^(?P<interface>[^.]+)\.rtr\d+\.dc\d+\.example\.com$",
            );
            let norm = HashMap::new();
            // PTR matches domain but does not match the regex pattern
            let result =
                filter_unmatched_ptrs(&ptrs(&["unknown-host.example.com"]), &patterns, &norm);
            assert_eq!(result, vec!["unknown-host.example.com"]);
        }

        #[test]
        fn domain_match_regex_success_not_reported() {
            let patterns = make_patterns(
                "example.com",
                r"^(?P<interface>[^.]+)\.(?P<device>[^.]+)\.example\.com$",
            );
            let norm = HashMap::new();
            let result =
                filter_unmatched_ptrs(&ptrs(&["xe-0-0-1.rtr01.example.com"]), &patterns, &norm);
            assert!(result.is_empty());
        }

        #[test]
        fn pattern_excludes_suppresses_ptr() {
            let patterns = make_patterns_with_excludes(
                "example.com",
                r"^(?P<interface>[^.]+)\.example\.com$",
                &[r"\.ad\.example\.com$"],
            );
            let norm = HashMap::new();
            let result = filter_unmatched_ptrs(&ptrs(&["host.ad.example.com"]), &patterns, &norm);
            assert!(result.is_empty());
        }

        #[test]
        fn domain_not_matching_is_ignored() {
            let patterns = make_patterns("example.com", r"^(?P<interface>[^.]+)\.example\.com$");
            let norm = HashMap::new();
            let result = filter_unmatched_ptrs(&ptrs(&["host.other.net"]), &patterns, &norm);
            assert!(result.is_empty());
        }

        #[test]
        fn normalize_excludes_suppresses_matched_ptr() {
            // Pattern matches and captures interface=lo0 → normalize.excludes suppresses it.
            let patterns = make_patterns(
                "example.com",
                r"^(?P<interface>[^.]+)\.rtr01\.example\.com$",
            );
            let norm = make_norm_map("interface", &[r"^lo\d*$"]);
            let result = filter_unmatched_ptrs(&ptrs(&["lo0.rtr01.example.com"]), &patterns, &norm);
            assert!(result.is_empty());
        }

        #[test]
        fn empty_ptr_set_returns_empty() {
            let patterns = make_patterns("example.com", r"^(?P<interface>[^.]+)\.example\.com$");
            let norm = HashMap::new();
            let result = filter_unmatched_ptrs(&BTreeSet::new(), &patterns, &norm);
            assert!(result.is_empty());
        }

        #[test]
        fn duplicate_ptrs_reported_once() {
            // BTreeSet deduplicates; same PTR appears once in output.
            let patterns = make_patterns(
                "example.com",
                r"^(?P<interface>[^.]+)\.rtr\d+\.dc\d+\.example\.com$",
            );
            let norm = HashMap::new();
            // Same PTR entered twice into the BTreeSet → deduplicated by set
            let set = ptrs(&["unknown.example.com", "unknown.example.com"]);
            let result = filter_unmatched_ptrs(&set, &patterns, &norm);
            assert_eq!(result.len(), 1);
            assert_eq!(
                result.first().map(String::as_str),
                Some("unknown.example.com")
            );
        }

        #[test]
        fn null_domain_pattern_matches_all_ptrs() {
            let patterns = ptr_parse::compile(&[PtrPattern {
                domain: None, // matches any domain
                regex: r"^(?P<interface>[^.]+)\.rtr01\.example\.com$".to_owned(),
                excludes: vec![],
            }])
            .unwrap();
            let norm = HashMap::new();
            // Fails regex → reported
            let result = filter_unmatched_ptrs(&ptrs(&["other.net"]), &patterns, &norm);
            assert_eq!(result, vec!["other.net"]);
        }
    }
}
