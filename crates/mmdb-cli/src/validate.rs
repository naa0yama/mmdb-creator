//! Validate subcommand: config validation and sheet scaffolding.

use std::collections::{BTreeSet, HashMap, HashSet};
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
/// - each `sheets[n].columns[m].name` contains only `[a-z0-9_]`
/// - exactly one of `sheet_name` / `sheet_names` is set per column
/// - `sheet_names` is only used with `type = "addresses"`
/// - `sheet_names` and `ptr_field` are not combined
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
                validate_column(col, idx, config, &mut errors);
            }
            validate_groups(sheet, idx, &mut errors);
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

/// Validate `groups` in a [`SheetConfig`] and push any errors into `out`.
///
/// Checks:
/// - each group has at least 2 sheet names
/// - no sheet name appears in more than one group
/// - no group sheet name is also in `excludes_sheets`
fn validate_groups(sheet: &mmdb_core::config::SheetConfig, idx: usize, out: &mut Vec<String>) {
    let mut membership: HashSet<&str> = HashSet::new();
    for (gidx, group) in sheet.groups.iter().enumerate() {
        if group.len() < 2 {
            out.push(format!(
                "sheets[{idx}].groups[{gidx}]: group must have at least 2 sheet names"
            ));
        }
        for name in group {
            if sheet.excludes_sheets.iter().any(|e| e == name) {
                out.push(format!(
                    "sheets[{idx}].groups[{gidx}]: '{name}' is also in excludes_sheets"
                ));
            }
            if !membership.insert(name.as_str()) {
                out.push(format!(
                    "sheets[{idx}].groups: '{name}' appears in multiple groups"
                ));
            }
        }
    }
}

/// Validate a single [`ColumnMapping`] and push any errors into `out`.
fn validate_column(
    col: &mmdb_core::config::ColumnMapping,
    idx: usize,
    config: &Config,
    out: &mut Vec<String>,
) {
    if !col.name.chars().all(is_snake_case_char) {
        out.push(format!(
            "sheets[{idx}].columns '{}': name must contain only [a-z0-9_]",
            col.name
        ));
    }
    match (&col.sheet_name, &col.sheet_names) {
        (Some(_), Some(_)) => {
            out.push(format!(
                "sheets[{idx}].columns '{}': sheet_name and sheet_names cannot both be set",
                col.name
            ));
        }
        (None, None) => {
            out.push(format!(
                "sheets[{idx}].columns '{}': \
                 exactly one of sheet_name or sheet_names must be set",
                col.name
            ));
        }
        _ => {}
    }
    if col.sheet_names.is_some()
        && !matches!(col.col_type, mmdb_core::config::ColumnType::Addresses)
    {
        out.push(format!(
            "sheets[{idx}].columns '{}': \
             sheet_names is only allowed with type = \"addresses\"",
            col.name
        ));
    }
    if col.sheet_names.is_some() && col.ptr_field.is_some() {
        out.push(format!(
            "sheets[{idx}].columns '{}': ptr_field cannot be combined with sheet_names",
            col.name
        ));
    }
    if col.sheet_names.is_none()
        && let Some(ref ptr_field) = col.ptr_field
        && !config.normalize.contains_key(ptr_field.as_str())
    {
        out.push(format!(
            "sheets[{idx}].columns '{}': ptr_field '{ptr_field}' has no \
             corresponding [normalize.{ptr_field}] section",
            col.name
        ));
    }
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
/// Validate `xlsx-rows.jsonl` for duplicate CIDRs within the same sheettype.
///
/// Reads the JSONL file, reconstructs `SheetResult`-like data from `_source` metadata,
/// and delegates to `mmdb_xlsx::import::validate_no_duplicate_cidrs`.
///
/// # Errors
///
/// Returns an error if the file cannot be read, or if duplicate CIDRs are found.
// NOTEST(io): reads xlsx-rows.jsonl from filesystem and writes to stdout
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::print_stdout)]
pub fn run_xlsx_rows(xlsx_rows_path: &Path, config: &Config) -> Result<()> {
    use indexmap::IndexMap;
    use ipnet::IpNet;
    use mmdb_core::config::SheetType;
    use mmdb_xlsx::reader::{CellValue, SheetResult, XlsxRow};

    let raw = std::fs::read_to_string(xlsx_rows_path).with_context(|| {
        format!(
            "{} not found — run 'import --xlsx' first",
            xlsx_rows_path.display()
        )
    })?;

    // Group rows back into SheetResult by (file, sheet, sheettype).
    let mut sheet_map: std::collections::HashMap<(String, String, SheetType), Vec<XlsxRow>> =
        std::collections::HashMap::new();

    for (lineno, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            tracing::warn!(
                line = lineno.saturating_add(1),
                "xlsx-rows.jsonl: skipping unparseable line"
            );
            continue;
        };
        let Some(obj) = val.as_object() else { continue };
        let src = obj.get("_source").and_then(|v| v.as_object());
        let file = src
            .and_then(|s| s.get("file"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let sheet = src
            .and_then(|s| s.get("sheet"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let sheettype_str = src
            .and_then(|s| s.get("sheettype"))
            .and_then(|v| v.as_str())
            .unwrap_or("backbone");
        let sheettype = if sheettype_str == "hosting" {
            SheetType::Hosting
        } else {
            SheetType::Backbone
        };
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
        let row_index = src
            .and_then(|s| s.get("row_index"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize;

        let nets: Vec<IpNet> = obj
            .iter()
            .filter(|(k, _)| k.as_str() != "_source")
            .filter_map(|(_, v)| v.as_array())
            .flatten()
            .filter_map(|item| item.as_str()?.parse::<IpNet>().ok())
            .collect();

        if !nets.is_empty() {
            let mut fields = IndexMap::new();
            fields.insert("network".to_owned(), CellValue::Addresses(nets));
            sheet_map
                .entry((file, sheet, sheettype))
                .or_default()
                .push(XlsxRow { row_index, fields });
        }
    }

    let results: Vec<SheetResult> = sheet_map
        .into_iter()
        .map(|((filename, sheetname, sheettype), rows)| SheetResult {
            filename,
            sheetname,
            last_modified: None,
            rows,
            skipped_count: 0,
            sheettype,
        })
        .collect();

    let group_lookup = if let Some(sheets) = config.sheets.as_deref() {
        mmdb_xlsx::import::build_group_lookup(sheets, &results)?
    } else {
        HashMap::new()
    };

    match mmdb_xlsx::import::validate_no_duplicate_cidrs(&results, &group_lookup) {
        Ok(()) => {
            println!(
                "xlsx-rows.jsonl: no duplicate CIDRs detected ({} sheets)",
                results.len()
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

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

    // Verify that every sheet name referenced in groups actually exists in the xlsx.
    validate_group_sheet_names(config)?;

    println!("✓ config is valid");

    if init_sheets {
        print_init_sheets(config)?;
    }

    Ok(())
}

/// Check that every sheet name in `groups` exists as a tab in the xlsx file.
///
/// Uses `inspect_sheets` to open each xlsx file. I/O errors are warned and
/// skipped rather than failing, since the file-existence check already runs
/// in `collect_config_errors`.
///
/// # Errors
///
/// Returns an error listing all group sheet names that are absent from the xlsx.
// NOTEST(io): opens xlsx files via inspect_sheets
#[cfg_attr(coverage_nightly, coverage(off))]
fn validate_group_sheet_names(config: &Config) -> Result<()> {
    let Some(sheets) = config.sheets.as_deref() else {
        return Ok(());
    };
    let mut errors: Vec<String> = Vec::new();

    for sheet_config in sheets {
        if sheet_config.groups.is_empty() {
            continue;
        }
        let available = match mmdb_xlsx::inspect_sheets(sheet_config, false) {
            Ok(infos) => infos.into_iter().map(|s| s.name).collect::<HashSet<_>>(),
            Err(e) => {
                tracing::warn!(
                    filename = %sheet_config.filename.display(),
                    error = %e,
                    "groups validation: failed to inspect sheets; skipping"
                );
                continue;
            }
        };
        for (gidx, group) in sheet_config.groups.iter().enumerate() {
            for name in group {
                if !available.contains(name) {
                    errors.push(format!(
                        "sheets[*].groups[{gidx}]: '{name}' not found in '{}'",
                        sheet_config.filename.display()
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("config validation failed:\n  {}", errors.join("\n  "))
    }
}

/// Emit a TOML scaffold for all `[[sheets]]` entries to stdout.
///
/// Returns `Err` if any generated `name` contains non-ASCII characters.
// NOTEST(io): calls mmdb_xlsx::inspect_sheets (Excel file I/O) and writes to stdout
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::print_stdout)]
fn print_init_sheets(config: &Config) -> Result<()> {
    let sheets = match config.sheets.as_deref() {
        None | Some([]) => {
            tracing::warn!("no [[sheets]] entries found; nothing to scaffold");
            println!("warning: no [[sheets]] entries found; nothing to scaffold");
            return Ok(());
        }
        Some(s) => s,
    };
    let mut init_errors = Vec::new();

    for sheet_config in sheets {
        let sheet_infos = match mmdb_xlsx::inspect_sheets(sheet_config, true) {
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
        // REASON: header_row is u32; usize is >= u32 on all supported targets.
        #[allow(clippy::as_conversions)]
        let header_row_usize = sheet_config.header_row as usize;

        for sheet_info in &sheet_infos {
            println!();
            println!("# --- Sheet: {} ---", sheet_info.name);

            if !sheet_info.preview_rows.is_empty() {
                let end_row = header_row_usize
                    .saturating_add(sheet_info.preview_rows.len())
                    .saturating_sub(1);
                println!(
                    "# Rows {}–{} (header_row = {}):",
                    sheet_config.header_row, end_row, sheet_config.header_row
                );
                for (offset, row) in sheet_info.preview_rows.iter().enumerate() {
                    let row_num = header_row_usize.saturating_add(offset);
                    let cells = row.join(" | ");
                    println!("#   row {row_num} | {cells}");
                }
            }

            for header in &sheet_info.headers {
                if !seen_headers.insert(header.clone()) {
                    continue;
                }
                let name = to_snake_case(header);
                if !name.chars().all(is_snake_case_char) {
                    init_errors.push(format!(
                        "generated name '{name}' (from header '{header}') contains characters outside [a-z0-9_]"
                    ));
                }
                println!();
                println!("[[sheets.columns]]");
                println!("name = \"{name}\"");
                println!("sheet_name = \"{header}\"");
                println!("type = \"string\"");
            }
        }
    }
    if !init_errors.is_empty() {
        println!("--init-sheets validation failed:");
        for e in &init_errors {
            println!("  - {e}");
        }
        return Err(anyhow::anyhow!(
            "--init-sheets generated invalid column names"
        ));
    }
    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

/// Return `true` if `c` is a valid `snake_case` character: `[a-z0-9_]`.
const fn is_snake_case_char(c: char) -> bool {
    matches!(c, 'a'..='z' | '0'..='9' | '_')
}

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
            mmdb: mmdb_core::config::MmdbConfig::default(),
            normalize: std::collections::HashMap::new(),
        }
    }

    fn whois_config(server: &str) -> WhoisConfig {
        WhoisConfig {
            server: server.to_owned(),
            auto_rir: false,
            timeout_sec: 10,
            asn: vec![],
            ip: vec![],
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
            sheettype: mmdb_core::config::SheetType::Backbone,
            groups: vec![],
        }
    }

    fn col(name: &str) -> ColumnMapping {
        ColumnMapping {
            name: name.to_owned(),
            sheet_name: Some(name.to_owned()),
            sheet_names: None,
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
    fn non_ascii_column_name_is_an_error() {
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col("日本語")],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("name must contain only [a-z0-9_]")),
            "expected non-ASCII name error in {errors:?}"
        );
    }

    #[test]
    fn ascii_column_name_is_valid() {
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col("valid_name_01")],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        assert!(collect_config_errors(&cfg).is_empty());
    }

    #[test]
    fn mixed_ascii_non_ascii_column_name_is_an_error() {
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col("region_日本")],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("name must contain only [a-z0-9_]")),
            "expected non-ASCII name error in {errors:?}"
        );
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

    // ── sheet_name / sheet_names validation ──────────────────────────────────

    fn addr_col_multi(name: &str, sheet_names: &[&str]) -> ColumnMapping {
        ColumnMapping {
            name: name.to_owned(),
            sheet_name: None,
            sheet_names: Some(sheet_names.iter().map(|s| (*s).to_owned()).collect()),
            col_type: ColumnType::Addresses,
            ptr_field: None,
        }
    }

    #[test]
    fn both_sheet_name_and_sheet_names_is_error() {
        let col = ColumnMapping {
            name: "addr".to_owned(),
            sheet_name: Some("Addr".to_owned()),
            sheet_names: Some(vec!["Addr1".to_owned()]),
            col_type: ColumnType::Addresses,
            ptr_field: None,
        };
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("cannot both be set")),
            "expected both-set error in {errors:?}"
        );
    }

    #[test]
    fn neither_sheet_name_nor_sheet_names_is_error() {
        let col = ColumnMapping {
            name: "addr".to_owned(),
            sheet_name: None,
            sheet_names: None,
            col_type: ColumnType::Addresses,
            ptr_field: None,
        };
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("exactly one")),
            "expected exactly-one error in {errors:?}"
        );
    }

    #[test]
    fn sheet_names_with_string_type_is_error() {
        let col = ColumnMapping {
            name: "site".to_owned(),
            sheet_name: None,
            sheet_names: Some(vec!["Site1".to_owned()]),
            col_type: ColumnType::String,
            ptr_field: None,
        };
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("only allowed with type")),
            "expected type-restriction error in {errors:?}"
        );
    }

    #[test]
    fn sheet_names_with_ptr_field_is_error() {
        let col = ColumnMapping {
            name: "addr".to_owned(),
            sheet_name: None,
            sheet_names: Some(vec!["Addr1".to_owned()]),
            col_type: ColumnType::Addresses,
            ptr_field: Some("facility".to_owned()),
        };
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![col],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        let errors = collect_config_errors(&cfg);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("ptr_field cannot be combined")),
            "expected ptr_field error in {errors:?}"
        );
    }

    #[test]
    fn sheet_names_with_addresses_type_is_valid() {
        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                columns: vec![addr_col_multi("addrs", &["Addr1", "Addr2"])],
                ..sheet(".", 1)
            }]),
            ..base_config()
        };
        assert!(
            collect_config_errors(&cfg).is_empty(),
            "sheet_names + Addresses should be valid"
        );
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

    // ── validate_groups ───────────────────────────────────────────────────────

    mod groups {
        use std::path::PathBuf;

        use mmdb_core::config::{Config, SheetConfig};

        use super::super::collect_config_errors;

        fn base_config() -> Config {
            Config {
                whois: None,
                sheets: None,
                scan: None,
                mmdb: mmdb_core::config::MmdbConfig::default(),
                normalize: std::collections::HashMap::new(),
            }
        }

        fn sheet_with_groups(groups: Vec<Vec<String>>) -> SheetConfig {
            SheetConfig {
                // Use a path that always exists so the file-existence check passes.
                filename: PathBuf::from("."),
                header_row: 1,
                excludes_sheets: vec![],
                columns: vec![],
                sheettype: mmdb_core::config::SheetType::Backbone,
                groups,
            }
        }

        #[test]
        fn valid_groups_no_error() {
            let cfg = Config {
                sheets: Some(vec![sheet_with_groups(vec![vec![
                    "border1.ty1".to_owned(),
                    "border1.ty2".to_owned(),
                ]])]),
                ..base_config()
            };
            let errors = collect_config_errors(&cfg);
            assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        }

        #[test]
        fn group_single_sheet_is_error() {
            let cfg = Config {
                sheets: Some(vec![sheet_with_groups(vec![vec![
                    "border1.ty1".to_owned(),
                ]])]),
                ..base_config()
            };
            let errors = collect_config_errors(&cfg);
            assert!(
                errors.iter().any(|e| e.contains("at least 2")),
                "expected 'at least 2' error, got: {errors:?}"
            );
        }

        #[test]
        fn group_sheet_in_excludes_is_error() {
            let mut s = sheet_with_groups(vec![vec![
                "border1.ty1".to_owned(),
                "border1.ty2".to_owned(),
            ]]);
            s.excludes_sheets = vec!["border1.ty1".to_owned()];
            let cfg = Config {
                sheets: Some(vec![s]),
                ..base_config()
            };
            let errors = collect_config_errors(&cfg);
            assert!(
                errors.iter().any(|e| e.contains("excludes_sheets")),
                "expected excludes_sheets error, got: {errors:?}"
            );
        }

        #[test]
        fn group_multi_membership_is_error() {
            let cfg = Config {
                sheets: Some(vec![sheet_with_groups(vec![
                    vec!["border1.ty1".to_owned(), "border1.ty2".to_owned()],
                    vec!["border1.ty2".to_owned(), "core1".to_owned()],
                ])]),
                ..base_config()
            };
            let errors = collect_config_errors(&cfg);
            assert!(
                errors.iter().any(|e| e.contains("multiple groups")),
                "expected 'multiple groups' error, got: {errors:?}"
            );
        }
    }
}
