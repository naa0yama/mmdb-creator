//! Validate subcommand: config validation and sheet scaffolding.

use anyhow::Result;
use mmdb_core::config::Config;

/// Collect all validation errors from `config`.
///
/// Checks:
/// - `whois.server` is not empty
/// - each `sheets[n].filename` exists on disk
/// - each `sheets[n].header_row >= 1`
/// - column names within each sheet are unique
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
            }
        }
    }

    errors
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
}
