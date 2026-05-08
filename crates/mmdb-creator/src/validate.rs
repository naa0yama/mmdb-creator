//! Validate subcommand: config validation and sheet scaffolding.

use anyhow::Result;
use mmdb_core::config::Config;

/// Run config validation and optionally emit an `--init-sheets` TOML scaffold.
///
/// # Errors
///
/// Returns an error if the config fails validation (missing files, bad `header_row`,
/// duplicate column names, or empty whois server).
// NOTEST(io): checks file existence on disk and writes to stdout — depends on filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::print_stdout)]
pub fn run(config: &Config, init_sheets: bool) -> Result<()> {
    // -------------------------------------------------------------------------
    // Part A — Config validation (always runs)
    // -------------------------------------------------------------------------
    let mut errors: Vec<String> = Vec::new();

    // Check [whois] section.
    if let Some(whois) = &config.whois
        && whois.server.trim().is_empty()
    {
        errors.push("whois.server is empty".to_owned());
    }

    // Check [[sheets]] entries.
    if let Some(sheets) = &config.sheets {
        for (idx, sheet) in sheets.iter().enumerate() {
            // filename exists on disk
            if !sheet.filename.exists() {
                errors.push(format!(
                    "sheets[{idx}].filename '{}' does not exist",
                    sheet.filename.display()
                ));
            }

            // header_row >= 1
            if sheet.header_row < 1 {
                errors.push(format!("sheets[{idx}].header_row must be >= 1"));
            }

            // columns names are unique within the sheet
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

    if !errors.is_empty() {
        println!("Config validation failed:");
        for e in &errors {
            println!("  - {e}");
        }
        return Err(anyhow::anyhow!("config validation failed"));
    }

    tracing::info!("config validation passed");
    println!("✓ config is valid");

    // -------------------------------------------------------------------------
    // Part B — --init-sheets output (only when init_sheets == true)
    // -------------------------------------------------------------------------
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

        // Build available sheet names and excludes for the header comment.
        let available: Vec<String> = sheet_infos.iter().map(|s| s.name.clone()).collect();
        let excludes = &sheet_config.excludes_sheets;

        // Format as TOML arrays.
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

        // Deduplicate columns across sheets by sheet_name (header text).
        let mut seen_headers: std::collections::HashSet<String> = std::collections::HashSet::new();

        for sheet_info in &sheet_infos {
            println!();
            println!("# --- Sheet: {} ---", sheet_info.name);

            for header in &sheet_info.headers {
                if !seen_headers.insert(header.clone()) {
                    // Deduplicated — already emitted for a previous sheet.
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
    use super::{format_toml_string_array, to_snake_case};

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
