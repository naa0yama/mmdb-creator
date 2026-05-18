//! Report generation module.

pub mod sankey;
mod template;

use anyhow::Result;
use mmdb_core::types::ScanGwRecord;

/// Generates a self-contained HTML topology report from scan records.
///
/// # Errors
///
/// Returns an error if JSON serialisation fails.
pub fn generate(records: &[ScanGwRecord]) -> Result<String> {
    let data = sankey::build(records);
    let json = serde_json::to_string(&data)?;
    Ok(template::render(&json))
}

#[cfg(test)]
mod tests {
    use super::generate;
    use crate::report::sankey::tests::make_record;

    #[test]
    fn generate_html_structure() -> anyhow::Result<()> {
        let records = vec![
            make_record("198.51.100.0/24", vec![("198.51.100.1", None)]),
            make_record("198.51.100.128/25", vec![("198.51.100.129", None)]),
        ];
        let html = generate(&records)?;
        assert!(html.contains("<!DOCTYPE html>"), "must be valid HTML");
        assert!(html.contains(r#"data-theme="dark""#), "must use dark theme");
        assert!(html.contains("198.51.100.0/24"), "must contain CIDR");
        assert!(html.contains("SANKEY_DATA"), "must inject sankey data");
        Ok(())
    }
}
