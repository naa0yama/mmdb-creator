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
    let all = sankey::build_all(records);
    let json = serde_json::to_string(&all)?;
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
        assert!(
            html.contains(r#""device_role""#),
            "must contain device_role key in JSON"
        );
        assert!(
            html.contains(r#""facility""#),
            "must contain facility key in JSON"
        );
        assert!(
            html.contains(r#""interface""#),
            "must contain interface key in JSON"
        );
        assert!(html.contains(r#""ptr""#), "must contain ptr key in JSON");
        Ok(())
    }
}
