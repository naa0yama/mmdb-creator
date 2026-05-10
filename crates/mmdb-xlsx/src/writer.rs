//! Writer for `xlsx-rows.jsonl` produced during the import step.

use std::path::Path;

use anyhow::{Context as _, Result};
use indexmap::IndexMap;
use serde::Serialize;
use tokio::io::AsyncWriteExt as _;

use crate::reader::{CellValue, SheetResult};

// -------------------------------------------------------------------------------------------------
// Row format
// -------------------------------------------------------------------------------------------------

/// Provenance metadata embedded in every `xlsx-rows.jsonl` line.
#[derive(Debug, Serialize)]
struct XlsxSource {
    file: String,
    sheet: String,
    row_index: usize,
}

/// One line in `xlsx-rows.jsonl`.
#[derive(Debug, Serialize)]
struct XlsxJsonlRow {
    #[serde(rename = "_source")]
    source: XlsxSource,
    #[serde(flatten)]
    fields: IndexMap<String, CellValue>,
}

// -------------------------------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------------------------------

/// Write all [`SheetResult`]s to `path` as JSONL.
///
/// The write is atomic: data is written to a `.tmp` file first, then
/// renamed to `path`. The caller is responsible for backup rotation
/// before invoking this function.
///
/// # Errors
///
/// Returns an error if directory creation, serialisation, or I/O fails.
// NOTEST(io): writes JSONL file to filesystem — integration-tested via write_and_read_back
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn write_jsonl(results: &[SheetResult], path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let tmp_path = path.with_extension("jsonl.tmp");
    let mut file = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("failed to create {}", tmp_path.display()))?;

    for sheet in results {
        for row in &sheet.rows {
            let record = XlsxJsonlRow {
                source: XlsxSource {
                    file: sheet.filename.clone(),
                    sheet: sheet.sheetname.clone(),
                    row_index: row.row_index,
                },
                fields: row.fields.clone(),
            };
            let line = serde_json::to_string(&record).with_context(|| {
                format!(
                    "failed to serialise row {} from sheet '{}'",
                    row.row_index, sheet.sheetname
                )
            })?;
            file.write_all(line.as_bytes())
                .await
                .context("failed to write xlsx JSONL line")?;
            file.write_all(b"\n")
                .await
                .context("failed to write newline")?;
        }
    }

    file.flush()
        .await
        .context("failed to flush xlsx-rows.jsonl")?;
    drop(file);

    tokio::fs::rename(&tmp_path, path).await.with_context(|| {
        format!(
            "failed to atomically rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use indexmap::IndexMap;
    use ipnet::IpNet;
    use serde_json::Value;
    use tempfile::TempDir;

    use super::{XlsxJsonlRow, XlsxSource};
    use crate::reader::{CellValue, SheetResult, XlsxRow};

    fn make_row(row_index: usize, fields: &[(&str, CellValue)]) -> XlsxRow {
        XlsxRow {
            row_index,
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        }
    }

    fn make_sheet(filename: &str, sheetname: &str, rows: Vec<XlsxRow>) -> SheetResult {
        SheetResult {
            filename: filename.to_owned(),
            sheetname: sheetname.to_owned(),
            last_modified: None,
            rows,
            skipped_count: 0,
        }
    }

    // --- XlsxJsonlRow serialisation ---

    #[test]
    fn json_row_has_source_and_fields() {
        let mut fields = IndexMap::new();
        fields.insert("host".to_owned(), CellValue::String("rtr0101".to_owned()));
        fields.insert("port".to_owned(), CellValue::String("xe-0/0/1".to_owned()));

        let row = XlsxJsonlRow {
            source: XlsxSource {
                file: "IPAM.xlsx".to_owned(),
                sheet: "border1.ty1".to_owned(),
                row_index: 3,
            },
            fields,
        };
        let json: Value = serde_json::from_str(&serde_json::to_string(&row).unwrap()).unwrap();
        assert_eq!(json["_source"]["file"], "IPAM.xlsx");
        assert_eq!(json["_source"]["sheet"], "border1.ty1");
        assert_eq!(json["_source"]["row_index"], 3);
        assert_eq!(json["host"], "rtr0101");
        assert_eq!(json["port"], "xe-0/0/1");
    }

    #[test]
    fn cell_value_string_serializes_as_json_string() {
        let v = CellValue::String("hello".to_owned());
        let json: Value = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(json, Value::String("hello".to_owned()));
    }

    #[test]
    fn cell_value_integer_serializes_as_json_number() {
        let v = CellValue::Integer(42);
        let json: Value = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(json, serde_json::json!(42));
    }

    #[test]
    fn cell_value_bool_serializes_as_json_bool() {
        let v = CellValue::Bool(true);
        let json: Value = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(json, Value::Bool(true));
    }

    #[test]
    fn cell_value_addresses_serializes_as_cidr_array() {
        let nets: Vec<IpNet> = vec!["198.51.100.0/29".parse().unwrap()];
        let v = CellValue::Addresses(nets);
        let json: Value = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(json, serde_json::json!(["198.51.100.0/29"]));
    }

    // --- write_jsonl integration (tempdir) ---

    #[tokio::test]
    async fn write_and_read_back() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("xlsx-rows.jsonl");

        let row = make_row(
            0,
            &[
                ("host", CellValue::String("rtr0101".to_owned())),
                (
                    "network",
                    CellValue::Addresses(vec!["198.51.100.0/29".parse().unwrap()]),
                ),
            ],
        );
        let sheet = make_sheet("IPAM.xlsx", "border1.ty1", vec![row]);

        super::write_jsonl(&[sheet], &path).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["_source"]["file"], "IPAM.xlsx");
        assert_eq!(parsed["_source"]["sheet"], "border1.ty1");
        assert_eq!(parsed["host"], "rtr0101");
        assert_eq!(parsed["network"], serde_json::json!(["198.51.100.0/29"]));
    }

    #[tokio::test]
    async fn write_multiple_sheets() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("xlsx-rows.jsonl");

        let sheets = vec![
            make_sheet(
                "A.xlsx",
                "sheet1",
                vec![make_row(
                    0,
                    &[("col", CellValue::String("val1".to_owned()))],
                )],
            ),
            make_sheet(
                "A.xlsx",
                "sheet2",
                vec![
                    make_row(0, &[("col", CellValue::String("val2".to_owned()))]),
                    make_row(1, &[("col", CellValue::String("val3".to_owned()))]),
                ],
            ),
        ];

        super::write_jsonl(&sheets, &path).await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content.lines().count(), 3);
    }
}
