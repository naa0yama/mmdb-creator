//! High-level xlsx import orchestration: read, filter, and write.

use std::path::PathBuf;

use anyhow::Result;
use ipnet::IpNet;
use mmdb_core::config::SheetConfig;

use crate::{SheetResult, filter, reader, writer};

/// Options for the xlsx import operation.
#[derive(Debug)]
pub struct XlsxImportOptions {
    /// Optional CIDR filters; when `Some`, only matching rows are kept.
    pub ip_filter: Option<Vec<IpNet>>,
    /// Path to write the output JSONL file.
    pub output_path: PathBuf,
}

/// Read all configured sheets, optionally filter by CIDR, and write to JSONL.
///
/// Errors from individual sheets are logged and skipped rather than aborting.
/// The caller is responsible for backup rotation before calling this function.
///
/// # Errors
///
/// Returns an error if JSONL writing fails.
pub async fn import(
    sheets: &[SheetConfig],
    options: XlsxImportOptions,
) -> Result<Vec<SheetResult>> {
    let mut all_results: Vec<SheetResult> = Vec::new();

    for sheet_config in sheets {
        match reader::read_xlsx(sheet_config) {
            Ok(results) => {
                for result in &results {
                    tracing::info!(
                        file = %sheet_config.filename.display(),
                        sheet = %result.sheetname,
                        rows = result.rows.len(),
                        skipped = result.skipped_count,
                        "xlsx import complete"
                    );
                }
                all_results.extend(results);
            }
            Err(e) => {
                tracing::error!(
                    file = %sheet_config.filename.display(),
                    error = %e,
                    "xlsx import failed"
                );
            }
        }
    }

    let filtered = if let Some(ref filters) = options.ip_filter {
        filter::filter_by_cidr(all_results, filters)
    } else {
        all_results
    };

    if !filtered.is_empty() {
        writer::write_jsonl(&filtered, &options.output_path).await?;
        tracing::info!(
            records = filtered.iter().map(|s| s.rows.len()).sum::<usize>(),
            path = %options.output_path.display(),
            "xlsx: saved"
        );
    }

    Ok(filtered)
}
