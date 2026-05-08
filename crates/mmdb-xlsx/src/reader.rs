//! Excel workbook reader that maps sheets to typed rows.
//!
//! The main entry point is [`read_xlsx`], which opens an `.xlsx` file,
//! iterates over the non-excluded sheets, and returns a [`SheetResult`] for
//! each sheet containing the parsed [`XlsxRow`] values.

use std::collections::HashMap;

use anyhow::{Context as _, anyhow};
use calamine::{Data, Range, Reader, Xlsx, open_workbook};
use indexmap::IndexMap;
use ipnet::IpNet;
use mmdb_core::config::{ColumnMapping, ColumnType, SheetConfig};

use crate::address::parse_addresses;

// -------------------------------------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------------------------------------

/// Metadata discovered from one sheet without full data parsing.
#[derive(Debug, Clone)]
pub struct SheetInfo {
    /// Sheet name in the workbook.
    pub name: String,
    /// Column header texts from the configured header row (non-empty cells only).
    pub headers: Vec<String>,
}

/// A single typed cell value produced from an Excel cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellValue {
    /// UTF-8 string.
    String(std::string::String),
    /// 64-bit integer.
    Integer(i64),
    /// Boolean.
    Bool(bool),
    /// One or more parsed IP network prefixes.
    Addresses(Vec<IpNet>),
}

/// A single data row parsed from an Excel sheet.
#[derive(Debug, Clone)]
pub struct XlsxRow {
    /// 0-indexed row offset from the first data row (i.e. the row after the header).
    pub row_index: usize,
    /// Ordered map from output field name to typed value.
    pub fields: IndexMap<std::string::String, CellValue>,
}

/// Parsed output for a single Excel sheet.
#[derive(Debug, Clone)]
pub struct SheetResult {
    /// Filename of the source workbook.
    pub filename: std::string::String,
    /// Sheet name within the workbook.
    pub sheetname: std::string::String,
    /// ISO-8601 last-modified timestamp of the file, if known.
    pub last_modified: Option<std::string::String>,
    /// Successfully parsed rows.
    pub rows: Vec<XlsxRow>,
    /// Number of rows that were skipped due to parse errors.
    pub skipped_count: usize,
}

// -------------------------------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------------------------------

/// Open `config.filename` and parse all non-excluded sheets according to `config`.
///
/// `last_modified` is derived from the file's mtime and formatted as ISO 8601 UTC.
///
/// # Errors
///
/// Returns an error if the workbook cannot be opened, or if every sheet is
/// excluded by `config.excludes_sheets`.
pub fn read_xlsx(config: &SheetConfig) -> anyhow::Result<Vec<SheetResult>> {
    let last_modified = std::fs::metadata(&config.filename)
        .and_then(|m| m.modified())
        .ok()
        .map(format_system_time);

    let mut wb: Xlsx<_> = open_workbook(&config.filename)
        .with_context(|| format!("failed to open {}", config.filename.display()))?;

    let filename = config.filename.file_name().map_or_else(
        || config.filename.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    );

    // Collect sheet names once to avoid borrow issues.
    let sheet_names: Vec<std::string::String> = wb.sheet_names();

    let filtered: Vec<std::string::String> = sheet_names
        .into_iter()
        .filter(|name| !config.excludes_sheets.contains(name))
        .collect();

    if filtered.is_empty() {
        return Err(anyhow!("no sheets to process after filtering"));
    }

    let mut results = Vec::with_capacity(filtered.len());

    for sheetname in &filtered {
        let range: Range<Data> = wb
            .worksheet_range(sheetname)
            .with_context(|| format!("failed to read sheet '{sheetname}'"))?;
        let result = read_sheet(&range, config, &filename, sheetname, last_modified.clone())
            .with_context(|| format!("failed to parse sheet '{sheetname}'"))?;
        results.push(result);
    }

    Ok(results)
}

/// Open an xlsx file and return sheet names + header columns for each sheet.
///
/// Filtered by `config.excludes_sheets`. Header row is `config.header_row`
/// (1-indexed). Returns one `SheetInfo` per processed sheet.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or no sheets remain after filtering.
pub fn inspect_sheets(config: &SheetConfig) -> anyhow::Result<Vec<SheetInfo>> {
    let mut wb: Xlsx<_> = open_workbook(&config.filename)
        .with_context(|| format!("failed to open {}", config.filename.display()))?;

    let names: Vec<std::string::String> = wb
        .sheet_names()
        .into_iter()
        .filter(|n| !config.excludes_sheets.contains(n))
        .collect();

    if names.is_empty() {
        anyhow::bail!("no sheets remain after filtering excludes_sheets");
    }

    // REASON: header_row is u32, and usize is >= u32 on all supported targets.
    #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
    let header_row_idx = (config.header_row as usize).saturating_sub(1);

    let mut result = Vec::new();
    for name in &names {
        let range = wb
            .worksheet_range(name)
            .with_context(|| format!("failed to read sheet '{name}'"))?;

        let headers: Vec<std::string::String> = range
            .rows()
            .nth(header_row_idx)
            .map(|row| {
                row.iter()
                    .filter_map(|cell| match cell {
                        Data::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        result.push(SheetInfo {
            name: name.clone(),
            headers,
        });
    }

    Ok(result)
}

// -------------------------------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------------------------------

/// Format a [`std::time::SystemTime`] as an ISO 8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Uses a pure-integer Gregorian calendar calculation (Howard Hinnant algorithm)
/// so that `chrono` is not required as a dependency.
fn format_system_time(t: std::time::SystemTime) -> std::string::String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert days since the Unix epoch (1970-01-01) to a `(year, month, day)` triple.
///
/// Uses the Howard Hinnant civil-calendar algorithm.
#[allow(clippy::arithmetic_side_effects)] // REASON: algorithm operates on bounded calendar values; overflow is impossible for valid Unix timestamps.
const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Parse a single sheet range into a [`SheetResult`].
///
/// # Errors
///
/// Returns an error if all data rows in the sheet fail to parse.
fn read_sheet(
    range: &Range<Data>,
    config: &SheetConfig,
    filename: &str,
    sheetname: &str,
    last_modified: Option<std::string::String>,
) -> anyhow::Result<SheetResult> {
    // REASON: header_row is u32, and usize is >= u32 on all supported targets.
    #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
    let header_row_idx = (config.header_row as usize).saturating_sub(1);
    #[allow(clippy::arithmetic_side_effects)]
    // REASON: saturating_sub guarantees header_row_idx < usize::MAX.
    let data_start = header_row_idx + 1;

    // Build header → column-index map from the header row.
    let header_map: HashMap<std::string::String, usize> = range
        .rows()
        .nth(header_row_idx)
        .map(|row| {
            row.iter()
                .enumerate()
                .filter_map(|(col_idx, cell)| {
                    let text = cell_to_string(cell)?;
                    Some((text, col_idx))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut rows: Vec<XlsxRow> = Vec::new();
    let mut skipped_count: usize = 0;

    for (row_offset, row) in range.rows().skip(data_start).enumerate() {
        match parse_row(row, &header_map, &config.columns, sheetname, row_offset) {
            Ok(xlsx_row) => rows.push(xlsx_row),
            Err(e) => {
                #[allow(clippy::arithmetic_side_effects)]
                // REASON: row_offset is bounded by worksheet row count; overflow is impossible.
                let row_num = row_offset + 1;
                tracing::warn!(
                    sheet = sheetname,
                    row = row_num,
                    error = %e,
                    "skipping row"
                );
                skipped_count = skipped_count.saturating_add(1);
            }
        }
    }

    if rows.is_empty() && skipped_count > 0 {
        anyhow::bail!("all {skipped_count} data rows in sheet '{sheetname}' failed to parse");
    }

    Ok(SheetResult {
        filename: filename.to_owned(),
        sheetname: sheetname.to_owned(),
        last_modified,
        rows,
        skipped_count,
    })
}

/// Parse one data row into an [`XlsxRow`].
///
/// # Errors
///
/// Returns an error if any required column cell cannot be converted to its
/// declared [`ColumnType`].
fn parse_row(
    row: &[Data],
    header_map: &HashMap<std::string::String, usize>,
    columns: &[ColumnMapping],
    sheetname: &str,
    row_index: usize,
) -> anyhow::Result<XlsxRow> {
    let mut fields: IndexMap<std::string::String, CellValue> =
        IndexMap::with_capacity(columns.len());

    for mapping in columns {
        let name = &mapping.sheet_name;
        let value = match header_map.get(name) {
            None => {
                tracing::warn!(
                    sheet = sheetname,
                    column = %name,
                    "column header not found in sheet; using empty string"
                );
                CellValue::String(std::string::String::new())
            }
            Some(&col_idx) => {
                let data = row.get(col_idx).unwrap_or(&Data::Empty);
                #[allow(clippy::arithmetic_side_effects)]
                // REASON: row_index is bounded by worksheet row count; overflow is impossible.
                let row_num = row_index + 1;
                // ast-grep-ignore: error-context-required
                parse_cell(data, &mapping.col_type)
                    .map_err(|e| anyhow!("column '{name}' row {row_num}: {e}"))?
            }
        };
        fields.insert(mapping.name.clone(), value);
    }

    Ok(XlsxRow { row_index, fields })
}

/// Convert a single [`Data`] cell to a [`CellValue`] of the requested type.
///
/// # Errors
///
/// Returns an error if the cell value cannot be converted to the requested
/// [`ColumnType`].
fn parse_cell(data: &Data, col_type: &ColumnType) -> anyhow::Result<CellValue> {
    match col_type {
        ColumnType::String => match data {
            Data::String(s) | Data::DateTimeIso(s) => Ok(CellValue::String(s.trim().to_owned())),
            Data::Float(f) => Ok(CellValue::String(f.to_string())),
            Data::Int(i) => Ok(CellValue::String(i.to_string())),
            Data::Bool(b) => Ok(CellValue::String(b.to_string())),
            Data::Empty => Ok(CellValue::String(std::string::String::new())),
            other => Err(anyhow!("cannot convert {other:?} to string")),
        },

        ColumnType::Integer => match data {
            Data::Int(i) => Ok(CellValue::Integer(*i)),
            Data::Float(f) => {
                // REASON: intentional truncation — spec says floats are truncated to integer.
                #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
                Ok(CellValue::Integer(f.trunc() as i64))
            }
            Data::String(s) => {
                let trimmed = s.trim();
                trimmed
                    .parse::<i64>()
                    .map(CellValue::Integer)
                    .map_err(|_| anyhow!("cannot parse '{trimmed}' as integer"))
            }
            Data::Bool(b) => Ok(CellValue::Integer(i64::from(*b))),
            Data::Empty => Err(anyhow!("empty cell for integer column")),
            other => Err(anyhow!("cannot convert {other:?} to integer")),
        },

        ColumnType::Bool => match data {
            Data::Bool(b) => Ok(CellValue::Bool(*b)),
            Data::String(s) => match s.trim().to_lowercase().as_str() {
                "true" | "1" => Ok(CellValue::Bool(true)),
                "false" | "0" => Ok(CellValue::Bool(false)),
                other => Err(anyhow!("cannot parse '{other}' as bool")),
            },
            Data::Int(i) => Ok(CellValue::Bool(*i != 0)),
            Data::Empty => Err(anyhow!("empty cell for bool column")),
            other => Err(anyhow!("cannot convert {other:?} to bool")),
        },

        ColumnType::Addresses => match data {
            Data::String(s) | Data::DateTimeIso(s) => {
                let (nets, warn_count) = parse_addresses(s);
                if warn_count > 0 {
                    tracing::warn!(
                        column = s.as_str(),
                        warn_count,
                        "some address tokens could not be parsed"
                    );
                }
                Ok(CellValue::Addresses(nets))
            }
            Data::Empty => Ok(CellValue::Addresses(Vec::new())),
            other => Err(anyhow!("cannot convert {other:?} to addresses")),
        },
    }
}

/// Extract a plain string from a [`Data`] cell, returning `None` for empty cells.
fn cell_to_string(data: &Data) -> Option<std::string::String> {
    match data {
        Data::String(s) | Data::DateTimeIso(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        Data::Float(f) => Some(f.to_string()),
        Data::Int(i) => Some(i.to_string()),
        Data::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use calamine::Data;
    use ipnet::IpNet;

    use super::{CellValue, ColumnType, parse_cell};

    // ---- parse_cell: String ----

    #[test]
    fn parse_cell_string_from_string() {
        let result = parse_cell(&Data::String("hello".to_owned()), &ColumnType::String).unwrap();
        assert_eq!(result, CellValue::String("hello".to_owned()));
    }

    #[test]
    fn parse_cell_string_trims() {
        let result = parse_cell(&Data::String("  hi  ".to_owned()), &ColumnType::String).unwrap();
        assert_eq!(result, CellValue::String("hi".to_owned()));
    }

    // ---- parse_cell: Integer ----

    #[test]
    fn parse_cell_integer_from_int() {
        let result = parse_cell(&Data::Int(42), &ColumnType::Integer).unwrap();
        assert_eq!(result, CellValue::Integer(42));
    }

    #[test]
    fn parse_cell_integer_from_float() {
        let result = parse_cell(&Data::Float(42.0), &ColumnType::Integer).unwrap();
        assert_eq!(result, CellValue::Integer(42));
    }

    // ---- parse_cell: Bool ----

    #[test]
    fn parse_cell_bool_true_literal() {
        let result = parse_cell(&Data::Bool(true), &ColumnType::Bool).unwrap();
        assert_eq!(result, CellValue::Bool(true));
    }

    #[test]
    fn parse_cell_bool_string_true() {
        let result = parse_cell(&Data::String("true".to_owned()), &ColumnType::Bool).unwrap();
        assert_eq!(result, CellValue::Bool(true));
    }

    #[test]
    fn parse_cell_bool_string_true_upper() {
        let result = parse_cell(&Data::String("TRUE".to_owned()), &ColumnType::Bool).unwrap();
        assert_eq!(result, CellValue::Bool(true));
    }

    #[test]
    fn parse_cell_bool_string_zero() {
        let result = parse_cell(&Data::String("0".to_owned()), &ColumnType::Bool).unwrap();
        assert_eq!(result, CellValue::Bool(false));
    }

    #[test]
    fn parse_cell_bool_string_one() {
        let result = parse_cell(&Data::String("1".to_owned()), &ColumnType::Bool).unwrap();
        assert_eq!(result, CellValue::Bool(true));
    }

    // ---- parse_cell: Addresses ----

    #[test]
    fn parse_cell_addresses_cidr() {
        let result = parse_cell(
            &Data::String("192.0.2.0/30".to_owned()),
            &ColumnType::Addresses,
        )
        .unwrap();
        let expected: Vec<IpNet> = ["192.0.2.0/30".parse().unwrap()].to_vec();
        assert_eq!(result, CellValue::Addresses(expected));
    }

    #[test]
    fn parse_cell_addresses_empty() {
        let result = parse_cell(&Data::Empty, &ColumnType::Addresses).unwrap();
        assert_eq!(result, CellValue::Addresses(vec![]));
    }

    // ---- header map indices ----

    #[test]
    fn build_header_map_indices() {
        use std::collections::HashMap;

        use calamine::Data;

        // Simulate a header row: ["Name", "Age", "IP"]
        let header_row = [
            Data::String("Name".to_owned()),
            Data::String("Age".to_owned()),
            Data::String("IP".to_owned()),
        ];

        let header_map: HashMap<String, usize> = header_row
            .iter()
            .enumerate()
            .filter_map(|(i, cell)| {
                if let Data::String(s) = cell {
                    Some((s.trim().to_owned(), i))
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(header_map.get("Name"), Some(&0));
        assert_eq!(header_map.get("Age"), Some(&1));
        assert_eq!(header_map.get("IP"), Some(&2));
        assert_eq!(header_map.get("Missing"), None);
    }
}
