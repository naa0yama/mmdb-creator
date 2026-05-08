//! Integration tests for `mmdb-xlsx` using the real sample xlsx file.
//!
//! Tests run from the workspace root, so paths like
//! `"data/exsample/IPAM_20260401r3.xlsx"` work directly.

#![allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use mmdb_core::config::{ColumnMapping, ColumnType, SheetConfig};
use mmdb_xlsx::{CellValue, inspect_sheets, read_xlsx};

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

/// Returns the workspace root by walking up from `CARGO_MANIFEST_DIR`.
fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the package root (crates/mmdb-xlsx).
    // The workspace root is two levels up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn test_config() -> SheetConfig {
    SheetConfig {
        filename: workspace_root().join("data/exsample/IPAM_20260401r3.xlsx"),
        excludes_sheets: vec![],
        header_row: 3, // 1-indexed: row 3 = 0-indexed row 2 = the header row
        columns: vec![
            ColumnMapping {
                name: "site".to_owned(),
                sheet_name: "site".to_owned(),
                col_type: ColumnType::String,
            },
            ColumnMapping {
                name: "host".to_owned(),
                sheet_name: "host".to_owned(),
                col_type: ColumnType::String,
            },
            ColumnMapping {
                name: "vlanid".to_owned(),
                sheet_name: "VLANID".to_owned(),
                col_type: ColumnType::Integer,
            },
            ColumnMapping {
                name: "demarc_addresses".to_owned(),
                sheet_name: "DEMARC addresses".to_owned(),
                col_type: ColumnType::Addresses,
            },
            ColumnMapping {
                name: "use".to_owned(),
                sheet_name: "use".to_owned(),
                col_type: ColumnType::Bool,
            },
        ],
    }
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[test]
fn reads_sample_xlsx_sheet_count() {
    let results = read_xlsx(&test_config()).unwrap();
    assert_eq!(
        results.len(),
        2,
        "expected two sheets (border1.ty1, border1.ty2)"
    );
}

#[test]
fn reads_sample_xlsx_row_count() {
    let results = read_xlsx(&test_config()).unwrap();
    // Rows 3-5 (xlsx) have VLANID + use populated and parse successfully.
    // Row 6 (xlsx) has empty VLANID and use columns, so it is skipped by the reader.
    assert_eq!(
        results[0].rows.len(),
        3,
        "expected 3 successfully parsed data rows"
    );
    assert_eq!(
        results[0].skipped_count, 1,
        "expected 1 skipped row (row 6 with empty integer/bool cells)"
    );
}

#[test]
fn reads_sample_xlsx_sheetname() {
    let results = read_xlsx(&test_config()).unwrap();
    assert_eq!(results[0].sheetname, "border1.ty1");
}

#[test]
fn reads_sample_xlsx_string_field() {
    let results = read_xlsx(&test_config()).unwrap();
    assert_eq!(
        results[0].rows[0].fields["site"],
        CellValue::String("TY1".to_owned()),
    );
}

#[test]
fn reads_sample_xlsx_integer_field() {
    let results = read_xlsx(&test_config()).unwrap();
    assert_eq!(
        results[0].rows[0].fields["vlanid"],
        CellValue::Integer(4000),
    );
}

#[test]
fn reads_sample_xlsx_bool_field() {
    let results = read_xlsx(&test_config()).unwrap();
    assert_eq!(results[0].rows[0].fields["use"], CellValue::Bool(true));
}

#[test]
fn reads_sample_xlsx_addresses_comma_separated() {
    // Row 0 (xlsx data row 3): "192.0.2.0/30, 2001:db8::/64"
    let results = read_xlsx(&test_config()).unwrap();
    let field = &results[0].rows[0].fields["demarc_addresses"];
    match field {
        CellValue::Addresses(v) => {
            assert_eq!(v.len(), 2, "expected 2 addresses in comma-separated cell");
        }
        other => panic!("expected CellValue::Addresses, got {other:?}"),
    }
}

#[test]
fn reads_sample_xlsx_addresses_newline_separated() {
    // Row 1 (xlsx data row 4): "192.0.2.0/30\n2001:db8::/64"
    let results = read_xlsx(&test_config()).unwrap();
    let field = &results[0].rows[1].fields["demarc_addresses"];
    match field {
        CellValue::Addresses(v) => {
            assert_eq!(v.len(), 2, "expected 2 addresses in newline-separated cell");
        }
        other => panic!("expected CellValue::Addresses, got {other:?}"),
    }
}

#[test]
fn reads_sample_xlsx_addresses_vip_annotation() {
    // Row 2 (xlsx data row 5): demarc = "192.0.2.0/30,\n2001:db8::/64" → 2 addresses.
    // This exercises the comma+newline separator that appears in the last parseable data row.
    // (Row 6 in the xlsx, which contains a VIP annotation in PE addresses, is skipped because
    //  its VLANID and use columns are empty and cannot be parsed as Integer/Bool.)
    let results = read_xlsx(&test_config()).unwrap();
    let field = &results[0].rows[2].fields["demarc_addresses"];
    match field {
        CellValue::Addresses(v) => {
            assert_eq!(
                v.len(),
                2,
                "expected 2 addresses in comma+newline separated cell"
            );
        }
        other => panic!("expected CellValue::Addresses, got {other:?}"),
    }
}

#[test]
fn inspect_sheets_returns_sheet_names_and_headers() {
    let config = SheetConfig {
        filename: workspace_root().join("data/exsample/IPAM_20260401r3.xlsx"),
        excludes_sheets: vec![],
        header_row: 3,
        columns: vec![], // inspect_sheets doesn't need columns
    };
    let sheets = inspect_sheets(&config).unwrap();
    assert_eq!(sheets.len(), 2);
    let names: Vec<&str> = sheets.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"border1.ty1"));
    assert!(names.contains(&"border1.ty2"));
    // Each sheet has the same header structure
    for sheet in &sheets {
        assert!(sheet.headers.len() >= 10);
        assert!(sheet.headers.contains(&"site".to_owned()));
        assert!(sheet.headers.contains(&"DEMARC addresses".to_owned()));
    }
}

#[test]
fn excludes_sheets_filters_correctly() {
    let config = SheetConfig {
        filename: workspace_root().join("data/exsample/IPAM_20260401r3.xlsx"),
        excludes_sheets: vec!["border1.ty1".to_owned(), "border1.ty2".to_owned()],
        header_row: 3,
        columns: vec![],
    };
    let result = read_xlsx(&config);
    assert!(
        result.is_err(),
        "expected Err when all sheets are excluded, got Ok"
    );
}
