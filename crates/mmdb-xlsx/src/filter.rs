//! CIDR-based row filtering for xlsx sheet results.

use ipnet::IpNet;

use crate::reader::{CellValue, SheetResult, XlsxRow};

/// Filter xlsx sheet results to rows whose `Addresses` fields overlap with any of `filters`.
///
/// A row is kept when at least one `CellValue::Addresses` value has its network address
/// contained within a filter CIDR. Rows with no `Addresses` fields are dropped.
/// Sheets that become empty after filtering are also dropped.
#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn filter_by_cidr(results: Vec<SheetResult>, filters: &[IpNet]) -> Vec<SheetResult> {
    results
        .into_iter()
        .filter_map(|mut sheet| {
            let before = sheet.rows.len();
            sheet.rows.retain(|row| row_matches_any_cidr(row, filters));
            let kept = sheet.rows.len();
            if kept < before {
                tracing::info!(
                    sheet = %sheet.sheetname,
                    before,
                    kept,
                    "xlsx: filtered rows by CIDR"
                );
            }
            if sheet.rows.is_empty() {
                None
            } else {
                Some(sheet)
            }
        })
        .collect()
}

/// Return true if any `Addresses` cell in `row` has a network address within any of `filters`.
fn row_matches_any_cidr(row: &XlsxRow, filters: &[IpNet]) -> bool {
    row.fields.values().any(|val| {
        if let CellValue::Addresses(addrs) = val {
            addrs
                .iter()
                .any(|addr| filters.iter().any(|f| f.contains(&addr.network())))
        } else {
            false
        }
    })
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;
    use ipnet::IpNet;

    use super::{filter_by_cidr, row_matches_any_cidr};
    use crate::reader::{CellValue, SheetResult, XlsxRow};

    fn make_row(addrs: &[&str]) -> XlsxRow {
        let nets: Vec<IpNet> = addrs.iter().map(|s| s.parse().unwrap()).collect();
        let mut fields = IndexMap::new();
        fields.insert("network".to_owned(), CellValue::Addresses(nets));
        XlsxRow {
            row_index: 0,
            fields,
        }
    }

    fn make_sheet(rows: Vec<XlsxRow>) -> SheetResult {
        SheetResult {
            filename: "test.xlsx".to_owned(),
            sheetname: "Sheet1".to_owned(),
            last_modified: None,
            rows,
            skipped_count: 0,
            sheettype: mmdb_core::config::SheetType::Backbone,
        }
    }

    #[test]
    fn row_matches_subnet_within_filter() {
        let row = make_row(&["198.51.100.0/29"]);
        let filters: Vec<IpNet> = vec!["198.51.100.0/24".parse().unwrap()];
        assert!(row_matches_any_cidr(&row, &filters));
    }

    #[test]
    fn row_does_not_match_outside_filter() {
        let row = make_row(&["203.0.113.0/24"]);
        let filters: Vec<IpNet> = vec!["198.51.100.0/24".parse().unwrap()];
        assert!(!row_matches_any_cidr(&row, &filters));
    }

    #[test]
    fn row_with_no_address_field_does_not_match() {
        let mut fields = IndexMap::new();
        fields.insert("host".to_owned(), CellValue::String("router".to_owned()));
        let row = XlsxRow {
            row_index: 0,
            fields,
        };
        let filters: Vec<IpNet> = vec!["198.51.100.0/24".parse().unwrap()];
        assert!(!row_matches_any_cidr(&row, &filters));
    }

    #[test]
    fn filter_keeps_matching_rows_and_drops_others() {
        let row_in = make_row(&["198.51.100.0/29"]);
        let row_out = make_row(&["203.0.113.0/24"]);
        let sheet = make_sheet(vec![row_in, row_out]);
        let filters: Vec<IpNet> = vec!["198.51.100.0/24".parse().unwrap()];

        let result = filter_by_cidr(vec![sheet], &filters);
        assert_eq!(result.len(), 1);
        let kept_sheet = result.first().expect("sheet exists");
        assert_eq!(kept_sheet.rows.len(), 1);
        let kept_row = kept_sheet.rows.first().expect("row exists");
        let net_val = kept_row
            .fields
            .get("network")
            .expect("network field exists");
        assert!(
            matches!(net_val, CellValue::Addresses(a) if a.first().map(ToString::to_string).as_deref() == Some("198.51.100.0/29"))
        );
    }

    #[test]
    fn filter_drops_empty_sheet_after_filtering() {
        let row_out = make_row(&["203.0.113.0/24"]);
        let sheet = make_sheet(vec![row_out]);
        let filters: Vec<IpNet> = vec!["198.51.100.0/24".parse().unwrap()];

        let result = filter_by_cidr(vec![sheet], &filters);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_no_ip_args_returns_all_rows() {
        let row1 = make_row(&["198.51.100.0/29"]);
        let row2 = make_row(&["203.0.113.0/24"]);
        let sheet = make_sheet(vec![row1, row2]);

        let result = filter_by_cidr(vec![sheet], &[]);
        // Empty filter list: no filter CIDRs, so no rows match; sheet is dropped.
        // (Caller only invokes filter_by_cidr when filters is non-empty.)
        assert!(result.is_empty());
    }
}
