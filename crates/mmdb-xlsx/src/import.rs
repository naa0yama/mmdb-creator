//! High-level xlsx import orchestration: read, filter, validate, and write.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Result;
use ipnet::IpNet;
use mmdb_core::config::{SheetConfig, SheetType};

use crate::{SheetResult, filter, reader, writer};

/// Options for the xlsx import operation.
#[derive(Debug)]
pub struct XlsxImportOptions {
    /// Optional CIDR filters; when `Some`, only matching rows are kept.
    pub ip_filter: Option<Vec<IpNet>>,
    /// Path to write the output JSONL file.
    pub output_path: PathBuf,
}

/// Read all configured sheets, optionally filter by CIDR, validate for
/// duplicate CIDRs within the same sheettype, and write to JSONL.
///
/// Errors from individual sheets are logged and skipped rather than aborting.
/// The caller is responsible for backup rotation before calling this function.
///
/// # Errors
///
/// Returns an error if JSONL writing fails or duplicate CIDRs are detected.
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

    // Validate for duplicate CIDRs within the same sheettype before writing.
    let group_lookup = build_group_lookup(sheets, &filtered)?;
    validate_no_duplicate_cidrs(&filtered, &group_lookup)?;
    log_import_statistics(&filtered);

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

/// Build a lookup table mapping `(filename, sheetname)` → set of group IDs.
///
/// Each inner `Vec` in `sheets[n].groups` defines one redundancy group.
/// Group IDs are assigned globally across all `SheetConfig`s so that groups
/// from different files never collide.
///
/// A sheet may appear in multiple groups (overlapping groups). Two sheets are
/// exempt from duplicate CIDR checks when their group-ID sets intersect — i.e.,
/// they share at least one group in common.
///
/// Also validates that every sheet name referenced in any group is present in
/// `results`. Returns an error listing all unknown sheet names.
///
/// # Errors
///
/// Returns an error if any group references a sheet name not found in `results`.
pub fn build_group_lookup(
    sheets: &[SheetConfig],
    results: &[SheetResult],
) -> Result<HashMap<(String, String), HashSet<usize>>> {
    let mut lookup: HashMap<(String, String), HashSet<usize>> = HashMap::new();
    let mut group_id: usize = 0;
    let mut errors: Vec<String> = Vec::new();

    for sheet_config in sheets {
        let filename = sheet_config
            .filename
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned();

        let actual: HashSet<&str> = results
            .iter()
            .filter(|r| r.filename == filename)
            .map(|r| r.sheetname.as_str())
            .collect();

        for group in &sheet_config.groups {
            for name in group {
                if actual.contains(name.as_str()) {
                    lookup
                        .entry((filename.clone(), name.clone()))
                        .or_default()
                        .insert(group_id);
                } else {
                    errors.push(format!("groups: sheet '{name}' not found in '{filename}'"));
                }
            }
            group_id = group_id.saturating_add(1);
        }
    }

    if errors.is_empty() {
        Ok(lookup)
    } else {
        anyhow::bail!(
            "xlsx import: invalid redundancy group(s):\n  {}",
            errors.join("\n  ")
        )
    }
}

/// Validate that no two rows within the same sheettype share an exact CIDR.
///
/// Containment relationships (e.g. /19 and /20) are intentional and allowed.
/// Only exact duplicates within the same sheettype are rejected.
///
/// Sheets are exempt from duplicate checks when their group-ID sets intersect —
/// i.e., they share at least one common group. A sheet may belong to multiple
/// groups simultaneously (overlapping groups). Two ungrouped sheets (empty set
/// in `group_lookup`) are never exempt.
///
/// # Errors
///
/// Returns an error listing all conflicting CIDRs and their source rows.
pub fn validate_no_duplicate_cidrs<S1, S2>(
    results: &[SheetResult],
    group_lookup: &HashMap<(String, String), HashSet<usize, S2>, S1>,
) -> Result<()>
where
    S1: ::std::hash::BuildHasher,
    S2: ::std::hash::BuildHasher,
{
    let mut backbone_seen: HashMap<IpNet, (String, String, usize, HashSet<usize>)> = HashMap::new();
    let mut hosting_seen: HashMap<IpNet, (String, String, usize, HashSet<usize>)> = HashMap::new();
    let mut errors: Vec<String> = Vec::new();

    for sheet in results {
        let (seen, sheettype_str) = match sheet.sheettype {
            SheetType::Backbone => (&mut backbone_seen, "backbone"),
            SheetType::Hosting => (&mut hosting_seen, "hosting"),
        };
        let cur_groups: HashSet<usize> = group_lookup
            .get(&(sheet.filename.clone(), sheet.sheetname.clone()))
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        for row in &sheet.rows {
            for cell_val in row.fields.values() {
                if let crate::reader::CellValue::Addresses(nets) = cell_val {
                    for net in nets {
                        if let Some((prev_file, prev_sheet, prev_row, prev_groups)) = seen.get(net)
                        {
                            if prev_groups.is_disjoint(&cur_groups) {
                                errors.push(format!(
                                    "duplicate {sheettype_str} CIDR {net}: \
                                    first seen in {prev_file}/{prev_sheet} row {prev_row}, \
                                    conflict in {}/{} row {}",
                                    sheet.filename, sheet.sheetname, row.row_index
                                ));
                            }
                        } else {
                            seen.insert(
                                *net,
                                (
                                    sheet.filename.clone(),
                                    sheet.sheetname.clone(),
                                    row.row_index,
                                    cur_groups.clone(),
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "xlsx import: {} duplicate CIDR(s) detected:\n  {}",
            errors.len(),
            errors.join("\n  ")
        )
    }
}

fn log_import_statistics(results: &[SheetResult]) {
    let mut backbone_sheets = 0usize;
    let mut backbone_rows = 0usize;
    let mut hosting_sheets = 0usize;
    let mut hosting_rows = 0usize;

    for sheet in results {
        match sheet.sheettype {
            SheetType::Backbone => {
                backbone_sheets = backbone_sheets.saturating_add(1);
                backbone_rows = backbone_rows.saturating_add(sheet.rows.len());
            }
            SheetType::Hosting => {
                hosting_sheets = hosting_sheets.saturating_add(1);
                hosting_rows = hosting_rows.saturating_add(sheet.rows.len());
            }
        }
    }

    tracing::info!(
        backbone_sheets,
        backbone_rows,
        hosting_sheets,
        hosting_rows,
        "xlsx import statistics: no conflicts detected"
    );
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{HashMap, HashSet};

    use indexmap::IndexMap;
    use ipnet::IpNet;
    use mmdb_core::config::SheetType;

    use super::{build_group_lookup, validate_no_duplicate_cidrs};
    use crate::reader::{CellValue, SheetResult, XlsxRow};

    fn no_groups() -> HashMap<(String, String), HashSet<usize>> {
        HashMap::new()
    }

    fn make_row(row_index: usize, nets: &[&str]) -> XlsxRow {
        let parsed: Vec<IpNet> = nets.iter().map(|s| s.parse().unwrap()).collect();
        let mut fields = IndexMap::new();
        fields.insert("network".to_owned(), CellValue::Addresses(parsed));
        XlsxRow { row_index, fields }
    }

    fn make_sheet(filename: &str, sheettype: SheetType, rows: Vec<XlsxRow>) -> SheetResult {
        make_sheet_named(filename, "Sheet1", sheettype, rows)
    }

    fn make_sheet_named(
        filename: &str,
        sheetname: &str,
        sheettype: SheetType,
        rows: Vec<XlsxRow>,
    ) -> SheetResult {
        SheetResult {
            filename: filename.to_owned(),
            sheetname: sheetname.to_owned(),
            last_modified: None,
            rows,
            skipped_count: 0,
            sheettype,
        }
    }

    fn group_lookup(groups: &[(&str, &[&str])]) -> HashMap<(String, String), HashSet<usize>> {
        let mut lookup: HashMap<(String, String), HashSet<usize>> = HashMap::new();
        for (gid, (file, sheets)) in groups.iter().enumerate() {
            for sheet in *sheets {
                lookup
                    .entry(((*file).to_owned(), (*sheet).to_owned()))
                    .or_default()
                    .insert(gid);
            }
        }
        lookup
    }

    // ── existing behaviour (no groups) ───────────────────────────────────────

    #[test]
    fn no_duplicates_ok() {
        let sheets = vec![
            make_sheet(
                "A.xlsx",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet(
                "B.xlsx",
                SheetType::Hosting,
                vec![make_row(0, &["198.51.100.1/32"])],
            ),
        ];
        assert!(validate_no_duplicate_cidrs(&sheets, &no_groups()).is_ok());
    }

    #[test]
    fn backbone_containment_is_not_an_error() {
        // /24 and /20 overlap but are not exact duplicates
        let sheets = vec![make_sheet(
            "A.xlsx",
            SheetType::Backbone,
            vec![
                make_row(0, &["198.51.96.0/20"]),
                make_row(1, &["198.51.100.0/24"]),
            ],
        )];
        assert!(validate_no_duplicate_cidrs(&sheets, &no_groups()).is_ok());
    }

    #[test]
    fn hosting_exact_duplicate_is_error() {
        let sheets = vec![
            make_sheet(
                "B1.xlsx",
                SheetType::Hosting,
                vec![make_row(0, &["198.51.100.1/32"])],
            ),
            make_sheet(
                "B2.xlsx",
                SheetType::Hosting,
                vec![make_row(0, &["198.51.100.1/32"])],
            ),
        ];
        let result = validate_no_duplicate_cidrs(&sheets, &no_groups());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("hosting") && msg.contains("198.51.100.1/32"));
    }

    #[test]
    fn backbone_exact_duplicate_is_error() {
        let sheets = vec![
            make_sheet(
                "A1.xlsx",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet(
                "A2.xlsx",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        let result = validate_no_duplicate_cidrs(&sheets, &no_groups());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("backbone") && msg.contains("198.51.100.0/24"));
    }

    #[test]
    fn cross_sheettype_duplicates_are_ok() {
        // Same CIDR in backbone and hosting is not a conflict
        let sheets = vec![
            make_sheet(
                "A.xlsx",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet(
                "B.xlsx",
                SheetType::Hosting,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        assert!(validate_no_duplicate_cidrs(&sheets, &no_groups()).is_ok());
    }

    #[test]
    fn duplicate_within_same_sheet_is_error() {
        // Two rows in the same hosting sheet with the same /32
        let sheets = vec![make_sheet(
            "B.xlsx",
            SheetType::Hosting,
            vec![
                make_row(0, &["198.51.100.1/32"]),
                make_row(1, &["198.51.100.1/32"]),
            ],
        )];
        let result = validate_no_duplicate_cidrs(&sheets, &no_groups());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("198.51.100.1/32"));
    }

    #[test]
    fn empty_results_is_ok() {
        assert!(validate_no_duplicate_cidrs(&[], &no_groups()).is_ok());
    }

    #[test]
    fn multiple_hosting_distinct_cidrs_ok() {
        let sheets = vec![make_sheet(
            "B.xlsx",
            SheetType::Hosting,
            vec![
                make_row(0, &["198.51.100.1/32"]),
                make_row(1, &["198.51.100.2/32"]),
                make_row(2, &["198.51.100.3/32"]),
            ],
        )];
        assert!(validate_no_duplicate_cidrs(&sheets, &no_groups()).is_ok());
    }

    #[test]
    fn multiple_errors_reported_together() {
        // Two distinct duplicate pairs
        let sheets = vec![
            make_sheet(
                "B1.xlsx",
                SheetType::Hosting,
                vec![
                    make_row(0, &["198.51.100.1/32"]),
                    make_row(1, &["198.51.100.2/32"]),
                ],
            ),
            make_sheet(
                "B2.xlsx",
                SheetType::Hosting,
                vec![
                    make_row(0, &["198.51.100.1/32"]),
                    make_row(1, &["198.51.100.2/32"]),
                ],
            ),
        ];
        let result = validate_no_duplicate_cidrs(&sheets, &no_groups());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("2 duplicate"));
    }

    #[test]
    fn backbone_cidr_plus_bgp_supernet_is_ok() {
        // /19 and /20 coexist as backbone — containment, not exact dup
        let sheets = vec![
            make_sheet(
                "A1.xlsx",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.96.0/19"])],
            ),
            make_sheet(
                "A2.xlsx",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.96.0/20"])],
            ),
        ];
        assert!(validate_no_duplicate_cidrs(&sheets, &no_groups()).is_ok());
    }

    // ── redundancy group behaviour ────────────────────────────────────────────

    #[test]
    fn same_group_allows_duplicates() {
        let lookup = group_lookup(&[("IPAM", &["border1", "border2"])]);
        let sheets = vec![
            make_sheet_named(
                "IPAM",
                "border1",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "border2",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        assert!(validate_no_duplicate_cidrs(&sheets, &lookup).is_ok());
    }

    #[test]
    fn same_group_three_sheets_allows_duplicates() {
        let lookup = group_lookup(&[("IPAM", &["border1", "border2", "border3"])]);
        let sheets = vec![
            make_sheet_named(
                "IPAM",
                "border1",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "border2",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "border3",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        assert!(validate_no_duplicate_cidrs(&sheets, &lookup).is_ok());
    }

    #[test]
    fn different_groups_same_cidr_is_error() {
        let lookup = group_lookup(&[
            ("IPAM", &["border1", "border2"]),
            ("IPAM", &["core1", "core2"]),
        ]);
        let sheets = vec![
            make_sheet_named(
                "IPAM",
                "border1",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "core1",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        let result = validate_no_duplicate_cidrs(&sheets, &lookup);
        assert!(result.is_err());
    }

    #[test]
    fn ungrouped_duplicate_is_error() {
        let sheets = vec![
            make_sheet_named(
                "IPAM",
                "border1",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "border2",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        let result = validate_no_duplicate_cidrs(&sheets, &no_groups());
        assert!(result.is_err());
    }

    #[test]
    fn grouped_vs_ungrouped_duplicate_is_error() {
        let lookup = group_lookup(&[("IPAM", &["border1", "border2"])]);
        let sheets = vec![
            make_sheet_named(
                "IPAM",
                "border1",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "stray",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        let result = validate_no_duplicate_cidrs(&sheets, &lookup);
        assert!(result.is_err());
    }

    // ── build_group_lookup ────────────────────────────────────────────────────

    #[test]
    fn build_group_lookup_unknown_sheet_is_error() {
        use mmdb_core::config::{SheetConfig, SheetType as ST};

        let sheets = vec![SheetConfig {
            filename: "IPAM.xlsx".into(),
            excludes_sheets: vec![],
            header_row: 1,
            columns: vec![],
            sheettype: ST::Backbone,
            groups: vec![vec!["border1".to_owned(), "typo_sheet".to_owned()]],
        }];
        let results = vec![make_sheet_named(
            "IPAM.xlsx",
            "border1",
            SheetType::Backbone,
            vec![],
        )];
        let err = build_group_lookup(&sheets, &results).unwrap_err();
        assert!(err.to_string().contains("typo_sheet"));
    }

    #[test]
    fn build_group_lookup_empty_groups_is_ok() {
        use mmdb_core::config::{SheetConfig, SheetType as ST};

        let sheets = vec![SheetConfig {
            filename: "IPAM.xlsx".into(),
            excludes_sheets: vec![],
            header_row: 1,
            columns: vec![],
            sheettype: ST::Backbone,
            groups: vec![],
        }];
        let results = vec![make_sheet_named(
            "IPAM.xlsx",
            "border1",
            SheetType::Backbone,
            vec![],
        )];
        let lookup = build_group_lookup(&sheets, &results).unwrap();
        assert!(lookup.is_empty());
    }

    // ── overlapping groups behaviour ──────────────────────────────────────────

    #[test]
    fn overlap_shared_group_allows_duplicates() {
        // groups: [sw1,sw2], [sw3,sw4], [sw1,sw3]
        // sw1 ∈ {0,2}, sw3 ∈ {1,2} → intersection {2} → exempt
        let lookup = group_lookup(&[
            ("IPAM", &["sw1", "sw2"]),
            ("IPAM", &["sw3", "sw4"]),
            ("IPAM", &["sw1", "sw3"]),
        ]);
        let sheets = vec![
            make_sheet_named(
                "IPAM",
                "sw1",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "sw3",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        assert!(validate_no_duplicate_cidrs(&sheets, &lookup).is_ok());
    }

    #[test]
    fn overlap_non_shared_group_is_error() {
        // groups: [sw1,sw2], [sw3,sw4], [sw1,sw3]
        // sw2 ∈ {0}, sw4 ∈ {1} → disjoint → error
        let lookup = group_lookup(&[
            ("IPAM", &["sw1", "sw2"]),
            ("IPAM", &["sw3", "sw4"]),
            ("IPAM", &["sw1", "sw3"]),
        ]);
        let sheets = vec![
            make_sheet_named(
                "IPAM",
                "sw2",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
            make_sheet_named(
                "IPAM",
                "sw4",
                SheetType::Backbone,
                vec![make_row(0, &["198.51.100.0/24"])],
            ),
        ];
        let result = validate_no_duplicate_cidrs(&sheets, &lookup);
        assert!(result.is_err());
    }

    #[test]
    fn build_group_lookup_sheet_in_multiple_groups() {
        use mmdb_core::config::{ColumnMapping, ColumnType, SheetConfig, SheetType as ST};

        // sw1 appears in group 0 ([sw1,sw2]) and group 2 ([sw1,sw3])
        let sheets = vec![SheetConfig {
            filename: "IPAM.xlsx".into(),
            excludes_sheets: vec![],
            header_row: 1,
            columns: vec![ColumnMapping {
                name: "network".to_owned(),
                sheet_name: Some("Network".to_owned()),
                sheet_names: None,
                col_type: ColumnType::Addresses,
                ptr_field: None,
            }],
            sheettype: ST::Backbone,
            groups: vec![
                vec!["sw1".to_owned(), "sw2".to_owned()],
                vec!["sw3".to_owned(), "sw4".to_owned()],
                vec!["sw1".to_owned(), "sw3".to_owned()],
            ],
        }];
        let results = vec![
            make_sheet_named("IPAM.xlsx", "sw1", SheetType::Backbone, vec![]),
            make_sheet_named("IPAM.xlsx", "sw2", SheetType::Backbone, vec![]),
            make_sheet_named("IPAM.xlsx", "sw3", SheetType::Backbone, vec![]),
            make_sheet_named("IPAM.xlsx", "sw4", SheetType::Backbone, vec![]),
        ];
        let lookup = build_group_lookup(&sheets, &results).unwrap();

        let sw1_groups = lookup
            .get(&("IPAM.xlsx".to_owned(), "sw1".to_owned()))
            .unwrap();
        let sw3_groups = lookup
            .get(&("IPAM.xlsx".to_owned(), "sw3".to_owned()))
            .unwrap();
        let sw2_groups = lookup
            .get(&("IPAM.xlsx".to_owned(), "sw2".to_owned()))
            .unwrap();
        let sw4_groups = lookup
            .get(&("IPAM.xlsx".to_owned(), "sw4".to_owned()))
            .unwrap();

        // sw1 is in group 0 and group 2
        assert_eq!(sw1_groups.len(), 2);
        // sw3 is in group 1 and group 2
        assert_eq!(sw3_groups.len(), 2);
        // sw2 is only in group 0
        assert_eq!(sw2_groups.len(), 1);
        // sw4 is only in group 1
        assert_eq!(sw4_groups.len(), 1);

        // sw1 and sw3 share group 2
        assert!(!sw1_groups.is_disjoint(sw3_groups));
        // sw2 and sw4 share no group
        assert!(sw2_groups.is_disjoint(sw4_groups));
    }
}
