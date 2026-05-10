//! PTR-to-xlsx and CIDR-to-xlsx matching for the enrich phase.
//!
//! Builds in-memory indices from `data/xlsx-rows.jsonl` once at enrich startup,
//! then matches each [`ScanGwRecord`] via:
//!
//! 1. PTR match: all `ptr_field` columns must match the corresponding PTR capture
//!    group after normalisation (AND condition). First match wins.
//! 2. CIDR fallback: xlsx [`IpNet`] contains the scanned range (or equals it).
//!    First match wins.

use std::{collections::HashMap, path::Path};

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{
    config::Config,
    types::{GatewayDevice, ScanGwRecord},
};
use serde_json::Value;

use crate::normalize::{self, CompiledNormalizeConfig};

// -------------------------------------------------------------------------------------------------
// Internal index types
// -------------------------------------------------------------------------------------------------

struct PtrCandidate {
    row: Value,
    /// (`ptr_field_name`, `normalised_value`) pairs extracted at build time.
    ptr_fields: Vec<(String, String)>,
}

struct CidrCandidate {
    net: IpNet,
    row: Value,
}

// -------------------------------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------------------------------

/// Index built once from `xlsx-rows.jsonl` for PTR and CIDR matching.
pub struct XlsxMatcher {
    ptr_candidates: Vec<PtrCandidate>,
    cidr_candidates: Vec<CidrCandidate>,
    compiled_normalize: HashMap<String, CompiledNormalizeConfig>,
    /// Maps column name → `ptr_field` name (from config).
    ptr_field_map: HashMap<String, String>,
}

impl XlsxMatcher {
    /// Build an [`XlsxMatcher`] from `xlsx_path` and the given config.
    ///
    /// Returns an empty matcher when the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the normalize rules fail to compile or the file
    /// cannot be read.
    pub fn build(path: &Path, config: &Config) -> Result<Self> {
        let compiled_normalize = normalize::compile_all(&config.normalize)
            .context("failed to compile normalize rules")?;

        // Build a map from column name → ptr_field for fast lookup.
        let mut ptr_field_map: HashMap<String, String> = HashMap::new();
        if let Some(sheets) = &config.sheets {
            for sheet in sheets {
                for col in &sheet.columns {
                    if let Some(ref pf) = col.ptr_field {
                        ptr_field_map.insert(col.name.clone(), pf.clone());
                    }
                }
            }
        }

        if !path.exists() {
            return Ok(Self {
                ptr_candidates: Vec::new(),
                cidr_candidates: Vec::new(),
                compiled_normalize,
                ptr_field_map,
            });
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        let mut ptr_candidates: Vec<PtrCandidate> = Vec::new();
        let mut cidr_candidates: Vec<CidrCandidate> = Vec::new();

        for line in raw.lines() {
            let Ok(row): Result<Value, _> = serde_json::from_str(line) else {
                continue;
            };
            let Some(obj) = row.as_object() else {
                continue;
            };

            // Build PTR candidate: collect normalised ptr_field values.
            let mut ptr_fields: Vec<(String, String)> = Vec::new();
            for (col_name, ptr_field_name) in &ptr_field_map {
                if let Some(cell_val) = obj.get(col_name)
                    && let Some(raw_str) = cell_val.as_str()
                {
                    let normalised = compiled_normalize.get(ptr_field_name.as_str()).map_or_else(
                        || {
                            tracing::warn!(
                                ptr_field = %ptr_field_name,
                                "xlsx_match: no normalize rule for ptr_field; using raw value"
                            );
                            raw_str.to_owned()
                        },
                        |norm| normalize::apply(norm, raw_str),
                    );
                    ptr_fields.push((ptr_field_name.clone(), normalised));
                }
            }
            if !ptr_fields.is_empty() {
                ptr_candidates.push(PtrCandidate {
                    row: row.clone(),
                    ptr_fields,
                });
            }

            // Build CIDR candidate: extract all IpNets from array fields.
            for (key, val) in obj {
                if key == "_source" {
                    continue;
                }
                if let Some(arr) = val.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_str()
                            && let Ok(net) = s.parse::<IpNet>()
                        {
                            cidr_candidates.push(CidrCandidate {
                                net,
                                row: row.clone(),
                            });
                        }
                    }
                }
            }
        }

        Ok(Self {
            ptr_candidates,
            cidr_candidates,
            compiled_normalize,
            ptr_field_map,
        })
    }

    /// Returns `true` when no PTR candidates and no CIDR candidates are loaded
    /// (e.g. when the xlsx file did not exist or contained no matching rows).
    pub const fn is_empty(&self) -> bool {
        self.ptr_candidates.is_empty() && self.cidr_candidates.is_empty()
    }

    /// Find the best matching xlsx row for `record` and attach it as `xlsx`.
    ///
    /// Match algorithm:
    /// 1. PTR match (gateway device fields against `ptr_field` columns, AND).
    /// 2. CIDR fallback (xlsx [`IpNet`] contains or equals record range).
    pub fn attach(&self, record: &mut ScanGwRecord) {
        if let Some(matched) = self.ptr_match(record.gateway.device.as_ref()) {
            record.xlsx = Some(matched);
            return;
        }
        if let Some(matched) = self.cidr_match(&record.range) {
            record.xlsx = Some(matched);
        }
    }

    // -------------------------------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------------------------------

    /// PTR match: all `ptr_field` columns must match (AND condition).
    fn ptr_match(&self, device: Option<&GatewayDevice>) -> Option<Value> {
        let device = device?;
        if self.ptr_field_map.is_empty() || self.ptr_candidates.is_empty() {
            return None;
        }

        // Build normalised PTR field values for comparison.
        let ptr_values = self.build_ptr_values(device);
        if ptr_values.is_empty() {
            return None;
        }

        let mut matched: Option<&Value> = None;
        let mut match_count = 0usize;

        for candidate in &self.ptr_candidates {
            if candidate_matches(candidate, &ptr_values) {
                match_count = match_count.saturating_add(1);
                if matched.is_none() {
                    matched = Some(&candidate.row);
                }
            }
        }

        if match_count > 1 {
            tracing::warn!(
                count = match_count,
                "xlsx_match: multiple xlsx rows match PTR key; using first"
            );
        }

        matched.cloned()
    }

    /// CIDR match: xlsx [`IpNet`] contains or equals the scanned range.
    fn cidr_match(&self, range: &str) -> Option<Value> {
        let Ok(range_net) = range.parse::<IpNet>() else {
            return None;
        };

        let mut matched: Option<&Value> = None;
        let mut match_count = 0usize;

        for candidate in &self.cidr_candidates {
            if candidate.net.contains(&range_net) || candidate.net == range_net {
                match_count = match_count.saturating_add(1);
                if matched.is_none() {
                    matched = Some(&candidate.row);
                }
            }
        }

        if match_count > 1 {
            tracing::warn!(
                count = match_count,
                "xlsx_match: multiple xlsx rows match CIDR; using first"
            );
        }

        matched.cloned()
    }

    /// Build a map from `ptr_field_name` → normalised PTR capture group value.
    fn build_ptr_values(&self, device: &GatewayDevice) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let fields: &[(&str, Option<&str>)] = &[
            ("interface", device.interface.as_deref()),
            ("device", device.device.as_deref()),
            ("device_role", device.device_role.as_deref()),
            ("facility", device.facility.as_deref()),
            ("facing", device.facing.as_deref()),
        ];
        for (field_name, raw_opt) in fields {
            if let Some(raw) = raw_opt
                && self.ptr_field_map.values().any(|v| v == *field_name)
            {
                let normalised = self.compiled_normalize.get(*field_name).map_or_else(
                    || {
                        tracing::warn!(
                            field = field_name,
                            "xlsx_match: no normalize rule for PTR field; using raw value"
                        );
                        (*raw).to_owned()
                    },
                    |norm| normalize::apply(norm, raw),
                );
                out.insert((*field_name).to_owned(), normalised);
            }
        }
        out
    }
}

/// Return `true` when ALL `ptr_field` columns in `candidate` match the
/// corresponding normalised PTR values.
fn candidate_matches(candidate: &PtrCandidate, ptr_values: &HashMap<String, String>) -> bool {
    for (field_name, normalised_xlsx_val) in &candidate.ptr_fields {
        match ptr_values.get(field_name.as_str()) {
            Some(ptr_val) => {
                if ptr_val != normalised_xlsx_val {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

// -------------------------------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use std::io::Write as _;

    use mmdb_core::{
        config::{ColumnMapping, ColumnType, Config, NormalizeConfig, SheetConfig},
        types::{GatewayDevice, GatewayInfo, ScanGwRecord},
    };
    use serde_json::json;
    use tempfile::NamedTempFile;

    use super::XlsxMatcher;

    fn base_config() -> Config {
        Config {
            whois: None,
            sheets: None,
            scan: None,
            mmdb: mmdb_core::config::MmdbConfig::default(),
            normalize: std::collections::HashMap::new(),
        }
    }

    fn gw_record(range: &str, device: Option<GatewayDevice>) -> ScanGwRecord {
        ScanGwRecord {
            range: range.to_owned(),
            netname: None,
            descr: None,
            as_num: None,
            as_name: None,
            as_descr: None,
            inetnum: None,
            country: None,
            whois_source: None,
            whois_last_modified: None,
            gateway: GatewayInfo {
                ip: None,
                ptr: None,
                votes: 1,
                total: 1,
                status: "inservice".to_owned(),
                device,
            },
            routes: Vec::new(),
            host_ip: None,
            host_ptr: None,
            measured_at: None,
            xlsx: None,
            xlsx_matched: false,
            gateway_found: false,
        }
    }

    fn make_device(device: &str, facility: &str) -> GatewayDevice {
        GatewayDevice {
            interface: None,
            device: Some(device.to_owned()),
            device_role: None,
            facility: Some(facility.to_owned()),
            facing: None,
            customer_asn: None,
        }
    }

    fn write_rows(rows: &[serde_json::Value]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for row in rows {
            writeln!(f, "{}", serde_json::to_string(row).unwrap()).unwrap();
        }
        f
    }

    // --- empty / missing file ---

    #[test]
    fn empty_matcher_when_file_missing() {
        let m = XlsxMatcher::build(
            std::path::Path::new("/nonexistent/xlsx-rows.jsonl"),
            &base_config(),
        )
        .unwrap();
        assert!(m.is_empty());
    }

    // --- CIDR fallback match ---

    #[test]
    fn cidr_match_exact() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0},
            "network": ["198.51.100.0/29"],
            "serviceid": "SVC-001"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/29", None);
        m.attach(&mut rec);
        assert!(rec.xlsx.is_some());
        assert_eq!(rec.xlsx.as_ref().unwrap()["serviceid"], "SVC-001");
    }

    #[test]
    fn cidr_match_supernet() {
        // xlsx has /24, record is /29 — supernet should match.
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0},
            "network": ["198.51.100.0/24"],
            "serviceid": "SVC-002"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/29", None);
        m.attach(&mut rec);
        assert!(rec.xlsx.is_some());
    }

    #[test]
    fn cidr_no_match_returns_none() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0},
            "network": ["198.51.100.128/25"]
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/29", None);
        m.attach(&mut rec);
        assert!(rec.xlsx.is_none());
    }

    // --- PTR match ---

    fn config_with_ptr_field(ptr_field_name: &str, col_name: &str) -> Config {
        Config {
            sheets: Some(vec![SheetConfig {
                filename: std::path::PathBuf::from("."),
                excludes_sheets: vec![],
                header_row: 1,
                columns: vec![ColumnMapping {
                    name: col_name.to_owned(),
                    sheet_name: col_name.to_owned(),
                    col_type: ColumnType::String,
                    ptr_field: Some(ptr_field_name.to_owned()),
                }],
            }]),
            normalize: std::collections::HashMap::from([(
                ptr_field_name.to_owned(),
                NormalizeConfig::default(),
            )]),
            ..base_config()
        }
    }

    #[test]
    fn ptr_match_single() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0},
            "host": "rtr0101",
            "network": ["198.51.100.0/29"]
        })];
        let f = write_rows(&rows);

        let cfg = config_with_ptr_field("device", "host");
        let m = XlsxMatcher::build(f.path(), &cfg).unwrap();
        let mut rec = gw_record("198.51.100.0/29", Some(make_device("rtr0101", "dc01")));
        m.attach(&mut rec);
        assert!(rec.xlsx.is_some());
        assert_eq!(rec.xlsx.as_ref().unwrap()["host"], "rtr0101");
    }

    #[test]
    fn ptr_no_match_returns_none() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0},
            "host": "rtr9999",
            "network": ["198.51.100.128/25"]
        })];
        let f = write_rows(&rows);

        let cfg = config_with_ptr_field("device", "host");
        let m = XlsxMatcher::build(f.path(), &cfg).unwrap();
        // PTR device doesn't match; range also doesn't match.
        let mut rec = gw_record("198.51.100.0/29", Some(make_device("rtr0101", "dc01")));
        m.attach(&mut rec);
        assert!(rec.xlsx.is_none());
    }

    #[test]
    fn normalize_applied_to_both_sides() {
        use mmdb_core::config::NormalizeRule;

        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0},
            "port": "xe-0/0/1"
        })];
        let f = write_rows(&rows);

        let cfg = Config {
            sheets: Some(vec![SheetConfig {
                filename: std::path::PathBuf::from("."),
                excludes_sheets: vec![],
                header_row: 1,
                columns: vec![ColumnMapping {
                    name: "port".to_owned(),
                    sheet_name: "port".to_owned(),
                    col_type: ColumnType::String,
                    ptr_field: Some("interface".to_owned()),
                }],
            }]),
            normalize: std::collections::HashMap::from([(
                "interface".to_owned(),
                NormalizeConfig {
                    rules: vec![NormalizeRule {
                        pattern: "/".to_owned(),
                        replacement: "-".to_owned(),
                    }],
                    case: mmdb_core::config::NormalizeCase::Lower,
                    excludes: vec![],
                },
            )]),
            ..base_config()
        };

        let m = XlsxMatcher::build(f.path(), &cfg).unwrap();

        // PTR has "xe-0-0-1" (DNS-safe); xlsx has "xe-0/0/1"
        // After normalize, both become "xe-0-0-1" → match.
        let device = GatewayDevice {
            interface: Some("xe-0-0-1".to_owned()),
            device: None,
            device_role: None,
            facility: None,
            facing: None,
            customer_asn: None,
        };
        let mut rec = gw_record("198.51.100.0/29", Some(device));
        m.attach(&mut rec);
        assert!(rec.xlsx.is_some(), "expected PTR normalize match");
    }
}
