//! PTR-to-xlsx and CIDR-to-xlsx matching for the enrich phase.
//!
//! Builds in-memory indices from `data/xlsx-rows.jsonl` once at enrich startup,
//! then matches each [`ScanGwRecord`] via:
//!
//! 1. **backbone** (PTR match): all `ptr_field` columns must match the corresponding
//!    PTR capture group after normalisation (AND condition). First match wins.
//! 2. **backbone** (CIDR fallback): bidirectional containment —
//!    `xlsx_net ⊇ scan_range` OR `scan_range ⊇ xlsx_net`. First match wins.
//! 3. **hosting** (CIDR exact): `xlsx_net == scan_range`. First match wins.
//!
//! The two sheettypes are kept in separate indices. `attach()` builds a
//! `HashMap<sheettype, matched_row>` and stores it as `ScanGwRecord.xlsx`.

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
    // backbone indices
    backbone_ptr_candidates: Vec<PtrCandidate>,
    backbone_cidr_candidates: Vec<CidrCandidate>,
    // hosting index (exact CIDR match only)
    hosting_cidr_candidates: Vec<CidrCandidate>,
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
                backbone_ptr_candidates: Vec::new(),
                backbone_cidr_candidates: Vec::new(),
                hosting_cidr_candidates: Vec::new(),
                compiled_normalize,
                ptr_field_map,
            });
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        let mut backbone_ptr_candidates: Vec<PtrCandidate> = Vec::new();
        let mut backbone_cidr_candidates: Vec<CidrCandidate> = Vec::new();
        let mut hosting_cidr_candidates: Vec<CidrCandidate> = Vec::new();

        for line in raw.lines() {
            let Ok(row): Result<Value, _> = serde_json::from_str(line) else {
                continue;
            };
            let Some(obj) = row.as_object() else {
                continue;
            };

            // Determine sheettype from _source; default to "backbone" for backward compat.
            let sheettype = obj
                .get("_source")
                .and_then(|s| s.get("sheettype"))
                .and_then(|v| v.as_str())
                .unwrap_or("backbone");

            // Extract IpNets from all non-_source array fields.
            let nets: Vec<IpNet> = obj
                .iter()
                .filter(|(k, _)| k.as_str() != "_source")
                .filter_map(|(_, val)| val.as_array())
                .flatten()
                .filter_map(|item| item.as_str()?.parse::<IpNet>().ok())
                .collect();

            if sheettype == "hosting" {
                for net in nets {
                    hosting_cidr_candidates.push(CidrCandidate {
                        net,
                        row: row.clone(),
                    });
                }
            } else {
                // backbone (default for any unrecognised sheettype)

                // Build PTR candidate: collect normalised ptr_field values.
                let mut ptr_fields: Vec<(String, String)> = Vec::new();
                for (col_name, ptr_field_name) in &ptr_field_map {
                    if let Some(cell_val) = obj.get(col_name)
                        && let Some(raw_str) = cell_val.as_str()
                    {
                        let normalised =
                                compiled_normalize.get(ptr_field_name.as_str()).map_or_else(
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
                    backbone_ptr_candidates.push(PtrCandidate {
                        row: row.clone(),
                        ptr_fields,
                    });
                }

                for net in nets {
                    backbone_cidr_candidates.push(CidrCandidate {
                        net,
                        row: row.clone(),
                    });
                }
            }
        }

        Ok(Self {
            backbone_ptr_candidates,
            backbone_cidr_candidates,
            hosting_cidr_candidates,
            compiled_normalize,
            ptr_field_map,
        })
    }

    /// Returns `true` when no candidates are loaded.
    pub const fn is_empty(&self) -> bool {
        self.backbone_ptr_candidates.is_empty()
            && self.backbone_cidr_candidates.is_empty()
            && self.hosting_cidr_candidates.is_empty()
    }

    /// Find the best matching xlsx row(s) for `record` and attach them as `xlsx`.
    ///
    /// Backbone: PTR match first, then bidirectional CIDR fallback.
    /// Hosting: exact CIDR match only.
    ///
    /// Sets `record.xlsx` to `Some(map)` where map keys are sheettype strings.
    /// Absent when neither matched.
    pub fn attach(&self, record: &mut ScanGwRecord) {
        let mut result: std::collections::HashMap<String, Value> = std::collections::HashMap::new();

        if let Some(matched) = self.backbone_match(record.gateway.device.as_ref(), &record.range) {
            result.insert("backbone".to_owned(), matched);
        }
        if let Some(matched) = self.hosting_match(&record.range) {
            result.insert("hosting".to_owned(), matched);
        }

        record.xlsx = if result.is_empty() {
            None
        } else {
            Some(result)
        };
    }

    // -------------------------------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------------------------------

    /// backbone match: PTR first, then bidirectional CIDR fallback.
    fn backbone_match(&self, device: Option<&GatewayDevice>, range: &str) -> Option<Value> {
        if let Some(matched) = self.ptr_match(device) {
            return Some(matched);
        }
        self.backbone_cidr_match(range)
    }

    /// PTR match: all `ptr_field` columns must match (AND condition).
    fn ptr_match(&self, device: Option<&GatewayDevice>) -> Option<Value> {
        let device = device?;
        if self.ptr_field_map.is_empty() || self.backbone_ptr_candidates.is_empty() {
            return None;
        }

        let ptr_values = self.build_ptr_values(device);
        if ptr_values.is_empty() {
            return None;
        }

        let mut matched: Option<&Value> = None;
        let mut match_count = 0usize;

        for candidate in &self.backbone_ptr_candidates {
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
                "xlsx_match: multiple backbone rows match PTR key; using first"
            );
        }

        matched.cloned()
    }

    /// backbone CIDR match: bidirectional containment.
    ///
    /// Matches when `xlsx_net ⊇ scan_range` (xlsx is supernet) OR
    /// `scan_range ⊇ xlsx_net` (scan range is supernet, e.g. BGP /19 with backbone /20).
    fn backbone_cidr_match(&self, range: &str) -> Option<Value> {
        let Ok(range_net) = range.parse::<IpNet>() else {
            return None;
        };

        let mut matched: Option<&Value> = None;
        let mut match_count = 0usize;

        for candidate in &self.backbone_cidr_candidates {
            if candidate.net.contains(&range_net) || range_net.contains(&candidate.net) {
                match_count = match_count.saturating_add(1);
                if matched.is_none() {
                    matched = Some(&candidate.row);
                }
            }
        }

        if match_count > 1 {
            tracing::warn!(
                count = match_count,
                "xlsx_match: multiple backbone rows match CIDR; using first"
            );
        }

        matched.cloned()
    }

    /// hosting CIDR match: exact equality only.
    fn hosting_match(&self, range: &str) -> Option<Value> {
        let Ok(range_net) = range.parse::<IpNet>() else {
            return None;
        };

        let mut matched: Option<&Value> = None;
        let mut match_count = 0usize;

        for candidate in &self.hosting_cidr_candidates {
            if candidate.net == range_net {
                match_count = match_count.saturating_add(1);
                if matched.is_none() {
                    matched = Some(&candidate.row);
                }
            }
        }

        if match_count > 1 {
            tracing::warn!(
                count = match_count,
                range = range,
                "xlsx_match: multiple hosting rows match CIDR; using first"
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
        config::{ColumnMapping, ColumnType, Config, NormalizeConfig, SheetConfig, SheetType},
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

    // --- backbone supernet match ---

    #[test]
    fn backbone_cidr_supernet_match() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
            "network": ["198.51.100.0/24"],
            "serviceid": "SVC-001"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/29", None);
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(xlsx.contains_key("backbone"));
        assert_eq!(xlsx["backbone"]["serviceid"], "SVC-001");
    }

    // --- backbone bidirectional match (scan range ⊇ xlsx CIDR) ---

    #[test]
    fn backbone_cidr_bidirectional_match() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
            "network": ["198.51.96.0/20"],
            "serviceid": "SVC-BGP"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.96.0/19", None);
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(
            xlsx.contains_key("backbone"),
            "scan /19 must match backbone /20"
        );
    }

    // --- backbone no match ---

    #[test]
    fn backbone_cidr_no_match() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
            "network": ["198.51.100.128/25"]
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/29", None);
        m.attach(&mut rec);
        assert!(rec.xlsx.is_none());
    }

    // --- hosting exact match ---

    #[test]
    fn hosting_exact_cidr_match() {
        let rows = vec![json!({
            "_source": {"file": "B.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
            "network": ["198.51.100.1/32"],
            "hostname": "customer1.example.com"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.1/32", None);
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(xlsx.contains_key("hosting"));
        assert_eq!(xlsx["hosting"]["hostname"], "customer1.example.com");
    }

    // --- hosting does NOT match supernet ---

    #[test]
    fn hosting_does_not_match_supernet() {
        let rows = vec![json!({
            "_source": {"file": "B.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
            "network": ["198.51.100.1/32"],
            "hostname": "customer1.example.com"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/24", None);
        m.attach(&mut rec);
        assert!(
            rec.xlsx.as_ref().is_none_or(|m| !m.contains_key("hosting")),
            "hosting must not match supernet"
        );
    }

    // --- both backbone and hosting attached ---

    #[test]
    fn both_backbone_and_hosting_attached() {
        let rows = vec![
            json!({
                "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
                "network": ["198.51.100.0/24"],
                "serviceid": "SVC-001"
            }),
            json!({
                "_source": {"file": "B.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
                "network": ["198.51.100.1/32"],
                "hostname": "customer1.example.com"
            }),
        ];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.1/32", None);
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(xlsx.contains_key("backbone"), "backbone must be attached");
        assert!(xlsx.contains_key("hosting"), "hosting must be attached");
        assert_eq!(xlsx["backbone"]["serviceid"], "SVC-001");
        assert_eq!(xlsx["hosting"]["hostname"], "customer1.example.com");
    }

    // --- backward compat: no sheettype defaults to backbone ---

    #[test]
    fn missing_sheettype_defaults_to_backbone() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0},
            "network": ["198.51.100.0/29"],
            "serviceid": "SVC-OLD"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/29", None);
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(
            xlsx.contains_key("backbone"),
            "no sheettype must default to backbone"
        );
    }

    // --- PTR match (backbone only) ---

    fn config_with_ptr_field(ptr_field_name: &str, col_name: &str) -> Config {
        Config {
            sheets: Some(vec![SheetConfig {
                filename: std::path::PathBuf::from("."),
                excludes_sheets: vec![],
                header_row: 1,
                columns: vec![ColumnMapping {
                    name: col_name.to_owned(),
                    sheet_name: Some(col_name.to_owned()),
                    sheet_names: None,
                    col_type: ColumnType::String,
                    ptr_field: Some(ptr_field_name.to_owned()),
                }],
                sheettype: SheetType::Backbone,
                groups: vec![],
            }]),
            normalize: std::collections::HashMap::from([(
                ptr_field_name.to_owned(),
                NormalizeConfig::default(),
            )]),
            ..base_config()
        }
    }

    #[test]
    fn ptr_match_backbone_only() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
            "host": "rtr0101",
            "network": ["198.51.100.0/29"]
        })];
        let f = write_rows(&rows);

        let cfg = config_with_ptr_field("device", "host");
        let m = XlsxMatcher::build(f.path(), &cfg).unwrap();
        let mut rec = gw_record("198.51.100.0/29", Some(make_device("rtr0101", "dc01")));
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(xlsx.contains_key("backbone"));
        assert_eq!(xlsx["backbone"]["host"], "rtr0101");
    }

    #[test]
    fn normalize_applied_to_both_sides() {
        use mmdb_core::config::NormalizeRule;

        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
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
                    sheet_name: Some("port".to_owned()),
                    sheet_names: None,
                    col_type: ColumnType::String,
                    ptr_field: Some("interface".to_owned()),
                }],
                sheettype: SheetType::Backbone,
                groups: vec![],
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
        assert!(
            rec.xlsx
                .as_ref()
                .is_some_and(|m| m.contains_key("backbone")),
            "expected PTR normalize match in backbone"
        );
    }

    // --- hosting multi-match warns, uses first ---

    #[test]
    fn hosting_multi_match_uses_first() {
        let rows = vec![
            json!({
                "_source": {"file": "B1.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
                "network": ["198.51.100.1/32"],
                "hostname": "first.example.com"
            }),
            json!({
                "_source": {"file": "B2.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
                "network": ["198.51.100.1/32"],
                "hostname": "second.example.com"
            }),
        ];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.1/32", None);
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(xlsx.contains_key("hosting"));
        assert_eq!(xlsx["hosting"]["hostname"], "first.example.com");
    }

    // --- backbone exact match ---

    #[test]
    fn backbone_exact_cidr_match() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
            "network": ["198.51.100.0/29"],
            "serviceid": "SVC-EXACT"
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        let mut rec = gw_record("198.51.100.0/29", None);
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(xlsx.contains_key("backbone"));
        assert_eq!(xlsx["backbone"]["serviceid"], "SVC-EXACT");
    }

    // --- hosting row does not produce ptr candidate ---

    #[test]
    fn hosting_row_does_not_create_ptr_candidate() {
        let rows = vec![json!({
            "_source": {"file": "B.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
            "host": "rtr0101",
            "network": ["198.51.100.1/32"]
        })];
        let f = write_rows(&rows);

        let cfg = config_with_ptr_field("device", "host");
        let m = XlsxMatcher::build(f.path(), &cfg).unwrap();
        // The hosting row has matching "host" field, but hosting has no PTR matching.
        // Only CIDR exact match applies.
        let mut rec = gw_record("198.51.100.0/29", Some(make_device("rtr0101", "dc01")));
        m.attach(&mut rec);
        // No backbone, no hosting (hosting /32 != /29)
        assert!(rec.xlsx.is_none(), "hosting must not match via PTR");
    }

    // --- xlsx absent when nothing matches ---

    #[test]
    fn no_match_xlsx_is_none() {
        let rows = vec![
            json!({
                "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
                "network": ["203.0.113.0/24"]
            }),
            json!({
                "_source": {"file": "B.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
                "network": ["203.0.113.5/32"]
            }),
        ];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        // Completely different range: neither backbone nor hosting matches
        let mut rec = gw_record("198.51.100.1/32", None);
        m.attach(&mut rec);
        assert!(rec.xlsx.is_none());
    }

    // --- is_empty reflects all three indices ---

    #[test]
    fn is_empty_false_when_hosting_only() {
        let rows = vec![json!({
            "_source": {"file": "B.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "hosting"},
            "network": ["198.51.100.1/32"]
        })];
        let f = write_rows(&rows);

        let m = XlsxMatcher::build(f.path(), &base_config()).unwrap();
        assert!(
            !m.is_empty(),
            "matcher with hosting candidates must not be empty"
        );
    }

    // --- PTR no match falls back to CIDR ---

    #[test]
    fn ptr_no_match_falls_back_to_backbone_cidr() {
        let rows = vec![json!({
            "_source": {"file": "A.xlsx", "sheet": "s1", "row_index": 0, "sheettype": "backbone"},
            "host": "rtr9999",
            "network": ["198.51.100.0/24"]
        })];
        let f = write_rows(&rows);

        let cfg = config_with_ptr_field("device", "host");
        let m = XlsxMatcher::build(f.path(), &cfg).unwrap();
        // PTR device doesn't match "rtr9999", but CIDR /24 contains /29 → backbone match via CIDR
        let mut rec = gw_record("198.51.100.0/29", Some(make_device("rtr0101", "dc01")));
        m.attach(&mut rec);
        let xlsx = rec.xlsx.as_ref().unwrap();
        assert!(
            xlsx.contains_key("backbone"),
            "should fall back to CIDR match"
        );
    }
}
