//! Enrich subcommand: annotate JSON/JSONL log files with MMDB lookup results.

mod fields;
pub use fields::{FieldInfo, flatten_fields, project_fields};
mod tui;
pub use tui::run_tui;

use std::{
    io::{BufRead as _, Write as _},
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use mmdb_core::config::Config;

/// Run the enrich subcommand.
///
/// Reads `input_file` as a JSON array or JSONL, looks up each record's
/// `ip_field` in the MMDB, appends a `"mmdb"` key (the matched record, or
/// `null` on miss), and writes the enriched output to a sibling file with
/// `.enriched` inserted before the last extension.
///
/// When `init_fields` is `true`, delegates to [`run_init_fields`] which opens
/// an interactive TUI and writes the `[enrich]` section to `config_path`.
///
/// # Errors
///
/// Returns an error if the MMDB cannot be opened, the input file cannot be
/// read or parsed, or writing the output file fails.
// NOTEST(io): reads MMDB + input file from filesystem, writes output file
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run(
    config: &Config,
    config_path: &Path,
    input_file: &Path,
    ip_field: &str,
    mmdb_path: &Path,
    init_fields: bool,
) -> Result<()> {
    tracing::info!(
        mmdb = %mmdb_path.display(),
        input = %input_file.display(),
        "enrich: opening MMDB"
    );

    let reader = maxminddb::Reader::open_readfile(mmdb_path)
        .with_context(|| format!("failed to open MMDB {}", mmdb_path.display()))?;

    let raw = tokio::fs::read_to_string(input_file)
        .await
        .with_context(|| format!("failed to read {}", input_file.display()))?;

    let is_jsonl = input_file
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"));

    let records: Vec<serde_json::Value> = if is_jsonl {
        raw.lines()
            .enumerate()
            .filter_map(|(i, line)| {
                if line.trim().is_empty() {
                    return None;
                }
                serde_json::from_str(line)
                    .map_err(|e| {
                        tracing::warn!(
                            line = i.saturating_add(1),
                            error = %e,
                            "enrich: skipping unparseable line"
                        );
                        e
                    })
                    .ok()
            })
            .collect()
    } else {
        serde_json::from_str(&raw).context("failed to parse input as JSON array")?
    };

    tracing::info!(count = records.len(), "enrich: loaded records");

    if init_fields {
        return run_init_fields(config, config_path, &reader, records, ip_field, mmdb_path);
    }

    let raw_records = enrich_records(&reader, records, ip_field);

    // Write raw output unconditionally (full enriched map structure, no projection).
    let raw_path = derive_output_path(input_file, "enriched.raw");
    tracing::info!(output = %raw_path.display(), "enrich: writing raw output");
    let raw_content = serialize_records(&raw_records, is_jsonl)?;
    tokio::fs::write(&raw_path, raw_content.as_bytes())
        .await
        .with_context(|| format!("failed to write {}", raw_path.display()))?;

    // Write processed output only when [enrich] is configured.
    if let Some(ref ec) = config.enrich {
        let projected: Vec<serde_json::Value> = raw_records
            .iter()
            .map(|record| project_fields(record, &ec.fields, &ec.array_join_sep))
            .collect();
        let out_path = derive_output_path(input_file, "enriched");
        tracing::info!(output = %out_path.display(), "enrich: writing processed output");
        let content = serialize_records(&projected, is_jsonl)?;
        tokio::fs::write(&out_path, content.as_bytes())
            .await
            .with_context(|| format!("failed to write {}", out_path.display()))?;
        tracing::info!(
            records = projected.len(),
            path = %out_path.display(),
            "enrich: done"
        );
    } else {
        tracing::info!(
            records = raw_records.len(),
            path = %raw_path.display(),
            "enrich: done (raw only)"
        );
    }
    Ok(())
}

/// Handle the `--init-fields` workflow: run the TUI field selector and write
/// the `[enrich]` section to `config_path`.
///
/// Enriches all records to build a sample and field union, then opens an
/// interactive TUI. On confirmation writes the selection to `config_path`,
/// prompting the user before overwriting an existing `[enrich]` section.
///
/// # Errors
///
/// Returns an error if enrichment, TUI I/O, or config writing fails.
// NOTEST(io): TUI + stdin prompt + config file write
#[cfg_attr(coverage_nightly, coverage(off))]
fn run_init_fields<S: AsRef<[u8]>>(
    config: &Config,
    config_path: &Path,
    reader: &maxminddb::Reader<S>,
    records: Vec<serde_json::Value>,
    ip_field: &str,
    mmdb_path: &Path,
) -> Result<()> {
    let enriched = enrich_records(reader, records, ip_field);
    let sample = enriched
        .first()
        .context("input file is empty — need at least one record for --init-fields")?;

    // Build the field union from two sources:
    // 1. All enriched input records — captures input-native fields (ip, timestamp, …)
    //    and any MMDB sub-trees that happen to match the input IPs.
    // 2. A full MMDB scan (up to 2000 records) — ensures that MMDB sub-trees whose
    //    CIDRs are not covered by the input file (e.g. xlsx.hosting when the input
    //    only contains backbone IPs) still appear in the TUI.
    let mut field_infos = union_field_infos(&enriched);
    let jsonl_path = mmdb_path.with_extension("jsonl");
    let mmdb_schema =
        schema_from_output_jsonl(&jsonl_path).unwrap_or_else(|| schema_from_mmdb(reader, 2000));
    let mut seen: std::collections::HashSet<String> =
        field_infos.iter().map(|f| f.path.clone()).collect();
    extend_with_new(&mut seen, &mut field_infos, mmdb_schema);

    let Some(enrich_cfg) = run_tui(field_infos, sample, config.enrich.as_ref())? else {
        return Ok(());
    };

    // Prompt for overwrite if [enrich] already configured.
    if config.enrich.is_some() {
        write!(
            std::io::stderr(),
            "[enrich] already configured in config.toml. Overwrite? (y/N): "
        )?;
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::BufReader::new(std::io::stdin())
            .read_line(&mut answer)
            .context("failed to read user input")?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Ok(());
        }
    }

    Config::write_enrich_section(config_path, &enrich_cfg)?;
    tracing::info!(
        fields = enrich_cfg.fields.len(),
        "enrich: wrote [enrich] section to config"
    );
    Ok(())
}

/// Append `new_infos` to `result`, skipping paths already present in `seen`.
///
/// `seen` tracks which dot-notation paths have been added; `result` accumulates
/// in first-seen order.  Call this helper anywhere a `(seen, result)` pair needs
/// to absorb a fresh batch of [`FieldInfo`] entries without duplicates.
fn extend_with_new(
    seen: &mut std::collections::HashSet<String>,
    result: &mut Vec<FieldInfo>,
    new_infos: Vec<FieldInfo>,
) {
    for info in new_infos {
        if seen.insert(info.path.clone()) {
            result.push(info);
        }
    }
}

/// Build the union of all [`FieldInfo`] entries across `records`.
///
/// Fields are returned in first-seen order: the first record's fields come
/// first (in traversal order), followed by any new paths found in subsequent
/// records. This ensures the TUI shows every possible field even when
/// different records produce different MMDB sub-trees.
fn union_field_infos(records: &[serde_json::Value]) -> Vec<FieldInfo> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for record in records {
        extend_with_new(&mut seen, &mut result, flatten_fields("", record));
    }
    result
}

/// Build a field-info union by scanning up to `max_records` entries in the MMDB.
///
/// Each MMDB record is wrapped under `"mmdb"` to match the enriched-record
/// structure, then flattened. Fields are accumulated in first-seen order.
/// This gives the TUI a complete schema even when the input log file contains
/// no IPs that match a particular MMDB sub-tree (e.g. `xlsx.hosting`).
// NOTEST(io): requires a live maxminddb::Reader opened from a real MMDB file
#[cfg_attr(coverage_nightly, coverage(off))]
fn schema_from_mmdb<S: AsRef<[u8]>>(
    reader: &maxminddb::Reader<S>,
    max_records: usize,
) -> Vec<FieldInfo> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    let Ok(iter) = reader.networks(maxminddb::WithinOptions::default()) else {
        return result;
    };
    for entry in iter.take(max_records) {
        let Ok(lookup) = entry else { continue };
        let Ok(Some(mmdb_val)) = lookup.decode::<serde_json::Value>() else {
            continue;
        };
        let wrapped = serde_json::json!({"mmdb": mmdb_val});
        extend_with_new(&mut seen, &mut result, flatten_fields("", &wrapped));
    }
    result
}

/// Build a field-info union by reading every line of `output.jsonl`.
///
/// Each line is a raw MMDB record (no `"mmdb"` wrapper); this function wraps it
/// under `"mmdb"` to match the enriched-record structure, then flattens fields.
/// Returns `None` when the file is absent or yields no fields, allowing the
/// caller to fall back to [`schema_from_mmdb`].
// NOTEST(io): reads output.jsonl from filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
fn schema_from_output_jsonl(path: &Path) -> Option<Vec<FieldInfo>> {
    let Ok(file) = std::fs::File::open(path) else {
        return None;
    };
    let reader = std::io::BufReader::new(file);
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let wrapped = serde_json::json!({"mmdb": val});
        extend_with_new(&mut seen, &mut result, flatten_fields("", &wrapped));
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Look up all records against the MMDB and merge results under the `"mmdb"` key.
// NOTEST(io): requires a live maxminddb::Reader opened from a real MMDB file
#[cfg_attr(coverage_nightly, coverage(off))]
fn enrich_records<S: AsRef<[u8]>>(
    reader: &maxminddb::Reader<S>,
    records: Vec<serde_json::Value>,
    ip_field: &str,
) -> Vec<serde_json::Value> {
    records
        .into_iter()
        .map(|record| {
            let mmdb_val = extract_ip(&record, ip_field).and_then(|ip| lookup_ip(reader, ip));
            merge_mmdb_field(record, mmdb_val)
        })
        .collect()
}

/// Look up `ip` in `reader` and return the decoded record as a `serde_json::Value`.
///
/// Returns `None` when the address is not in the database or any error occurs
/// (errors are logged as warnings).
// NOTEST(io): requires a live maxminddb::Reader opened from a real MMDB file
#[cfg_attr(coverage_nightly, coverage(off))]
fn lookup_ip<S: AsRef<[u8]>>(
    reader: &maxminddb::Reader<S>,
    ip: IpAddr,
) -> Option<serde_json::Value> {
    let result = match reader.lookup(ip) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(ip = %ip, error = %e, "enrich: MMDB lookup error");
            return None;
        }
    };
    match result.decode::<serde_json::Value>() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(ip = %ip, error = %e, "enrich: MMDB decode error");
            None
        }
    }
}

/// Extract the IP address from `record[ip_field]` and parse it to an [`IpAddr`].
///
/// Returns `None` if the field is missing, not a string, or not a valid IP.
fn extract_ip(record: &serde_json::Value, ip_field: &str) -> Option<IpAddr> {
    record.get(ip_field)?.as_str()?.parse().ok()
}

/// Insert `mmdb` under the `"mmdb"` key of `record`.
///
/// If `record` is not a JSON object the value is returned unchanged.
fn merge_mmdb_field(
    mut record: serde_json::Value,
    mmdb: Option<serde_json::Value>,
) -> serde_json::Value {
    if let serde_json::Value::Object(ref mut map) = record {
        map.insert(
            String::from("mmdb"),
            mmdb.unwrap_or(serde_json::Value::Null),
        );
    }
    record
}

/// Derive the output path by inserting `.<suffix>` before the last extension.
///
/// Examples (`suffix = "enriched"`):
/// - `foo.jsonl` → `foo.enriched.jsonl`
/// - `foo.json`  → `foo.enriched.json`
/// - `foo`       → `foo.enriched`
fn derive_output_path(input: &Path, suffix: &str) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let new_name = input.extension().and_then(|e| e.to_str()).map_or_else(
        || format!("{stem}.{suffix}"),
        |ext| format!("{stem}.{suffix}.{ext}"),
    );

    input.with_file_name(new_name)
}

/// Serialize a slice of JSON records to either JSONL or a pretty-printed JSON array.
fn serialize_records(records: &[serde_json::Value], jsonl: bool) -> Result<String> {
    if jsonl {
        let mut buf = String::new();
        for record in records {
            buf.push_str(&serde_json::to_string(record).context("failed to serialize record")?);
            buf.push('\n');
        }
        Ok(buf)
    } else {
        let mut s =
            serde_json::to_string_pretty(records).context("failed to serialize JSON array")?;
        s.push('\n');
        Ok(s)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn derive_output_path_jsonl() {
        let p = derive_output_path(Path::new("input.jsonl"), "enriched");
        assert_eq!(p, PathBuf::from("input.enriched.jsonl"));
    }

    #[test]
    fn derive_output_path_json() {
        let p = derive_output_path(Path::new("log.json"), "enriched");
        assert_eq!(p, PathBuf::from("log.enriched.json"));
    }

    #[test]
    fn derive_output_path_no_extension() {
        let p = derive_output_path(Path::new("log"), "enriched");
        assert_eq!(p, PathBuf::from("log.enriched"));
    }

    #[test]
    fn derive_output_path_nested() {
        let p = derive_output_path(Path::new("/data/logs/access.jsonl"), "enriched");
        assert_eq!(p, PathBuf::from("/data/logs/access.enriched.jsonl"));
    }

    #[test]
    fn derive_output_path_raw_suffix() {
        let p = derive_output_path(Path::new("input.jsonl"), "enriched.raw");
        assert_eq!(p, PathBuf::from("input.enriched.raw.jsonl"));
    }

    #[test]
    fn derive_output_path_raw_no_extension() {
        let p = derive_output_path(Path::new("input"), "enriched.raw");
        assert_eq!(p, PathBuf::from("input.enriched.raw"));
    }

    #[test]
    fn extract_ip_present_ipv4() {
        let record = json!({"ip_address": "198.51.100.1"});
        let ip = extract_ip(&record, "ip_address");
        assert_eq!(ip, Some("198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn extract_ip_present_ipv6() {
        let record = json!({"src": "2001:db8::1"});
        let ip = extract_ip(&record, "src");
        assert_eq!(ip, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn extract_ip_missing_field() {
        let record = json!({"msg": "hello"});
        assert!(extract_ip(&record, "ip_address").is_none());
    }

    #[test]
    fn extract_ip_invalid_address() {
        let record = json!({"ip_address": "not-an-ip"});
        assert!(extract_ip(&record, "ip_address").is_none());
    }

    #[test]
    fn merge_mmdb_field_with_hit() {
        let record = json!({"ip_address": "198.51.100.1"});
        let mmdb = json!({"range": "198.51.100.0/24", "autonomous_system_number": 64496});
        let result = merge_mmdb_field(record, Some(mmdb.clone()));
        assert_eq!(result["mmdb"], mmdb);
        assert_eq!(result["ip_address"], "198.51.100.1");
    }

    #[test]
    fn merge_mmdb_field_with_miss() {
        let record = json!({"ip_address": "203.0.113.99"});
        let result = merge_mmdb_field(record, None);
        assert!(result["mmdb"].is_null());
    }

    #[test]
    fn merge_mmdb_field_non_object_passthrough() {
        let record = json!("just a string");
        let result = merge_mmdb_field(record.clone(), None);
        assert_eq!(result, record);
    }

    // --- union_field_infos ---

    #[test]
    fn union_field_infos_single_record() {
        let records = vec![json!({"ip": "198.51.100.1", "mmdb": {"asn": 64496}})];
        let infos = union_field_infos(&records);
        let paths: Vec<&str> = infos.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"ip"));
        assert!(paths.contains(&"mmdb"));
        assert!(paths.contains(&"mmdb.asn"));
    }

    #[test]
    fn union_field_infos_merges_across_records() {
        // First record has mmdb.backbone, second has mmdb.hosting.
        let records = vec![
            json!({"ip": "198.51.100.1", "mmdb": {"backbone": {"router": "r1"}}}),
            json!({"ip": "198.51.100.2", "mmdb": {"hosting": {"dc": "dc1"}}}),
        ];
        let infos = union_field_infos(&records);
        let paths: Vec<&str> = infos.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"mmdb.backbone.router"));
        assert!(paths.contains(&"mmdb.hosting.dc"));
    }

    #[test]
    fn union_field_infos_deduplicates() {
        // Both records share the same field — must appear only once.
        let records = vec![
            json!({"ip": "198.51.100.1", "mmdb": {"asn": 64496}}),
            json!({"ip": "198.51.100.2", "mmdb": {"asn": 64497}}),
        ];
        let infos = union_field_infos(&records);
        let count = infos.iter().filter(|f| f.path == "mmdb.asn").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn union_field_infos_empty() {
        let infos = union_field_infos(&[]);
        assert!(infos.is_empty());
    }
}
