//! Enrich subcommand: annotate JSON/JSONL log files with MMDB lookup results.

use std::{
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
/// # Errors
///
/// Returns an error if the MMDB cannot be opened, the input file cannot be
/// read or parsed, or writing the output file fails.
// NOTEST(io): reads MMDB + input file from filesystem, writes output file
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run(
    _config: &Config,
    input_file: &Path,
    ip_field: &str,
    mmdb_path: &Path,
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

    let enriched = enrich_records(&reader, records, ip_field);

    let out_path = derive_output_path(input_file);
    tracing::info!(output = %out_path.display(), "enrich: writing output");

    let content = if is_jsonl {
        let mut buf = String::new();
        for record in &enriched {
            buf.push_str(&serde_json::to_string(record).context("failed to serialize record")?);
            buf.push('\n');
        }
        buf
    } else {
        let mut s =
            serde_json::to_string_pretty(&enriched).context("failed to serialize JSON array")?;
        s.push('\n');
        s
    };

    tokio::fs::write(&out_path, content.as_bytes())
        .await
        .with_context(|| format!("failed to write {}", out_path.display()))?;

    tracing::info!(
        records = enriched.len(),
        path = %out_path.display(),
        "enrich: done"
    );
    Ok(())
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

/// Derive the output path by inserting `.enriched` before the last extension.
///
/// Examples:
/// - `foo.jsonl` → `foo.enriched.jsonl`
/// - `foo.json`  → `foo.enriched.json`
/// - `foo`       → `foo.enriched`
fn derive_output_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let new_name = input.extension().and_then(|e| e.to_str()).map_or_else(
        || format!("{stem}.enriched"),
        |ext| format!("{stem}.enriched.{ext}"),
    );

    input.with_file_name(new_name)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn derive_output_path_jsonl() {
        let p = derive_output_path(Path::new("input.jsonl"));
        assert_eq!(p, PathBuf::from("input.enriched.jsonl"));
    }

    #[test]
    fn derive_output_path_json() {
        let p = derive_output_path(Path::new("log.json"));
        assert_eq!(p, PathBuf::from("log.enriched.json"));
    }

    #[test]
    fn derive_output_path_no_extension() {
        let p = derive_output_path(Path::new("log"));
        assert_eq!(p, PathBuf::from("log.enriched"));
    }

    #[test]
    fn derive_output_path_nested() {
        let p = derive_output_path(Path::new("/data/logs/access.jsonl"));
        assert_eq!(p, PathBuf::from("/data/logs/access.enriched.jsonl"));
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
}
