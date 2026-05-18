//! Scan subcommand: thin client that delegates to mmdb-scan.

use std::{collections::HashSet, path::Path};

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{
    config::Config,
    types::{ScanRecord, WhoisRecord},
};

use crate::{backup, cache};

/// Run the scan subcommand.
// NOTEST(io): orchestrates mmdb-scan — requires scamper on PATH
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run(config: &Config, force: bool, ip: Option<&str>, full: bool) -> Result<()> {
    // Rotate backup before clearing/scanning.
    let output_path = Path::new("data/scanned.jsonl");
    backup::rotate_backup(output_path, 5)
        .await
        .context("failed to rotate scanned.jsonl backup")?;

    let scanning_cache_path = Path::new("data/cache/scan/scanning.jsonl");
    backup::rotate_backup(scanning_cache_path, 5)
        .await
        .context("failed to rotate scanning.jsonl backup")?;

    if force {
        cache::clear_file(scanning_cache_path).await?;
    }

    // Load target CIDRs: from --ip flag, or merge whois-cidr.jsonl + xlsx-rows.jsonl.
    let cidrs: Vec<IpNet> = if let Some(cidr_str) = ip {
        let net: IpNet = cidr_str
            .parse()
            .with_context(|| format!("invalid CIDR: {cidr_str}"))?;
        tracing::info!(cidr = %net, "scan: using single CIDR from --ip flag");
        vec![net]
    } else {
        let whois_path = Path::new("data/whois-cidr.jsonl");
        let records = load_cidrs(whois_path).await.with_context(|| {
            format!(
                "failed to load whois CIDRs from {}; run 'import --whois' or 'import --xlsx' first",
                whois_path.display()
            )
        })?;
        let xlsx_cidrs = mmdb_scan::load_xlsx_cidrs(Path::new("data/xlsx-rows.jsonl"))
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "scan: failed to load xlsx CIDRs, skipping");
                Vec::new()
            });

        // Merge and deduplicate; whois CIDRs take precedence in order.
        let mut seen = std::collections::HashSet::new();
        let merged: Vec<IpNet> = records
            .into_iter()
            .filter_map(|rec| rec.network.parse::<IpNet>().ok())
            .chain(xlsx_cidrs)
            .filter(|net| seen.insert(*net))
            .collect();

        if merged.is_empty() {
            tracing::warn!("scan: no CIDRs found from whois or xlsx sources; nothing to scan");
            return Ok(());
        }
        tracing::info!(total = merged.len(), "scan: CIDRs loaded from whois + xlsx");
        merged
    };

    // Prune stale records from the cache (only in CIDR-range mode, not --ip).
    if ip.is_none() {
        prune_stale_cache(scanning_cache_path, &cidrs).await?;
    }

    mmdb_scan::run(
        config,
        &cidrs,
        mmdb_scan::ScanOptions {
            full,
            cache_path: scanning_cache_path.to_path_buf(),
        },
    )
    .await
}

/// Remove records from `scanning.jsonl` whose `range` CIDR is not in `current_cidrs`.
///
/// Reads the cache file, discards any line whose parsed `range` is absent from
/// `current_cidrs`, and atomically rewrites the file only when stale records are
/// found.  Does nothing if the file does not exist or all records are current.
///
/// # Errors
///
/// Returns an error if reading, writing, or renaming the cache file fails.
// NOTEST(io): reads and atomically rewrites scanning.jsonl — filesystem I/O
#[cfg_attr(coverage_nightly, coverage(off))]
async fn prune_stale_cache(cache_path: &Path, current_cidrs: &[IpNet]) -> Result<()> {
    let raw = match tokio::fs::read_to_string(cache_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| format!("failed to read {}", cache_path.display()));
        }
    };

    let current: HashSet<IpNet> = current_cidrs.iter().copied().collect();
    let (kept, pruned) = partition_scan_lines(&raw, &current);

    if pruned == 0 {
        return Ok(());
    }

    tracing::info!(
        pruned,
        kept,
        path = %cache_path.display(),
        "scan: pruning stale records from cache"
    );

    let tmp_path = cache_path.with_extension("jsonl.pruning");
    tokio::fs::write(&tmp_path, kept.as_bytes())
        .await
        .with_context(|| format!("failed to write pruned cache to {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, cache_path)
        .await
        .with_context(|| {
            format!(
                "failed to rename {} to {}",
                tmp_path.display(),
                cache_path.display()
            )
        })?;

    Ok(())
}

/// Partition JSONL lines into (`kept_string`, `pruned_count`).
///
/// Lines whose `range` field parses to an `IpNet` present in `current` are
/// kept; all others (stale CIDRs or unparseable lines) are dropped.
fn partition_scan_lines(raw: &str, current: &HashSet<IpNet>) -> (String, usize) {
    let mut kept = String::with_capacity(raw.len());
    let mut pruned: usize = 0;

    for line in raw.lines() {
        match serde_json::from_str::<ScanRecord>(line) {
            Ok(record)
                if record
                    .range
                    .parse::<IpNet>()
                    .is_ok_and(|net| current.contains(&net)) =>
            {
                kept.push_str(line);
                kept.push('\n');
            }
            _ => {
                pruned = pruned.saturating_add(1);
            }
        }
    }

    (kept, pruned)
}

/// Read `data/whois-cidr.jsonl` and return all whois records.
// NOTEST(io): reads whois JSONL file from filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
async fn load_cidrs(path: &Path) -> Result<Vec<WhoisRecord>> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut records = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let record: WhoisRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse whois record at line {}",
                i.saturating_add(1)
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scan_line(range: &str, dst: &str) -> String {
        format!(
            r#"{{"range":"{range}","routes":{{"version":"0.1","measured_at":"2001-01-01T00:00:00Z","source":"198.51.100.1","destination":"{dst}","stop_reason":"COMPLETED","hops":[]}}}}"#
        )
    }

    fn current(cidrs: &[&str]) -> HashSet<IpNet> {
        cidrs.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn partition_keeps_records_in_current_cidrs() {
        let line = make_scan_line("198.51.100.0/24", "198.51.100.1");
        let cidrs = current(&["198.51.100.0/24"]);
        let (kept, pruned) = partition_scan_lines(&line, &cidrs);
        assert_eq!(pruned, 0);
        assert!(kept.contains("198.51.100.0/24"));
    }

    #[test]
    fn partition_prunes_records_not_in_current_cidrs() {
        let old = make_scan_line("203.0.113.0/24", "203.0.113.1");
        let cidrs = current(&["198.51.100.0/24"]);
        let (kept, pruned) = partition_scan_lines(&old, &cidrs);
        assert_eq!(pruned, 1);
        assert!(kept.is_empty());
    }

    #[test]
    fn partition_mixed_keeps_only_current() {
        let current_line = make_scan_line("198.51.100.0/24", "198.51.100.1");
        let stale_line = make_scan_line("203.0.113.0/24", "203.0.113.1");
        let raw = format!("{current_line}\n{stale_line}\n");
        let cidrs = current(&["198.51.100.0/24"]);
        let (kept, pruned) = partition_scan_lines(&raw, &cidrs);
        assert_eq!(pruned, 1);
        assert!(kept.contains("198.51.100.0/24"));
        assert!(!kept.contains("203.0.113.0/24"));
    }

    #[test]
    fn partition_empty_input_returns_empty() {
        let cidrs = current(&["198.51.100.0/24"]);
        let (kept, pruned) = partition_scan_lines("", &cidrs);
        assert_eq!(pruned, 0);
        assert!(kept.is_empty());
    }

    #[test]
    fn partition_unparseable_line_is_pruned() {
        let cidrs = current(&["198.51.100.0/24"]);
        let (kept, pruned) = partition_scan_lines("not-valid-json", &cidrs);
        assert_eq!(pruned, 1);
        assert!(kept.is_empty());
    }
}
