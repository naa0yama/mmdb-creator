//! Scan subcommand: thin client that delegates to mmdb-scan.

use std::path::Path;

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{config::Config, types::WhoisRecord};

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

    if force {
        cache::clear_file(Path::new("data/cache/scan/scanning.jsonl")).await?;
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

    mmdb_scan::run(
        config,
        &cidrs,
        mmdb_scan::ScanOptions {
            full,
            cache_path: "data/cache/scan/scanning.jsonl".into(),
        },
    )
    .await
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
