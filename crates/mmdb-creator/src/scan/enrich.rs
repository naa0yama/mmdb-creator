//! Post-scan enrichment: ASN hop filter, TTL renumber, Cymru ASN, and PTR reverse lookup.
//!
//! Phase 1 (network-free):
//!   - Load target ASN prefixes from `data/whois-cidr.jsonl`
//!   - Filter each [`ScanRecord`]'s hops to only those within the target CIDR
//!   - Renumber remaining hops from the minimum matched TTL, starting at 1
//!
//! Phase 2 (DNS-over-HTTPS via mmdb-dns):
//!   - Resolve Team Cymru ASN data and PTR records for all hop IPs in one call

use std::{collections::HashSet, net::IpAddr, path::Path};

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{
    config::Config,
    types::{ScanRecord, WhoisRecord},
};

/// Run the enrichment phase.
///
/// Reads `data/cache/scan/scanning.jsonl`, filters hops to the target ASN range,
/// renumbers TTLs, resolves Cymru ASN and PTR records via `DoH`, then atomically
/// writes the enriched data to `data/scanned.jsonl`.
///
/// # Errors
///
/// Returns an error if any I/O or JSON operation fails.
pub async fn run(config: &Config) -> Result<()> {
    let whois_path = Path::new("data/whois-cidr.jsonl");
    let scan_path = Path::new("data/cache/scan/scanning.jsonl");
    let out_path = Path::new("data/scanned.jsonl");

    if !scan_path.exists() {
        tracing::info!("scan: no scanning.jsonl found, skipping enrichment");
        return Ok(());
    }

    // Load the target prefix set from whois-cidr.jsonl.
    let prefixes = load_prefixes(whois_path).await.with_context(|| {
        format!(
            "failed to load whois prefixes from {}",
            whois_path.display()
        )
    })?;
    tracing::info!(count = prefixes.len(), "enrich: loaded target prefixes");

    // Read all scan records.
    let raw = tokio::fs::read_to_string(scan_path)
        .await
        .with_context(|| format!("failed to read {}", scan_path.display()))?;

    let mut records: Vec<ScanRecord> = raw
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            serde_json::from_str(line)
                .map_err(|e| {
                    tracing::warn!(
                        line = i.saturating_add(1),
                        error = %e,
                        "enrich: skipping unparseable scan record"
                    );
                    e
                })
                .ok()
        })
        .collect();

    tracing::info!(count = records.len(), "enrich: loaded scan records");

    // Phase 1: filter hops + renumber.
    for record in &mut records {
        let target_cidr: Option<IpNet> = record.range.parse().ok();
        filter_and_renumber(record, &prefixes, target_cidr);
    }

    // Phase 2: DNS enrichment (Cymru ASN + PTR) via DoH.
    let all_hop_ips: Vec<IpAddr> = records
        .iter()
        .flat_map(|r| r.routes.hops.iter())
        .filter_map(|h| h.ip.as_ref()?.parse::<IpAddr>().ok())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    if !all_hop_ips.is_empty() {
        let dns_config = build_dns_config(config.scan.as_ref());

        tracing::info!(
            count = all_hop_ips.len(),
            "enrich: starting DNS enrichment (Cymru + PTR)"
        );
        let dns_results = mmdb_dns::enrich(&all_hop_ips, &dns_config)
            .await
            .context("DNS enrichment (Cymru + PTR) failed")?;
        tracing::info!(
            resolved = dns_results.len(),
            "enrich: DNS enrichment complete"
        );

        for record in &mut records {
            for hop in &mut record.routes.hops {
                if let Some(ref ip_str) = hop.ip
                    && let Ok(ip) = ip_str.parse::<IpAddr>()
                    && let Some(result) = dns_results.get(&ip)
                {
                    hop.asn = result.asn;
                    hop.ptr.clone_from(&result.ptr);
                }
            }
        }
    }

    // Atomic write: write to a temp file then rename.
    let tmp_path = out_path.with_extension("jsonl.tmp");
    write_jsonl(&tmp_path, &records).await?;
    tokio::fs::rename(&tmp_path, out_path)
        .await
        .context("failed to atomically write scanned.jsonl")?;

    tracing::info!(
        records = records.len(),
        path = %out_path.display(),
        "enrich: done"
    );
    Ok(())
}

/// Build a [`mmdb_dns::DnsConfig`] from an optional [`mmdb_core::config::ScanConfig`].
///
/// Reads `dns_concurrency` and `doh_server` from the scan config when present.
/// Falls back to [`mmdb_dns::DnsConfig::default()`] for any missing fields.
fn build_dns_config(scan: Option<&mmdb_core::config::ScanConfig>) -> mmdb_dns::DnsConfig {
    let Some(scan) = scan else {
        return mmdb_dns::DnsConfig::default();
    };

    let doh_server = match scan.doh_server.as_str() {
        "google" => mmdb_dns::DohServer::Google,
        "quad9" => mmdb_dns::DohServer::Quad9,
        _ => mmdb_dns::DohServer::Cloudflare,
    };

    mmdb_dns::DnsConfig {
        max_concurrency: scan.dns_concurrency,
        doh_server,
        ..mmdb_dns::DnsConfig::default()
    }
}

/// Filter hops to those whose IP falls within any of the known target prefixes,
/// then renumber the surviving hops starting from 1.
///
/// The `target_cidr` hint is used to derive the ASN: the hop's ASN is set to the
/// ASN number of the matching prefix if the record's CIDR is found in `prefixes`.
fn filter_and_renumber(record: &mut ScanRecord, prefixes: &[IpNet], _target_cidr: Option<IpNet>) {
    // Filter and renumber in a single pass.
    let renumbered: Vec<_> = record
        .routes
        .hops
        .iter()
        .filter(|hop| {
            hop.ip
                .as_ref()
                .and_then(|ip_str| ip_str.parse::<IpAddr>().ok())
                .is_some_and(|ip| prefixes.iter().any(|net| net.contains(&ip)))
        })
        .cloned()
        .enumerate()
        .map(|(i, mut hop)| {
            hop.hop = u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX);
            hop
        })
        .collect();

    record.routes.hops = renumbered;
}

/// Load all network prefixes from `data/whois-cidr.jsonl`.
async fn load_prefixes(path: &Path) -> Result<Vec<IpNet>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut nets = Vec::new();
    for line in raw.lines() {
        if let Ok(record) = serde_json::from_str::<WhoisRecord>(line)
            && let Ok(net) = record.network.parse::<IpNet>()
        {
            nets.push(net);
        }
    }
    Ok(nets)
}

/// Write a list of [`ScanRecord`]s to a file as JSONL.
async fn write_jsonl(path: &Path, records: &[ScanRecord]) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("failed to create {}", path.display()))?;

    for record in records {
        let line =
            serde_json::to_string(record).context("failed to serialize ScanRecord to JSON")?;
        file.write_all(line.as_bytes())
            .await
            .context("failed to write JSONL line")?;
        file.write_all(b"\n")
            .await
            .context("failed to write newline")?;
    }
    file.flush()
        .await
        .context("failed to flush enriched scan file")?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use mmdb_core::types::{Hop, RouteData};

    fn make_record(dst: &str, hop_ips: &[&str]) -> ScanRecord {
        let hops = hop_ips
            .iter()
            .enumerate()
            .map(|(i, ip)| Hop {
                hop: u32::try_from(i.saturating_add(1)).unwrap_or(u32::MAX),
                ip: Some((*ip).to_owned()),
                rtt_avg: Some(1.0),
                rtt_best: Some(0.9),
                rtt_worst: Some(1.1),
                icmp_type: Some(11),
                asn: None,
                ptr: None,
            })
            .collect();
        ScanRecord {
            range: String::from("192.0.2.0/29"),
            routes: RouteData {
                version: String::from("0.1"),
                measured_at: String::from("2026-05-07T00:00:00Z"),
                source: String::from("10.0.0.1"),
                destination: dst.to_owned(),
                stop_reason: String::from("COMPLETED"),
                hops,
            },
        }
    }

    fn nets(cidrs: &[&str]) -> Vec<IpNet> {
        cidrs.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn filter_keeps_only_matching_hops() {
        let mut record = make_record("192.0.2.1", &["10.0.0.1", "192.0.2.1", "203.0.113.1"]);
        let prefixes = nets(&["192.0.2.0/29"]);
        filter_and_renumber(&mut record, &prefixes, None);
        assert_eq!(record.routes.hops.len(), 1);
        assert_eq!(record.routes.hops[0].ip.as_deref(), Some("192.0.2.1"));
    }

    #[test]
    fn filter_renumbers_hops_from_one() {
        let mut record = make_record(
            "192.0.2.3",
            &["10.0.0.1", "192.0.2.1", "192.0.2.2", "192.0.2.3"],
        );
        let prefixes = nets(&["192.0.2.0/29"]);
        filter_and_renumber(&mut record, &prefixes, None);
        assert_eq!(record.routes.hops.len(), 3);
        assert_eq!(record.routes.hops[0].hop, 1);
        assert_eq!(record.routes.hops[1].hop, 2);
        assert_eq!(record.routes.hops[2].hop, 3);
    }

    #[test]
    fn filter_all_transit_produces_empty_hops() {
        let mut record = make_record("192.0.2.1", &["10.0.0.1", "172.16.0.1"]);
        let prefixes = nets(&["192.0.2.0/29"]);
        filter_and_renumber(&mut record, &prefixes, None);
        assert!(record.routes.hops.is_empty());
    }
}
