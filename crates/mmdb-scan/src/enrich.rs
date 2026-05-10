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
    types::{ScanGwRecord, ScanRecord, WhoisData, WhoisRecord},
};

use crate::ptr_parse;

/// Run the enrichment phase.
///
/// Reads `data/cache/scan/scanning.jsonl`, filters hops to the target ASN range,
/// renumbers TTLs, and resolves Cymru ASN and PTR records via `DoH`.
///
/// Writes two outputs atomically:
/// - `data/cache/scan/scanned.jsonl` — per-IP enriched [`ScanRecord`]s
/// - `data/scanned.jsonl` — range-aggregated [`ScanGwRecord`]s (one per CIDR)
///
/// # Errors
///
/// Returns an error if any I/O or JSON operation fails.
// NOTEST(io): reads/writes JSONL files + DNS enrichment — depends on filesystem and DoH
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
pub async fn run(config: &Config) -> Result<()> {
    let whois_path = Path::new("data/whois-cidr.jsonl");
    let scan_path = Path::new("data/cache/scan/scanning.jsonl");
    let per_ip_path = Path::new("data/cache/scan/scanned.jsonl");
    let out_path = Path::new("data/scanned.jsonl");

    if !scan_path.exists() {
        tracing::info!("scan: no scanning.jsonl found, skipping enrichment");
        return Ok(());
    }

    // Load the target prefix set and whois metadata from whois-cidr.jsonl.
    let (mut prefixes, whois_index) = load_whois_index(whois_path).await.with_context(|| {
        format!(
            "failed to load whois prefixes from {}",
            whois_path.display()
        )
    })?;

    // Merge xlsx CIDRs into the prefix set so hops within xlsx-only ranges
    // are not filtered out during hop filtering.
    let xlsx_path = Path::new("data/xlsx-rows.jsonl");
    let xlsx_cidrs = crate::load_xlsx_cidrs(xlsx_path).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "enrich: failed to load xlsx CIDRs, skipping");
        Vec::new()
    });
    let existing: std::collections::HashSet<IpNet> = prefixes.iter().copied().collect();
    for net in xlsx_cidrs {
        if existing.contains(&net) {
            continue;
        }
        prefixes.push(net);
    }
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

    sort_by_range(&mut records);

    // Write per-IP enriched records to data/cache/scan/scanned.jsonl (atomic).
    let tmp_per_ip = per_ip_path.with_extension("jsonl.tmp");
    write_jsonl(&tmp_per_ip, &records).await?;
    crate::backup::rotate_backup(per_ip_path, 5)
        .await
        .with_context(|| format!("failed to rotate backup for {}", per_ip_path.display()))?;
    tokio::fs::rename(&tmp_per_ip, per_ip_path)
        .await
        .context("failed to atomically write cache/scan/scanned.jsonl")?;
    tracing::info!(
        records = records.len(),
        path = %per_ip_path.display(),
        "enrich: per-IP records written"
    );

    // Compile PTR patterns once for GW resolution.
    let ptr_patterns = ptr_parse::compile(
        &config
            .scan
            .as_ref()
            .map_or_else(Vec::new, |s| s.ptr_patterns.clone()),
    )
    .context("failed to compile ptr_patterns")?;

    // GW resolution: aggregate per-range.
    let mut gw_records = crate::gw::resolve(&records, &ptr_patterns, &whois_index);
    tracing::info!(
        ranges = gw_records.len(),
        "enrich: gateway resolution complete"
    );

    // PTR-to-xlsx and CIDR-to-xlsx matching.
    let xlsx_rows_path = Path::new("data/xlsx-rows.jsonl");
    match crate::xlsx_match::XlsxMatcher::build(xlsx_rows_path, config) {
        Ok(matcher) if !matcher.is_empty() => {
            let mut matched_count = 0usize;
            for rec in &mut gw_records {
                matcher.attach(rec);
                if rec.xlsx.as_ref().is_some_and(|m| !m.is_empty()) {
                    matched_count = matched_count.saturating_add(1);
                }
            }
            tracing::info!(
                matched = matched_count,
                total = gw_records.len(),
                "enrich: xlsx matching complete"
            );
        }
        Ok(_) => {
            tracing::debug!("enrich: no xlsx candidates; skipping xlsx matching");
        }
        Err(e) => {
            tracing::warn!(error = %e, "enrich: xlsx matching failed; skipping");
        }
    }

    // Populate derived boolean fields before writing.
    for record in &mut gw_records {
        record.xlsx_matched = record.xlsx.as_ref().is_some_and(|m| !m.is_empty());
        record.gateway_found = record.gateway.status == "inservice";
    }

    // Write range-aggregated GW records to data/scanned.jsonl (atomic).
    let tmp_path = out_path.with_extension("jsonl.tmp");
    write_gw_jsonl(&tmp_path, &gw_records).await?;
    crate::backup::rotate_backup(out_path, 5)
        .await
        .with_context(|| format!("failed to rotate backup for {}", out_path.display()))?;
    tokio::fs::rename(&tmp_path, out_path)
        .await
        .context("failed to atomically write scanned.jsonl")?;

    tracing::info!(
        records = gw_records.len(),
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

/// Sort records by CIDR range: IPv4 before IPv6, then by network address, then by prefix length.
/// Records with unparseable ranges sort after valid ones, falling back to lexicographic order.
fn sort_by_range(records: &mut [ScanRecord]) {
    records.sort_by(|a, b| {
        let a_net: Option<IpNet> = a.range.parse().ok();
        let b_net: Option<IpNet> = b.range.parse().ok();
        match (a_net, b_net) {
            (Some(an), Some(bn)) => an.cmp(&bn),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.range.cmp(&b.range),
        }
    });
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

/// Load all network prefixes and whois metadata from `data/whois-cidr.jsonl`.
///
/// Returns `(prefixes, whois_index)` where `prefixes` is used for hop filtering
/// and `whois_index` carries metadata joined during GW resolution.
// NOTEST(io): reads whois JSONL from filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
async fn load_whois_index(
    path: &Path,
) -> Result<(Vec<IpNet>, std::collections::HashMap<IpNet, WhoisData>)> {
    if !path.exists() {
        return Ok((Vec::new(), std::collections::HashMap::new()));
    }

    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut nets = Vec::new();
    let mut index = std::collections::HashMap::new();
    for line in raw.lines() {
        if let Ok(record) = serde_json::from_str::<WhoisRecord>(line)
            && let Ok(net) = record.network.parse::<IpNet>()
        {
            nets.push(net);
            index.insert(net, record.whois);
        }
    }
    Ok((nets, index))
}

/// Write a list of [`ScanGwRecord`]s to a file as JSONL.
// NOTEST(io): writes JSONL file to filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
async fn write_gw_jsonl(path: &Path, records: &[ScanGwRecord]) -> Result<()> {
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
            serde_json::to_string(record).context("failed to serialize ScanGwRecord to JSON")?;
        file.write_all(line.as_bytes())
            .await
            .context("failed to write JSONL line")?;
        file.write_all(b"\n")
            .await
            .context("failed to write newline")?;
    }
    file.flush().await.context("failed to flush GW scan file")?;
    Ok(())
}

/// Write a list of [`ScanRecord`]s to a file as JSONL.
// NOTEST(io): writes JSONL file to filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
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

    fn record_with_range(range: &str) -> ScanRecord {
        make_record_range(range, "198.51.100.1", &[])
    }

    fn make_record_range(range: &str, dst: &str, hop_ips: &[&str]) -> ScanRecord {
        let mut r = make_record(dst, hop_ips);
        r.range = range.to_owned();
        r
    }

    #[test]
    fn sort_by_range_orders_ipv4_numerically() {
        let mut records = vec![
            record_with_range("198.51.100.128/25"),
            record_with_range("198.51.100.0/25"),
            record_with_range("198.51.100.0/24"),
        ];
        sort_by_range(&mut records);
        assert_eq!(records[0].range, "198.51.100.0/24");
        assert_eq!(records[1].range, "198.51.100.0/25");
        assert_eq!(records[2].range, "198.51.100.128/25");
    }

    #[test]
    fn sort_by_range_ipv4_before_ipv6() {
        let mut records = vec![
            record_with_range("2001:db8::/32"),
            record_with_range("198.51.100.0/24"),
        ];
        sort_by_range(&mut records);
        assert_eq!(records[0].range, "198.51.100.0/24");
        assert_eq!(records[1].range, "2001:db8::/32");
    }

    #[test]
    fn sort_by_range_invalid_range_sorts_last() {
        let mut records = vec![
            record_with_range("not-a-cidr"),
            record_with_range("198.51.100.0/24"),
        ];
        sort_by_range(&mut records);
        assert_eq!(records[0].range, "198.51.100.0/24");
        assert_eq!(records[1].range, "not-a-cidr");
    }
}
