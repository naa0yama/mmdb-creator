//! mmdb-scan: scamper-based network scan pipeline.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod backup;
pub mod gw;
pub mod normalize;
pub mod ptr_parse;
pub mod resume;
pub mod socket;

#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod enrich;
#[cfg(unix)]
mod writer;
#[cfg(unix)]
mod xlsx_match;

use std::path::Path;

use anyhow::{Context as _, Result};
use ipnet::IpNet;

/// Run the scan pipeline: expand CIDRs, run scamper traces, then enrich results.
///
/// The caller (mmdb-cli) is responsible for loading CIDRs and handling `--force`
/// (cache clearing) before calling this function.
///
/// # Errors
///
/// Returns an error if scamper cannot be spawned, I/O fails, or enrichment fails.
// NOTEST(io): orchestrates scamper binary + file I/O — requires scamper on PATH
#[cfg(unix)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run(
    config: &mmdb_core::config::Config,
    cidrs: &[IpNet],
    options: ScanOptions,
) -> Result<()> {
    use mmdb_core::external;

    external::require_commands(&["scamper"])?;

    let scan_cfg = config.scan.clone().unwrap_or_default();

    let scan_path = &options.cache_path;

    // Expand CIDRs to target IPs.
    let all_targets = resume::expand_cidrs(cidrs, options.full);
    let total = all_targets.len();
    tracing::info!(
        cidrs = cidrs.len(),
        targets = total,
        "scan: target IPs generated"
    );

    // Resume: skip already-scanned IPs.
    let done = resume::load_completed(scan_path).await?;
    let remaining = resume::compute_remaining(&all_targets, &done);
    let skipped = total.saturating_sub(remaining.len());
    tracing::info!(
        total,
        skipped,
        remaining = remaining.len(),
        "scan: resume check complete"
    );

    if remaining.is_empty() {
        tracing::info!("scan: all targets already scanned; running enrichment only");
        return enrich::run(config).await;
    }

    // Spawn the JSONL writer.
    let flush_interval = std::time::Duration::from_secs(scan_cfg.flush_interval_sec);
    let writer_handle =
        writer::spawn_writer(scan_path.clone(), scan_cfg.flush_count, flush_interval).await?;

    // Spawn the scamper daemon.
    let mut daemon = daemon::ScamperDaemon::spawn(scan_cfg.pps).await?;

    let result = scan_loop(
        daemon.stream(),
        &remaining,
        &all_targets,
        &writer_handle,
        &scan_cfg,
    )
    .await;

    // Always shut down writer and daemon, even on error.
    if let Err(e) = writer_handle.shutdown().await {
        tracing::warn!(error = %e, "scan: writer shutdown error");
    }
    if let Err(e) = daemon.shutdown().await {
        tracing::warn!(error = %e, "scan: daemon shutdown error");
    }

    result?;

    // Post-scan enrichment: ASN filter + renumber + PTR.
    enrich::run(config).await
}

/// Options controlling the scan pipeline.
#[derive(Debug)]
pub struct ScanOptions {
    /// When `true`, probe every usable host in each CIDR instead of a sample.
    pub full: bool,
    /// Path to the incremental scan cache (`data/cache/scan/scanning.jsonl`).
    pub cache_path: std::path::PathBuf,
}

/// Run the trace loop using the scamper daemon control socket protocol.
// NOTEST(io): Unix socket I/O loop talking to scamper daemon — requires scamper binary
#[cfg(unix)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
async fn scan_loop(
    stream: &mut tokio::net::UnixStream,
    remaining: &[&(IpNet, std::net::IpAddr)],
    all_targets: &[(IpNet, std::net::IpAddr)],
    writer: &writer::WriterHandle,
    cfg: &mmdb_core::config::ScanConfig,
) -> Result<()> {
    use tokio::io::{AsyncWriteExt as _, BufReader};

    let total_remaining = remaining.len();
    let start_time = std::time::Instant::now();

    // Build a lookup: destination IP → parent CIDR, preferring the most specific
    // (longest-prefix) CIDR when the same IP appears in both whois and xlsx targets.
    // Hosting xlsx rows contribute /32 entries that must win over whois /24 entries
    // so that hosting exact-CIDR matching works correctly in the enrich phase.
    let mut cidr_by_ip: std::collections::HashMap<std::net::IpAddr, IpNet> =
        std::collections::HashMap::new();
    for (cidr, ip) in all_targets {
        cidr_by_ip
            .entry(*ip)
            .and_modify(|existing| {
                if cidr.prefix_len() > existing.prefix_len() {
                    *existing = *cidr;
                }
            })
            .or_insert(*cidr);
    }

    let window = cfg.window;
    let probes = cfg.probes;

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let mut target_iter = remaining.iter().peekable();

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut in_flight: usize = 0;
    let mut submitted: usize = 0;
    let mut completed: usize = 0;

    loop {
        if target_iter.peek().is_none() && in_flight == 0 {
            break;
        }

        tokio::select! {
            biased;

            // Ctrl+C — highest priority so the user is never kept waiting.
            _ = &mut ctrl_c => {
                tracing::info!("scan: Ctrl+C received, stopping scan");
                break;
            }

            // Reader — process scamper results ahead of new submissions so that
            // completed slots are freed before we ask for more work.
            msg_result = socket::read_msg(&mut reader) => {
                let Some(msg) = msg_result.context("error reading scamper message")? else {
                    tracing::warn!("scan: scamper daemon closed the socket unexpectedly");
                    break;
                };
                match msg {
                    // Flow-control messages are no-ops: the writer arm drives
                    // submission via the in_flight guard, not scamper's MORE signal.
                    socket::ScamperMsg::Ok
                    | socket::ScamperMsg::More
                    | socket::ScamperMsg::OkId => {}
                    socket::ScamperMsg::Data(bytes) => {
                        match socket::parse_data_block(&bytes) {
                            Ok(Some(socket::WartsOutcome::Trace(route))) => {
                                let dst_ip = route.destination.parse::<std::net::IpAddr>().ok();
                                let Some(range) = dst_ip.and_then(|ip| cidr_by_ip.get(&ip).copied()) else {
                                    tracing::warn!(
                                        dst = %route.destination,
                                        "scan: no CIDR found for destination, skipping"
                                    );
                                    in_flight = in_flight.saturating_sub(1);
                                    continue;
                                };
                                let record = mmdb_core::types::ScanRecord {
                                    range: range.to_string(),
                                    routes: route,
                                };
                                completed = completed.saturating_add(1);
                                tracing::info!(
                                    completed,
                                    total = total_remaining,
                                    dst = %record.routes.destination,
                                    hops = record.routes.hops.len(),
                                    "scan: trace complete"
                                );
                                writer.send(record).await?;
                                in_flight = in_flight.saturating_sub(1);
                            }
                            Ok(Some(socket::WartsOutcome::Meta(warts_type))) => {
                                tracing::debug!(
                                    warts_type,
                                    "scan: received non-trace DATA block, skipping"
                                );
                            }
                            Ok(None) => {
                                tracing::debug!("scan: received empty DATA block, skipping");
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "scan: failed to parse DATA block");
                            }
                        }
                    }
                    socket::ScamperMsg::Err(e) => {
                        tracing::warn!(error = %e, "scan: scamper returned error");
                        in_flight = in_flight.saturating_sub(1);
                    }
                    socket::ScamperMsg::Unknown(line) => {
                        if !line.is_empty() {
                            tracing::debug!(line = %line, "scan: unrecognised scamper message");
                        }
                    }
                }
            }

            // Writer arm — fires immediately (zero-cost future) whenever the
            // pipeline has capacity and targets remain.  No pre-fill or idle
            // timer needed: this arm fills the window on every loop iteration.
            () = async {}, if in_flight < window && target_iter.peek().is_some() => {
                let Some((_, ip)) = target_iter.next() else { continue; };
                submitted = submitted.saturating_add(1);
                let elapsed = start_time.elapsed();
                // Percent: compute in scaled integer arithmetic to avoid float casts.
                // percent_x100 gives two decimal places (e.g. 4250 = "42.50 %").
                let percent_x100 = submitted
                    .saturating_mul(10_000)
                    .checked_div(total_remaining)
                    .unwrap_or(0);
                let percent = format!(
                    "{}.{:02}",
                    percent_x100.checked_div(100).unwrap_or(0),
                    percent_x100.checked_rem(100).unwrap_or(0)
                );
                // ETA: integer arithmetic avoids usize→f64 precision loss and
                // the f64→u64 truncation/sign-loss warnings.
                let eta_secs: u64 = if submitted > 0 {
                    let remaining_count = total_remaining.saturating_sub(submitted);
                    let elapsed_secs = elapsed.as_secs();
                    let submitted_u64 = u64::try_from(submitted).unwrap_or(1);
                    let remaining_u64 = u64::try_from(remaining_count).unwrap_or(0);
                    elapsed_secs
                        .saturating_mul(remaining_u64)
                        .checked_div(submitted_u64)
                        .unwrap_or(0)
                } else {
                    0
                };
                tracing::info!(
                    ip = %ip,
                    submitted,
                    total = total_remaining,
                    percent,
                    elapsed = fmt_hms(elapsed.as_secs()),
                    eta = fmt_hms(eta_secs),
                    "scan: submitting trace"
                );
                write_half
                    .write_all(socket::format_command(&ip.to_string(), probes).as_bytes())
                    .await
                    .context("failed to send trace command to scamper")?;
                in_flight = in_flight.saturating_add(1);
            }
        }
    }

    tracing::info!(submitted, completed, "scan: loop finished");

    Ok(())
}

/// Format a duration in seconds as `HHhMMmSSs`.
fn fmt_hms(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}h{m:02}m{s:02}s")
}

/// Extract all CIDR prefixes from an xlsx-rows JSONL file.
///
/// Each line is parsed as a JSON object; any value that is a JSON array of
/// strings is checked for parseable [`IpNet`] values.  Non-CIDR strings are
/// silently skipped.  If the file does not exist, an empty `Vec` is returned.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read.
pub fn load_xlsx_cidrs(path: &Path) -> Result<Vec<IpNet>> {
    if !path.exists() {
        tracing::debug!(
            path = %path.display(),
            "scan: xlsx-rows.jsonl not found, skipping xlsx CIDRs"
        );
        return Ok(Vec::new());
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut cidrs: Vec<IpNet> = Vec::new();
    for line in raw.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(obj) = value.as_object() else {
            continue;
        };
        for (key, val) in obj {
            if key == "_source" {
                continue;
            }
            if let Some(arr) = val.as_array() {
                for item in arr {
                    if let Some(s) = item.as_str()
                        && let Ok(net) = s.parse::<IpNet>()
                    {
                        cidrs.push(net);
                    }
                }
            }
        }
    }
    Ok(cidrs)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use ipnet::IpNet;
    use tempfile::NamedTempFile;

    use super::load_xlsx_cidrs;

    #[test]
    fn load_xlsx_cidrs_missing_file_returns_empty() {
        let result = load_xlsx_cidrs(std::path::Path::new("/nonexistent/xlsx-rows.jsonl"));
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn load_xlsx_cidrs_extracts_address_fields() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"{{"_source":{{"file":"A.xlsx","sheet":"s1","row_index":0}},"host":"rtr0101","network":["198.51.100.0/29","198.51.100.8/29"]}}"#
        )
        .unwrap();
        let cidrs = load_xlsx_cidrs(f.path()).unwrap();
        let expected: Vec<IpNet> = vec![
            "198.51.100.0/29".parse().unwrap(),
            "198.51.100.8/29".parse().unwrap(),
        ];
        assert_eq!(cidrs, expected);
    }

    #[test]
    fn load_xlsx_cidrs_skips_non_address_fields() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"{{"_source":{{"file":"A.xlsx","sheet":"s1","row_index":0}},"host":"rtr0101","vlanid":100}}"#
        )
        .unwrap();
        let cidrs = load_xlsx_cidrs(f.path()).unwrap();
        assert!(cidrs.is_empty());
    }

    #[test]
    fn load_xlsx_cidrs_deduplicates() {
        let mut f = NamedTempFile::new().unwrap();
        // Two rows with the same CIDR.
        writeln!(
            f,
            r#"{{"_source":{{"file":"A.xlsx","sheet":"s1","row_index":0}},"network":["198.51.100.0/24"]}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"_source":{{"file":"A.xlsx","sheet":"s1","row_index":1}},"network":["198.51.100.0/24"]}}"#
        )
        .unwrap();
        let cidrs = load_xlsx_cidrs(f.path()).unwrap();
        // Dedup happens at merge time; raw load returns duplicates.
        // This test verifies the raw load finds both (pre-merge).
        assert_eq!(cidrs.len(), 2);
    }
}
