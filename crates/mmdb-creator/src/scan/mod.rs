//! Scan subcommand: probe CIDRs with scamper icmp-paris for demarc discovery.

pub mod daemon;
pub mod enrich;
pub mod resume;
pub mod socket;
pub mod writer;

use std::path::Path;

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{
    config::{Config, ScanConfig},
    external,
    types::{ScanRecord, WhoisRecord},
};
use tokio::io::{AsyncWriteExt as _, BufReader};

use crate::cache;

/// Run the scan subcommand.
pub async fn run(config: &Config, force: bool, enrich_only: bool, ip: Option<&str>) -> Result<()> {
    if enrich_only {
        return enrich::run(config).await;
    }

    if force {
        cache::clear_file(Path::new("data/cache/scan/scanning.jsonl")).await?;
    }

    external::require_commands(&["scamper"])?;

    let scan_cfg = config.scan.clone().unwrap_or_default();

    // Load target CIDRs: from --ip flag or whois-cidr.jsonl.
    let cidrs: Vec<IpNet> = if let Some(cidr_str) = ip {
        let net: IpNet = cidr_str
            .parse()
            .with_context(|| format!("invalid CIDR: {cidr_str}"))?;
        tracing::info!(cidr = %net, "scan: using single CIDR from --ip flag");
        vec![net]
    } else {
        let whois_path = Path::new("data/whois-cidr.jsonl");
        let cidrs = load_cidrs(whois_path).await.with_context(|| {
            format!(
                "failed to load whois CIDRs from {}; run 'import --whois' first",
                whois_path.display()
            )
        })?;
        if cidrs.is_empty() {
            tracing::warn!(
                "scan: no CIDRs found in {}; nothing to scan",
                whois_path.display()
            );
            return Ok(());
        }
        cidrs
    };

    // Expand CIDRs to target IPs.
    let all_targets = resume::expand_cidrs(&cidrs);
    let total = all_targets.len();
    tracing::info!(
        cidrs = cidrs.len(),
        targets = total,
        "scan: target IPs generated"
    );

    // Resume: skip already-scanned IPs.
    let scan_path = Path::new("data/cache/scan/scanning.jsonl");
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
    let writer = writer::spawn_writer(
        scan_path.to_path_buf(),
        scan_cfg.flush_count,
        flush_interval,
    )
    .await?;

    // Spawn the scamper daemon.
    let mut daemon = daemon::ScamperDaemon::spawn(scan_cfg.pps).await?;

    let result = scan_loop(
        daemon.stream(),
        &remaining,
        &all_targets,
        &writer,
        &scan_cfg,
    )
    .await;

    // Always shut down writer and daemon, even on error.
    if let Err(e) = writer.shutdown().await {
        tracing::warn!(error = %e, "scan: writer shutdown error");
    }
    if let Err(e) = daemon.shutdown().await {
        tracing::warn!(error = %e, "scan: daemon shutdown error");
    }

    result?;

    // Post-scan enrichment: ASN filter + renumber + PTR.
    enrich::run(config).await
}

/// Run the trace loop using the scamper daemon control socket protocol.
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
async fn scan_loop(
    stream: &mut tokio::net::UnixStream,
    remaining: &[&(IpNet, std::net::IpAddr)],
    all_targets: &[(IpNet, std::net::IpAddr)],
    writer: &writer::WriterHandle,
    cfg: &ScanConfig,
) -> Result<()> {
    let total_remaining = remaining.len();
    let start_time = std::time::Instant::now();

    // Build a lookup: destination IP → parent CIDR.
    let cidr_by_ip: std::collections::HashMap<std::net::IpAddr, IpNet> =
        all_targets.iter().map(|(cidr, ip)| (*ip, *cidr)).collect();

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
                                let record = ScanRecord {
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

/// Read `data/whois-cidr.jsonl` and return all CIDR prefixes.
async fn load_cidrs(path: &Path) -> Result<Vec<IpNet>> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut cidrs = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let record: WhoisRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse whois record at line {}",
                i.saturating_add(1)
            )
        })?;
        if let Ok(net) = record.network.parse::<IpNet>() {
            cidrs.push(net);
        }
    }
    Ok(cidrs)
}
