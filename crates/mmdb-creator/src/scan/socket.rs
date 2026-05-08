//! scamper daemon socket protocol: command formatting, warts conversion, and JSON parsing.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use mmdb_core::types::{Hop, RouteData};
use serde::Deserialize;

/// Messages received from the scamper daemon control socket.
#[derive(Debug)]
pub enum ScamperMsg {
    /// Attach command acknowledged.
    Ok,
    /// Daemon is ready to accept more commands.
    More,
    /// Trace command accepted.
    OkId,
    /// Measurement result: N bytes of warts binary data.
    Data(Vec<u8>),
    /// Error response from the daemon.
    Err(String),
    /// Unrecognised control message (logged and skipped).
    Unknown(String),
}

/// Read one message from the scamper control socket.
///
/// Handles both text control lines and binary `DATA N` blocks.
///
/// # Errors
///
/// Returns an error if I/O fails or if a `DATA N` length cannot be parsed.
pub async fn read_msg<R>(reader: &mut R) -> Result<Option<ScamperMsg>>
where
    R: tokio::io::AsyncBufReadExt + tokio::io::AsyncReadExt + Unpin,
{
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .await
        .context("failed to read line from scamper socket")?;
    if n == 0 {
        return Ok(None); // EOF
    }

    let trimmed = line.trim();

    if trimmed == "OK" {
        return Ok(Some(ScamperMsg::Ok));
    }
    if trimmed == "MORE" {
        return Ok(Some(ScamperMsg::More));
    }
    if trimmed.starts_with("OK id-") {
        return Ok(Some(ScamperMsg::OkId));
    }
    if let Some(len_str) = trimmed.strip_prefix("DATA ") {
        let len: usize = len_str
            .parse()
            .with_context(|| format!("invalid DATA length: {len_str}"))?;
        let mut data = vec![0u8; len];
        reader
            .read_exact(&mut data)
            .await
            .with_context(|| format!("failed to read {len} warts bytes from scamper"))?;
        return Ok(Some(ScamperMsg::Data(data)));
    }
    if trimmed.starts_with("ERR") {
        return Ok(Some(ScamperMsg::Err(trimmed.to_owned())));
    }

    Ok(Some(ScamperMsg::Unknown(trimmed.to_owned())))
}

/// Format a scamper icmp-paris trace command for the given target IP.
///
/// The returned string is ready to be written to the scamper daemon Unix socket.
#[must_use]
pub fn format_command(ip: &str, probes: u32) -> String {
    format!("trace -P icmp-paris -q {probes} {ip}\n")
}

/// Outcome of converting a warts DATA block.
#[derive(Debug)]
pub enum WartsOutcome {
    /// A traceroute measurement result.
    Trace(RouteData),
    /// A non-trace metadata object (e.g. `cycle-start`, `cycle-stop`).
    Meta(String),
}

/// Parse a JSON DATA block received from the scamper daemon (`attach format json`).
///
/// Returns `Ok(None)` when the block is empty or unparseable.
///
/// # Errors
///
/// Returns an error only on UTF-8 decoding failure.
pub fn parse_data_block(data: &[u8]) -> Result<Option<WartsOutcome>> {
    let json = std::str::from_utf8(data)
        .context("scamper DATA block is not valid UTF-8")?
        .trim();

    if json.is_empty() {
        return Ok(None);
    }

    tracing::trace!(json, "scan: scamper DATA block");

    let val: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "scan: failed to parse scamper DATA block as JSON");
            return Ok(None);
        }
    };

    let obj_type = val
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    if obj_type == "trace" {
        match parse_trace(json) {
            Ok(route) => return Ok(Some(WartsOutcome::Trace(route))),
            Err(e) => {
                tracing::warn!(error = %e, "scan: trace JSON found but parse_trace failed");
            }
        }
    }

    Ok(Some(WartsOutcome::Meta(obj_type.to_owned())))
}

/// Parse a scamper JSON trace response into [`RouteData`].
///
/// # Errors
///
/// Returns an error if the JSON is malformed or required fields are missing.
pub fn parse_trace(json: &str) -> Result<RouteData> {
    let raw: ScamperTrace =
        serde_json::from_str(json).context("failed to deserialize scamper trace JSON")?;

    let measured_at = {
        let sec = raw.start.sec;
        let usec = raw.start.usec.unwrap_or(0);
        let nsec = u32::try_from(usec.min(999_999))
            .unwrap_or(0)
            .saturating_mul(1000);
        chrono::DateTime::from_timestamp(
            i64::try_from(sec).context("scamper start.sec overflows i64")?,
            nsec,
        )
        .context("invalid scamper start timestamp")?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
    };

    // Group raw hop entries by probe_ttl.
    let mut groups: HashMap<u32, Vec<&ScamperHop>> = HashMap::new();
    for hop in &raw.hops {
        groups.entry(hop.probe_ttl).or_default().push(hop);
    }

    // Determine the TTL range to produce a contiguous hop list.
    let max_ttl = groups.keys().copied().max().unwrap_or(0);

    let mut hops: Vec<Hop> = Vec::with_capacity(usize::try_from(max_ttl).unwrap_or(0));

    for ttl in 1..=max_ttl {
        let Some(entries) = groups.get(&ttl) else {
            // No response at this TTL — insert a null hop.
            hops.push(Hop {
                hop: ttl,
                ip: None,
                rtt_avg: None,
                rtt_best: None,
                rtt_worst: None,
                icmp_type: None,
                asn: None,
                ptr: None,
            });
            continue;
        };

        // Collect all addresses in this TTL group.
        let addrs: Vec<&str> = entries.iter().filter_map(|h| h.addr.as_deref()).collect();

        // ICMP-Paris guarantees a single address per TTL.
        // Multiple addresses are anomalous; warn and use the majority vote.
        let ip = if addrs.is_empty() {
            None
        } else {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for a in &addrs {
                let entry = counts.entry(a).or_insert(0);
                *entry = entry.saturating_add(1);
            }
            let majority = counts.into_iter().max_by_key(|(_, c)| *c).map(|(a, _)| a);
            if addrs.iter().collect::<std::collections::HashSet<_>>().len() > 1 {
                tracing::warn!(
                    ttl,
                    addrs = ?addrs,
                    chosen = ?majority,
                    "scamper: multiple addresses at same TTL (ICMP-Paris anomaly), using majority"
                );
            }
            majority.map(str::to_owned)
        };

        // RTT statistics from all probes in this group.
        let rtts: Vec<f64> = entries.iter().filter_map(|h| h.rtt).collect();
        let (rtt_avg, rtt_best, rtt_worst) = if rtts.is_empty() {
            (None, None, None)
        } else {
            #[allow(clippy::cast_precision_loss, clippy::as_conversions)]
            let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
            let best = rtts.iter().copied().fold(f64::INFINITY, f64::min);
            let worst = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            (Some(avg), Some(best), Some(worst))
        };

        let icmp_type = entries.iter().find_map(|h| h.icmp_type);

        hops.push(Hop {
            hop: ttl,
            ip,
            rtt_avg,
            rtt_best,
            rtt_worst,
            icmp_type,
            asn: None,
            ptr: None,
        });
    }

    Ok(RouteData {
        version: raw.version.unwrap_or_else(|| String::from("unknown")),
        measured_at,
        source: raw.src,
        destination: raw.dst,
        stop_reason: raw.stop_reason,
        hops,
    })
}

// ---- scamper JSON schema (internal) ----

#[derive(Debug, Deserialize)]
struct ScamperTrace {
    #[serde(default)]
    version: Option<String>,
    src: String,
    dst: String,
    stop_reason: String,
    start: ScamperStart,
    #[serde(default)]
    hops: Vec<ScamperHop>,
}

#[derive(Debug, Deserialize)]
struct ScamperStart {
    sec: u64,
    usec: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ScamperHop {
    #[serde(rename = "addr")]
    addr: Option<String>,
    probe_ttl: u32,
    rtt: Option<f64>,
    icmp_type: Option<u8>,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_json(hops_json: &str, stop_reason: &str) -> String {
        format!(
            r#"{{
                "version": "0.1",
                "type": "trace",
                "src": "10.0.0.1",
                "dst": "192.0.2.1",
                "stop_reason": "{stop_reason}",
                "start": {{"sec": 1746489626, "usec": 0}},
                "hops": [{hops_json}]
            }}"#
        )
    }

    #[test]
    fn format_command_produces_correct_string() {
        let cmd = format_command("192.0.2.1", 3);
        assert_eq!(cmd, "trace -P icmp-paris -q 3 192.0.2.1\n");
    }

    #[test]
    fn parse_trace_normal_three_hop() {
        let hops = r#"
            {"addr":"10.1.0.1","probe_ttl":1,"probe_id":1,"rtt":0.232,"icmp_type":11},
            {"addr":"10.1.0.1","probe_ttl":1,"probe_id":2,"rtt":0.241,"icmp_type":11},
            {"addr":"10.1.0.1","probe_ttl":1,"probe_id":3,"rtt":0.228,"icmp_type":11},
            {"addr":"10.2.0.1","probe_ttl":2,"probe_id":1,"rtt":1.1,"icmp_type":11},
            {"addr":"10.2.0.1","probe_ttl":2,"probe_id":2,"rtt":1.2,"icmp_type":11},
            {"addr":"10.2.0.1","probe_ttl":2,"probe_id":3,"rtt":1.0,"icmp_type":11},
            {"addr":"192.0.2.1","probe_ttl":3,"probe_id":1,"rtt":5.0,"icmp_type":0},
            {"addr":"192.0.2.1","probe_ttl":3,"probe_id":2,"rtt":5.1,"icmp_type":0},
            {"addr":"192.0.2.1","probe_ttl":3,"probe_id":3,"rtt":4.9,"icmp_type":0}
        "#;
        let route = parse_trace(&sample_json(hops, "COMPLETED")).unwrap();
        assert_eq!(route.hops.len(), 3);
        assert_eq!(route.hops[0].hop, 1);
        assert_eq!(route.hops[0].ip.as_deref(), Some("10.1.0.1"));
        assert!(route.hops[0].rtt_avg.is_some());
        assert_eq!(route.hops[2].icmp_type, Some(0));
        assert_eq!(route.stop_reason, "COMPLETED");
    }

    #[test]
    fn parse_trace_fills_gap_with_null_hop() {
        // TTL 2 is missing → should produce a null hop at position 2.
        let hops = r#"
            {"addr":"10.1.0.1","probe_ttl":1,"probe_id":1,"rtt":0.5,"icmp_type":11},
            {"addr":"192.0.2.1","probe_ttl":3,"probe_id":1,"rtt":5.0,"icmp_type":0}
        "#;
        let route = parse_trace(&sample_json(hops, "COMPLETED")).unwrap();
        assert_eq!(route.hops.len(), 3);
        assert_eq!(route.hops[1].hop, 2);
        assert!(route.hops[1].ip.is_none());
        assert!(route.hops[1].rtt_avg.is_none());
    }

    #[test]
    fn parse_trace_empty_hops_gaplimit() {
        let route = parse_trace(&sample_json("", "GAPLIMIT")).unwrap();
        assert!(route.hops.is_empty());
        assert_eq!(route.stop_reason, "GAPLIMIT");
    }

    #[test]
    fn parse_trace_rtt_statistics() {
        let hops = r#"
            {"addr":"10.0.0.1","probe_ttl":1,"probe_id":1,"rtt":1.0,"icmp_type":11},
            {"addr":"10.0.0.1","probe_ttl":1,"probe_id":2,"rtt":3.0,"icmp_type":11},
            {"addr":"10.0.0.1","probe_ttl":1,"probe_id":3,"rtt":2.0,"icmp_type":11}
        "#;
        let route = parse_trace(&sample_json(hops, "COMPLETED")).unwrap();
        let hop = &route.hops[0];
        assert!((hop.rtt_avg.unwrap() - 2.0).abs() < 1e-9);
        assert!((hop.rtt_best.unwrap() - 1.0).abs() < 1e-9);
        assert!((hop.rtt_worst.unwrap() - 3.0).abs() < 1e-9);
    }

    #[test]
    fn parse_trace_source_and_destination() {
        let route = parse_trace(&sample_json("", "GAPLIMIT")).unwrap();
        assert_eq!(route.source, "10.0.0.1");
        assert_eq!(route.destination, "192.0.2.1");
    }
}
