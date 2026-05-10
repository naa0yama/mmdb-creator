//! High-level whois import API.
//!
//! Orchestrates RIPE Stat lookups and TCP 43 whois queries, then writes the
//! collected [`WhoisRecord`] list to a JSONL file.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{
    config::WhoisConfig,
    types::{WhoisData, WhoisRecord},
};

use crate::{PrefixClient, clients_from_config, parse_asns, parse_prefixes, query_asn};

/// Options for the [`import`] function.
#[derive(Debug)]
pub struct WhoisImportOptions {
    /// Destination path for the JSONL output (e.g. `"data/whois-cidr.jsonl"`).
    pub output_path: PathBuf,
}

/// Import whois data and write to JSONL.
///
/// # Behaviour
///
/// - When `ip_args` is provided, each CIDR is resolved via RIPE Stat (no ASN loop).
/// - When `ip_args` is `None`, iterates over ASNs from `asn_args` or `config.asn`.
/// - Writes the collected records atomically to [`WhoisImportOptions::output_path`]
///   using a `.tmp` → rename strategy.  The caller is responsible for any backup
///   rotation before invoking this function.
/// - Returns early without writing when no records are collected.
///
/// # Errors
///
/// Returns an error if client construction, RIPE Stat queries, serialisation,
/// or I/O operations fail.
// NOTEST(io): orchestrates RIPE Stat HTTP + TCP 43 whois — depends on live network
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn import(
    config: &WhoisConfig,
    asn_args: Option<Vec<String>>,
    ip_args: Option<Vec<String>>,
    options: WhoisImportOptions,
) -> Result<Vec<WhoisRecord>> {
    let (whois_client, prefix_client) = clients_from_config(config)?;
    let mut whois_records: Vec<WhoisRecord> = Vec::new();

    // Collect prefixes from --ip args (all via RIPE Stat — no TCP 43).
    if let Some(ref raw_ips) = ip_args {
        let prefixes = parse_prefixes(raw_ips).with_context(|| "failed to parse --ip arguments")?;
        for prefix in &prefixes {
            collect_ip_records(&prefix_client, *prefix, &mut whois_records).await;
        }
    }

    // ASN loop only runs when --ip is not given.
    if ip_args.is_none() {
        let asns = match asn_args {
            Some(raw) => parse_asns(&raw).with_context(|| "failed to parse --asn arguments")?,
            None => config.asn.clone(),
        };

        if asns.is_empty() {
            tracing::warn!("whois: no --asn or --ip provided and config.whois.asn is empty");
        }

        for asn in asns {
            // query_asn internally: announced-prefixes → query_autnum → TCP 43 per CIDR.
            let results = query_asn(&whois_client, &prefix_client, asn).await?;
            log_results(&results);
            collect_records(&results, &mut whois_records);
        }
    }

    if !whois_records.is_empty() {
        write_whois_jsonl(&whois_records, &options.output_path).await?;
        tracing::info!(
            records = whois_records.len(),
            path = %options.output_path.display(),
            "whois: saved"
        );
    }

    Ok(whois_records)
}

/// Query a single CIDR via RIPE Stat (reverse-lookup ASN → aut-num → cidr whois).
// NOTEST(io): HTTP requests to RIPE Stat — depends on live network
#[cfg_attr(coverage_nightly, coverage(off))]
async fn collect_ip_records(
    prefix_client: &PrefixClient,
    prefix: IpNet,
    out: &mut Vec<WhoisRecord>,
) {
    // Step 1: reverse-lookup the ASN.
    let asn = prefix_client
        .reverse_lookup_asn(&prefix)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(cidr = %prefix, error = %e, "whois: ASN reverse lookup failed");
            None
        });

    // Step 3: fetch aut-num if ASN is known (cached per ASN).
    let autnum = if let Some(a) = asn {
        match prefix_client.query_autnum(a).await {
            Ok(an) => Some(an),
            Err(e) => {
                tracing::warn!(asn = a, error = %e, "whois: autnum lookup failed");
                None
            }
        }
    } else {
        None
    };

    // Step 2: RIPE Stat whois for the CIDR (with AS fields embedded).
    match prefix_client
        .query_cidr_whois(&prefix, autnum.as_ref())
        .await
    {
        Ok(entries) => {
            tracing::info!(
                cidr = %prefix,
                records = entries.len(),
                "whois: ripestat cidr complete"
            );
            for data in entries {
                let net = crate::rpsl::inetnum_to_net(&data.inetnum).unwrap_or(prefix);
                out.push(WhoisRecord {
                    network: net.to_string(),
                    whois: data,
                });
            }
        }
        Err(e) => {
            tracing::error!(cidr = %prefix, error = %e, "whois: ripestat cidr failed");
        }
    }
}

/// Append successful whois results to `out`, logging errors.
fn collect_records(results: &[(IpNet, Result<WhoisData>)], out: &mut Vec<WhoisRecord>) {
    for (net, result) in results {
        match result {
            Ok(data) => out.push(WhoisRecord {
                network: net.to_string(),
                whois: data.clone(),
            }),
            Err(e) => {
                tracing::error!(cidr = %net, error = %e, "whois: skipping failed record");
            }
        }
    }
}

fn log_results<T>(results: &[(IpNet, Result<T>)]) {
    let (ok, failed): (Vec<_>, Vec<_>) = results.iter().partition(|(_, r)| r.is_ok());
    tracing::info!(
        ok = ok.len(),
        failed = failed.len(),
        "whois: batch complete"
    );
    for (cidr, result) in failed {
        if let Err(e) = result {
            tracing::error!(cidr = %cidr, error = %e, "whois: query failed");
        }
    }
}

/// Write whois records to `path` atomically (write to `{path}.tmp` then rename).
// NOTEST(io): writes JSONL file to filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
async fn write_whois_jsonl(records: &[WhoisRecord], path: &std::path::Path) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let tmp_path = path.with_extension("jsonl.tmp");

    let mut file = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("failed to create {}", tmp_path.display()))?;

    for record in records {
        let line = serde_json::to_string(record)
            .with_context(|| format!("failed to serialize record for {}", record.network))?;
        file.write_all(line.as_bytes())
            .await
            .context("failed to write whois JSONL line")?;
        file.write_all(b"\n")
            .await
            .context("failed to write newline")?;
    }

    file.flush().await.context("failed to flush whois JSONL")?;
    drop(file);

    tokio::fs::rename(&tmp_path, path).await.with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}
