//! Import subcommand: collect data from whois and Excel sources.

use std::path::Path;

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{
    config::Config,
    types::{WhoisData, WhoisRecord},
};
use mmdb_whois::{PrefixClient, clients_from_config, parse_asns, parse_prefixes, query_asn};

use crate::cache;

/// Run the import subcommand.
pub async fn run(
    config: &Config,
    force: bool,
    whois_only: bool,
    xlsx_only: bool,
    asn_args: Option<Vec<String>>,
    ip_args: Option<Vec<String>>,
) -> Result<()> {
    if force {
        cache::clear_dir(Path::new("data/cache/import")).await?;
    }

    let run_whois = whois_only || !xlsx_only;
    let run_xlsx = xlsx_only || !whois_only;

    if run_whois {
        let whois_cfg = config
            .whois
            .as_ref()
            .context("whois config missing; add a [whois] section to config.toml")?;

        let (whois_client, prefix_client) = clients_from_config(whois_cfg)?;
        let mut whois_records: Vec<WhoisRecord> = Vec::new();

        // Collect prefixes from --ip args (all via RIPE Stat — no TCP 43).
        if let Some(ref raw_ips) = ip_args {
            let prefixes =
                parse_prefixes(raw_ips).with_context(|| "failed to parse --ip arguments")?;
            for prefix in &prefixes {
                collect_ip_records(&prefix_client, *prefix, &mut whois_records).await;
            }
        }

        // Collect prefixes from --asn args (RIPE Stat → TCP 43, AS fields embedded at query time).
        let asns = match asn_args {
            Some(raw) => parse_asns(&raw).with_context(|| "failed to parse --asn arguments")?,
            None => whois_cfg.asn.clone(),
        };

        if asns.is_empty() && ip_args.is_none() {
            tracing::warn!("whois: no --asn or --ip provided and config.whois.asn is empty");
        }

        for asn in asns {
            // query_asn internally: announced-prefixes → query_autnum → TCP 43 per CIDR.
            let results = query_asn(&whois_client, &prefix_client, asn).await?;
            log_results(&results);
            collect_records(&results, &mut whois_records);
        }

        if !whois_records.is_empty() {
            write_whois_jsonl(&whois_records).await?;
            tracing::info!(
                records = whois_records.len(),
                path = "data/whois-cidr.jsonl",
                "whois: saved"
            );
        }
    }

    if run_xlsx {
        if let Some(ref sheets) = config.sheets {
            for sheet_config in sheets {
                match mmdb_xlsx::read_xlsx(sheet_config) {
                    Ok(results) => {
                        for result in &results {
                            tracing::info!(
                                file = %sheet_config.filename.display(),
                                sheet = %result.sheetname,
                                rows = result.rows.len(),
                                skipped = result.skipped_count,
                                "xlsx import complete"
                            );
                        }
                        // TODO: write results to data/import.jsonl
                    }
                    Err(e) => {
                        tracing::error!(
                            file = %sheet_config.filename.display(),
                            error = %e,
                            "xlsx import failed"
                        );
                    }
                }
            }
        } else {
            tracing::warn!("xlsx import requested but no [[sheets]] configured in config.toml");
        }
    }

    Ok(())
}

/// Query a single CIDR via RIPE Stat (reverse-lookup ASN → aut-num → cidr whois).
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
                let net = mmdb_whois::rpsl::inetnum_to_net(&data.inetnum).unwrap_or(prefix);
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

fn log_results<T>(results: &[(ipnet::IpNet, Result<T>)]) {
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

/// Write whois records to `data/whois-cidr.jsonl`, overwriting any existing file.
async fn write_whois_jsonl(records: &[WhoisRecord]) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let path = std::path::Path::new("data/whois-cidr.jsonl");
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let mut file = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("failed to create {}", path.display()))?;

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
    Ok(())
}
