//! Import subcommand: collect data from whois and Excel sources.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use mmdb_core::config::Config;
use mmdb_whois::parse_prefixes;

use crate::cache;

/// Run the import subcommand.
// NOTEST(io): orchestrates whois + xlsx I/O — depends on live network and filesystem
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
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

    // When --ip is given, it determines the path exclusively:
    //   without --xlsx: whois-only for that CIDR (no xlsx, no ASN loop)
    //   with --xlsx:    xlsx-only filtered by that CIDR (no whois)
    let run_whois = if ip_args.is_some() {
        !xlsx_only
    } else {
        whois_only || !xlsx_only
    };
    let run_xlsx = if ip_args.is_some() {
        xlsx_only
    } else {
        xlsx_only || !whois_only
    };

    if run_whois {
        let whois_cfg = config
            .whois
            .as_ref()
            .context("whois config missing; add a [whois] section to config.toml")?;

        let whois_path = PathBuf::from("data/whois-cidr.jsonl");
        crate::backup::rotate_backup(&whois_path, 5)
            .await
            .with_context(|| format!("failed to rotate backup for {}", whois_path.display()))?;

        mmdb_whois::import::import(
            whois_cfg,
            asn_args,
            ip_args.clone(),
            mmdb_whois::import::WhoisImportOptions {
                output_path: whois_path,
            },
        )
        .await?;
    }

    if run_xlsx {
        let ip_filter = if let Some(ref raw_ips) = ip_args {
            let filters = parse_prefixes(raw_ips).context("failed to parse --ip arguments")?;
            Some(filters)
        } else {
            None
        };

        if let Some(ref sheets) = config.sheets {
            let xlsx_path = PathBuf::from("data/xlsx-rows.jsonl");
            crate::backup::rotate_backup(&xlsx_path, 5)
                .await
                .with_context(|| format!("failed to rotate backup for {}", xlsx_path.display()))?;
            mmdb_xlsx::import::import(
                sheets,
                mmdb_xlsx::import::XlsxImportOptions {
                    ip_filter,
                    output_path: xlsx_path,
                },
            )
            .await?;
        } else {
            tracing::warn!("xlsx import requested but no [[sheets]] configured in config.toml");
        }
    }

    Ok(())
}
