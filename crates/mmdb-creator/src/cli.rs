//! CLI argument definitions for mmdb-creator.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(about, version = super::APP_VERSION)]
pub struct Args {
    /// Path to the configuration file
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Collect data from whois and/or Excel files
    Import {
        /// Clear the import cache before running (forces a full re-fetch from RIPE Stat and whois)
        #[arg(long)]
        force: bool,
        /// Import whois data only
        #[arg(long)]
        whois: bool,
        /// Import xlsx data only
        #[arg(long)]
        xlsx: bool,
        /// ASN numbers to query (comma-separated; "AS" prefix is optional, e.g. 64496,AS64497)
        #[arg(long, value_delimiter = ',')]
        asn: Option<Vec<String>>,
        /// IP addresses or CIDR prefixes to query directly (comma-separated, e.g. 192.0.2.1,192.0.2.0/24)
        #[arg(long, value_delimiter = ',')]
        ip: Option<Vec<String>>,
    },
    /// Merge collected data and generate `MMDB` via mmdbctl
    Export {
        /// Output MMDB file path
        #[arg(short, long, default_value = "output.mmdb")]
        out: PathBuf,
    },
    /// Probe CIDRs with scamper icmp-paris for demarc discovery
    Scan {
        /// Clear the scan cache before running (discards resume state and restarts from the beginning)
        #[arg(long)]
        force: bool,
        /// Skip scanning and run only the post-scan enrichment phase (ASN filter + PTR)
        #[arg(long)]
        enrich_only: bool,
        /// Scan a single CIDR prefix instead of reading from data/whois-cidr.jsonl (e.g. 192.0.2.0/24)
        #[arg(long)]
        ip: Option<String>,
    },
    /// Validate configuration and optionally scaffold sheet column mappings
    Validate {
        /// Read xlsx files listed in config and print [[sheets.columns]] TOML to stdout
        #[arg(long)]
        init_sheets: bool,
    },
}
