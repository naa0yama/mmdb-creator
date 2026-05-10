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
        #[arg(long, conflicts_with = "asn")]
        xlsx: bool,
        /// ASN numbers to query (comma-separated; "AS" prefix is optional, e.g. 64496,AS64497)
        #[arg(long, value_delimiter = ',', conflicts_with = "xlsx")]
        asn: Option<Vec<String>>,
        /// IP addresses or CIDR prefixes to query directly (comma-separated, e.g. 192.0.2.1,192.0.2.0/24)
        #[arg(long, value_delimiter = ',')]
        ip: Option<Vec<String>>,
    },
    /// Build and query MMDB files
    Mmdb {
        #[command(subcommand)]
        command: MmdbCommand,
    },
    /// Probe CIDRs with scamper icmp-paris for demarc discovery
    Scan {
        /// Clear the scan cache before running (discards resume state and restarts from the beginning)
        #[arg(long)]
        force: bool,
        /// Scan a single CIDR prefix instead of reading from data/whois-cidr.jsonl (e.g. 192.0.2.0/24)
        #[arg(long)]
        ip: Option<String>,
        /// Scan every host in each CIDR instead of the gateway-heuristic sample (first 3 + last 3)
        #[arg(long)]
        full: bool,
    },
    /// Validate configuration and optionally scaffold sheet column mappings
    Validate {
        /// Read xlsx files listed in config and print [[sheets.columns]] TOML to stdout
        #[arg(long)]
        init_sheets: bool,
        /// Re-apply current `ptr_patterns`/`normalize` config to `data/scanned.jsonl` and
        /// report unique domain-matching but unmatched PTR hostnames
        #[arg(long, conflicts_with = "init_sheets")]
        ptr: bool,
    },
    /// Enrich a JSON/JSONL log file with MMDB lookup results
    Enrich {
        /// Input JSON or JSONL log file to enrich
        #[arg(long)]
        input_enrich_file: PathBuf,
        /// Field name in each record that holds the IP address to look up
        #[arg(long)]
        input_enrich_ip: String,
        /// MMDB file to use for lookups (default: config.mmdb.path)
        #[arg(short = 'm', long)]
        mmdb: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum MmdbCommand {
    /// Build MMDB from scanned.jsonl via mmdbctl
    Build {
        /// Output MMDB file path (default: config.mmdb.path)
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Source JSONL file (scanned.jsonl)
        #[arg(short, long, default_value = "data/scanned.jsonl")]
        input: PathBuf,
    },
    /// Look up one or more IP addresses in an MMDB file
    #[command(alias = "q")]
    Query {
        /// MMDB file to query (default: config.mmdb.path)
        #[arg(short = 'm', long)]
        mmdb: Option<PathBuf>,
        /// IP addresses to look up
        ips: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::Args;

    fn try_parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(args)
    }

    // --- import conflicts ---

    #[test]
    fn import_asn_and_ip_together_is_valid() {
        assert!(
            try_parse(&[
                "prog",
                "import",
                "--asn",
                "64496",
                "--ip",
                "198.51.100.0/24"
            ])
            .is_ok()
        );
    }

    #[test]
    fn import_asn_conflicts_with_xlsx() {
        assert!(try_parse(&["prog", "import", "--asn", "64496", "--xlsx"]).is_err());
    }

    #[test]
    fn import_xlsx_ip_is_valid() {
        assert!(try_parse(&["prog", "import", "--xlsx", "--ip", "198.51.100.0/24"]).is_ok());
    }

    #[test]
    fn import_asn_alone_is_valid() {
        assert!(try_parse(&["prog", "import", "--asn", "64496"]).is_ok());
    }

    #[test]
    fn import_ip_alone_is_valid() {
        assert!(try_parse(&["prog", "import", "--ip", "198.51.100.0/24"]).is_ok());
    }

    // --- mmdb build ---

    #[test]
    fn mmdb_build_defaults() {
        let args = try_parse(&["prog", "mmdb", "build"]).unwrap();
        let super::Command::Mmdb { command } = args.command else {
            panic!("expected Mmdb");
        };
        let super::MmdbCommand::Build { out, input } = command else {
            panic!("expected Build");
        };
        assert_eq!(out, None);
        assert_eq!(input, std::path::PathBuf::from("data/scanned.jsonl"));
    }

    #[test]
    fn mmdb_build_custom_paths() {
        let args = try_parse(&[
            "prog",
            "mmdb",
            "build",
            "--out",
            "custom.mmdb",
            "--input",
            "custom.jsonl",
        ])
        .unwrap();
        let super::Command::Mmdb { command } = args.command else {
            panic!("expected Mmdb");
        };
        let super::MmdbCommand::Build { out, input } = command else {
            panic!("expected Build");
        };
        assert_eq!(out, Some(std::path::PathBuf::from("custom.mmdb")));
        assert_eq!(input, std::path::PathBuf::from("custom.jsonl"));
    }

    // --- mmdb query ---

    #[test]
    fn mmdb_query_single_ip() {
        let args = try_parse(&["prog", "mmdb", "query", "198.51.100.1"]).unwrap();
        let super::Command::Mmdb { command } = args.command else {
            panic!("expected Mmdb");
        };
        let super::MmdbCommand::Query { mmdb, ips } = command else {
            panic!("expected Query");
        };
        assert_eq!(mmdb, None);
        assert_eq!(ips, vec!["198.51.100.1"]);
    }

    #[test]
    fn mmdb_query_alias_q() {
        let args = try_parse(&["prog", "mmdb", "q", "198.51.100.1"]).unwrap();
        let super::Command::Mmdb { command } = args.command else {
            panic!("expected Mmdb");
        };
        assert!(matches!(command, super::MmdbCommand::Query { .. }));
    }

    #[test]
    fn mmdb_query_multiple_ips() {
        let args = try_parse(&["prog", "mmdb", "query", "198.51.100.1", "203.0.113.5"]).unwrap();
        let super::Command::Mmdb { command } = args.command else {
            panic!("expected Mmdb");
        };
        let super::MmdbCommand::Query { ips, .. } = command else {
            panic!("expected Query");
        };
        assert_eq!(ips, vec!["198.51.100.1", "203.0.113.5"]);
    }

    #[test]
    fn mmdb_query_custom_mmdb() {
        let args = try_parse(&[
            "prog",
            "mmdb",
            "query",
            "--mmdb",
            "other.mmdb",
            "198.51.100.1",
        ])
        .unwrap();
        let super::Command::Mmdb { command } = args.command else {
            panic!("expected Mmdb");
        };
        let super::MmdbCommand::Query { mmdb, .. } = command else {
            panic!("expected Query");
        };
        assert_eq!(mmdb, Some(std::path::PathBuf::from("other.mmdb")));
    }

    // --- scan flags ---

    #[test]
    fn scan_enrich_only_does_not_exist() {
        assert!(try_parse(&["prog", "scan", "--enrich-only"]).is_err());
    }

    #[test]
    fn scan_force_ip_is_valid() {
        assert!(try_parse(&["prog", "scan", "--force", "--ip", "198.51.100.0/24"]).is_ok());
    }

    #[test]
    fn scan_force_full_is_valid() {
        assert!(try_parse(&["prog", "scan", "--force", "--full"]).is_ok());
    }

    // --- validate conflicts ---

    #[test]
    fn validate_ptr_conflicts_with_init_sheets() {
        assert!(try_parse(&["prog", "validate", "--ptr", "--init-sheets"]).is_err());
    }

    #[test]
    fn validate_ptr_alone_is_valid() {
        assert!(try_parse(&["prog", "validate", "--ptr"]).is_ok());
    }

    #[test]
    fn validate_init_sheets_alone_is_valid() {
        assert!(try_parse(&["prog", "validate", "--init-sheets"]).is_ok());
    }

    // --- enrich required args ---

    #[test]
    fn enrich_both_required_args_is_valid() {
        assert!(
            try_parse(&[
                "prog",
                "enrich",
                "--input-enrich-file",
                "access.jsonl",
                "--input-enrich-ip",
                "ip_address",
            ])
            .is_ok()
        );
    }

    #[test]
    fn enrich_missing_ip_field_is_invalid() {
        assert!(try_parse(&["prog", "enrich", "--input-enrich-file", "access.jsonl"]).is_err());
    }

    #[test]
    fn enrich_missing_file_is_invalid() {
        assert!(try_parse(&["prog", "enrich", "--input-enrich-ip", "ip_address"]).is_err());
    }
}
