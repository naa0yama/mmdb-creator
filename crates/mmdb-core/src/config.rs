//! Configuration file schema for mmdb-creator.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Deserialize;

/// Top-level configuration loaded from `config.toml`.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Whois collection configuration.
    pub whois: Option<WhoisConfig>,
    /// Excel sheet import configurations.
    pub sheets: Option<Vec<SheetConfig>>,
    /// Scan subcommand configuration.
    pub scan: Option<ScanConfig>,
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not valid TOML.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("failed to parse config {}", path.display()))
    }

    /// Return a minimal starter `config.toml` template as a string.
    #[must_use]
    pub const fn template() -> &'static str {
        include_str!("config_template.toml")
    }
}

/// Configuration for whois data collection.
#[allow(dead_code, clippy::module_name_repetitions)]
#[derive(Debug, Deserialize)]
pub struct WhoisConfig {
    /// Whois server hostname (TCP port 43)
    pub server: String,
    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_sec: u64,
    /// ASN numbers to query (used when --asn is not passed on CLI)
    #[serde(default)]
    pub asn: Vec<u32>,
    /// Delay in milliseconds between consecutive TCP 43 whois queries (default: 2000)
    #[serde(default = "default_rate_limit_ms")]
    pub rate_limit_ms: u64,
    /// Maximum retry attempts per query on transient failure (default: 3)
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Initial backoff in milliseconds before first retry (default: 1000)
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// Delay in milliseconds between consecutive RIPE Stat REST API requests (default: 1000)
    #[serde(default = "default_ripe_stat_rate_limit_ms")]
    pub ripe_stat_rate_limit_ms: u64,
    /// Delay in milliseconds between consecutive bgp.tools REST API requests (default: 1000)
    #[serde(default = "default_bgptool_rate_limit_ms")]
    pub bgptool_rate_limit_ms: u64,
    /// Directory to store REST API response caches (RIPE Stat + bgp.tools). Default: "data/cache"
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    /// Cache TTL in seconds for REST API responses (default: 7200 = 2 hours)
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Maximum HTTP retry attempts for REST API calls (default: 3)
    #[serde(default = "default_http_max_retries")]
    pub http_max_retries: u32,
    /// Delay in seconds between HTTP retry attempts (default: 2)
    #[serde(default = "default_http_retry_delay_secs")]
    pub http_retry_delay_secs: u64,
}

const fn default_timeout() -> u64 {
    10
}

const fn default_rate_limit_ms() -> u64 {
    2000
}

const fn default_max_retries() -> u32 {
    3
}

const fn default_initial_backoff_ms() -> u64 {
    1000
}

const fn default_ripe_stat_rate_limit_ms() -> u64 {
    1000
}

const fn default_bgptool_rate_limit_ms() -> u64 {
    1000
}

fn default_cache_dir() -> String {
    String::from("data/cache/import")
}

const fn default_cache_ttl_secs() -> u64 {
    7200
}

const fn default_http_max_retries() -> u32 {
    3
}

const fn default_http_retry_delay_secs() -> u64 {
    2
}

/// Configuration for the scan subcommand.
#[allow(dead_code, clippy::module_name_repetitions)]
#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    /// scamper global packets-per-second limit (default: 50).
    #[serde(default = "default_scan_pps")]
    pub pps: u32,
    /// Probes per hop (`-q` flag passed to scamper, default: 3).
    #[serde(default = "default_scan_probes")]
    pub probes: u32,
    /// Maximum number of targets submitted to scamper concurrently (default: 200).
    #[serde(default = "default_scan_window")]
    pub window: usize,
    /// Flush the JSONL writer buffer when it reaches this many records (default: 100).
    #[serde(default = "default_scan_flush_count")]
    pub flush_count: usize,
    /// Flush the JSONL writer buffer after this many seconds since the last flush (default: 5).
    #[serde(default = "default_scan_flush_interval_sec")]
    pub flush_interval_sec: u64,
    /// Maximum concurrent DNS lookups for Cymru ASN and PTR enrichment (default: 10).
    #[serde(default = "default_dns_concurrency")]
    pub dns_concurrency: usize,
    /// DNS-over-HTTPS server for enrichment: `"cloudflare"` (default), `"google"`, or `"quad9"`.
    #[serde(default = "default_doh_server")]
    pub doh_server: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            pps: default_scan_pps(),
            probes: default_scan_probes(),
            window: default_scan_window(),
            flush_count: default_scan_flush_count(),
            flush_interval_sec: default_scan_flush_interval_sec(),
            dns_concurrency: default_dns_concurrency(),
            doh_server: default_doh_server(),
        }
    }
}

const fn default_scan_pps() -> u32 {
    50
}

const fn default_scan_probes() -> u32 {
    3
}

const fn default_scan_window() -> usize {
    200
}

const fn default_scan_flush_count() -> usize {
    100
}

const fn default_scan_flush_interval_sec() -> u64 {
    5
}

const fn default_dns_concurrency() -> usize {
    10
}

fn default_doh_server() -> String {
    String::from("cloudflare")
}

/// Configuration for a single Excel file import.
#[allow(dead_code, clippy::module_name_repetitions)]
#[derive(Debug, Deserialize)]
pub struct SheetConfig {
    /// Path to the Excel file
    pub filename: PathBuf,
    /// Sheet names to skip
    #[serde(default)]
    pub excludes_sheets: Vec<String>,
    /// 1-indexed header row number
    #[serde(default = "default_header_row")]
    pub header_row: u32,
    /// Column mapping definitions
    #[serde(default)]
    pub columns: Vec<ColumnMapping>,
}

const fn default_header_row() -> u32 {
    1
}

/// Mapping from an Excel column header to an output field.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ColumnMapping {
    /// Output field name
    pub name: String,
    /// Column header in the Excel sheet
    pub sheet_name: String,
    /// Data type for parsing
    #[serde(rename = "type")]
    pub col_type: ColumnType,
}

/// Supported column data types.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColumnType {
    /// UTF-8 string value.
    String,
    /// Integer value.
    Integer,
    /// IPv4 or IPv6 address.
    Addresses,
    /// Boolean true/false value.
    Bool,
}
