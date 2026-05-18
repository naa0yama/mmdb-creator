//! Configuration file schema for mmdb-creator.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

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
    /// MMDB file path shared by build, query, and enrich subcommands.
    #[serde(default)]
    pub mmdb: MmdbConfig,
    /// Named normalisation rule sets (`[normalize.<name>]`).
    #[serde(default)]
    pub normalize: HashMap<String, NormalizeConfig>,
    /// Field projection configuration for the enrich subcommand.
    pub enrich: Option<EnrichConfig>,
}

/// Configuration for the enrich subcommand field projection.
#[allow(dead_code, clippy::module_name_repetitions)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrichConfig {
    /// Separator used when joining list fields of type `array_join`.
    #[serde(default = "default_array_join_sep")]
    pub array_join_sep: String,
    /// Ordered list of output fields.
    #[serde(default)]
    pub fields: Vec<EnrichField>,
}

/// A single field entry in the `[[enrich.fields]]` table array.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrichField {
    /// Dot-notation source path in the enriched record (e.g. `"mmdb.asn"`).
    pub field: String,
    /// Column name in the processed output.  Falls back to `field` when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_name: Option<String>,
    /// How to coerce the value in the processed output.
    #[serde(rename = "type", default)]
    pub field_type: EnrichFieldType,
}

/// Type coercion applied to a field in the processed output.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnrichFieldType {
    /// Pass the value through unchanged, preserving its original JSON type.
    #[default]
    Auto,
    /// Coerce value to string using its display representation.
    String,
    /// Parse value as a 64-bit integer; keeps raw value on failure.
    Integer,
    /// Parse value as a boolean; keeps raw value on failure.
    Bool,
    /// Join scalar array elements with the global `array_join_sep`; keeps raw if object array.
    ArrayJoin,
}

impl EnrichFieldType {
    /// Return the canonical TOML string representation of this type tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::String => "string",
            Self::Integer => "integer",
            Self::Bool => "bool",
            Self::ArrayJoin => "array_join",
        }
    }
}

// NOTEST(cfg): serde default callback — returns constant string
#[cfg_attr(coverage_nightly, coverage(off))]
fn default_array_join_sep() -> String {
    String::from(",")
}

/// MMDB path configuration shared by `mmdb build`, `mmdb query`, and `enrich`.
#[allow(dead_code, clippy::module_name_repetitions)]
#[derive(Debug, Deserialize)]
pub struct MmdbConfig {
    /// Path where `mmdb build` writes and `mmdb query`/`enrich` reads.
    #[serde(default = "default_mmdb_path")]
    pub path: PathBuf,
}

impl Default for MmdbConfig {
    fn default() -> Self {
        Self {
            path: default_mmdb_path(),
        }
    }
}

/// A single regex substitution rule within a normalisation pipeline.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct NormalizeRule {
    /// Regex pattern to match (compiled once at startup).
    pub pattern: String,
    /// Replacement string; supports `$1`, `$name` back-references.
    pub replacement: String,
}

/// Case transformation applied after all substitution rules.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NormalizeCase {
    /// Convert to lowercase (default).
    #[default]
    Lower,
    /// Convert to uppercase.
    Upper,
    /// Leave case unchanged.
    None,
}

/// Normalisation pipeline for a named field (e.g. `[normalize.interface]`).
#[allow(dead_code, clippy::module_name_repetitions)]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NormalizeConfig {
    /// Sequential substitution rules applied in order.
    #[serde(default)]
    pub rules: Vec<NormalizeRule>,
    /// Case transformation applied after all substitution rules.
    #[serde(default)]
    pub case: NormalizeCase,
    /// Regex patterns matched against the normalised field value after capture.
    /// Records whose captured value matches any entry are suppressed in
    /// `validate --ptr` output (e.g. loopback or management interfaces).
    #[serde(default)]
    pub excludes: Vec<String>,
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not valid TOML.
    // NOTEST(io): reads TOML file from filesystem
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("failed to parse config {}", path.display()))
    }

    /// Write or replace the `[enrich]` section in the config file at `path`.
    ///
    /// Preserves existing comments and formatting for all other sections.
    /// If `[enrich]` already exists it is replaced; otherwise appended.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, parsed as TOML, or written.
    // NOTEST(io): reads and writes TOML file from filesystem
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn write_enrich_section(path: &Path, enrich: &EnrichConfig) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .with_context(|| format!("failed to parse config {}", path.display()))?;

        // Remove old [enrich] / [[enrich.fields]] entirely, then rebuild.
        doc.remove("enrich");

        let mut enrich_table = toml_edit::Table::new();
        if enrich.array_join_sep != "," {
            enrich_table.insert(
                "array_join_sep",
                toml_edit::value(enrich.array_join_sep.as_str()),
            );
        }

        let mut fields_arr = toml_edit::ArrayOfTables::new();
        for field in &enrich.fields {
            let mut t = toml_edit::Table::new();
            t.insert("field", toml_edit::value(field.field.as_str()));
            if let Some(ref name) = field.output_name {
                t.insert("output_name", toml_edit::value(name.as_str()));
            }
            if field.field_type != EnrichFieldType::Auto {
                t.insert("type", toml_edit::value(field.field_type.as_str()));
            }
            fields_arr.push(t);
        }
        enrich_table.insert("fields", toml_edit::Item::ArrayOfTables(fields_arr));

        doc.insert("enrich", toml_edit::Item::Table(enrich_table));

        std::fs::write(path, doc.to_string())
            .with_context(|| format!("failed to write config {}", path.display()))?;
        Ok(())
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
    /// Whois server hostname (TCP port 43). Used as fallback when `auto_rir` fails.
    #[serde(default = "default_whois_server")]
    pub server: String,
    /// Automatically select the authoritative RIR WHOIS server via whois.iana.org.
    /// When true (default), the configured server is only used as a fallback.
    #[serde(default = "default_auto_rir")]
    pub auto_rir: bool,
    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_sec: u64,
    /// ASN numbers to query (used when --asn is not passed on CLI)
    #[serde(default)]
    pub asn: Vec<u32>,
    /// IP/CIDR prefixes to query directly (used when --ip is not passed on CLI)
    #[serde(default)]
    pub ip: Vec<String>,
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
    /// Directory to store REST API response caches (RIPE Stat per-ASN). Default: "data/cache"
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

// NOTEST(cfg): serde default callback — returns constant string
#[cfg_attr(coverage_nightly, coverage(off))]
fn default_whois_server() -> String {
    String::from("whois.iana.org")
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_auto_rir() -> bool {
    true
}

// NOTEST(cfg): serde default callback — trivial constant, only invoked during deserialization
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_timeout() -> u64 {
    10
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_rate_limit_ms() -> u64 {
    2000
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_max_retries() -> u32 {
    3
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_initial_backoff_ms() -> u64 {
    1000
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_ripe_stat_rate_limit_ms() -> u64 {
    1000
}

// NOTEST(cfg): serde default callback — returns constant string
#[cfg_attr(coverage_nightly, coverage(off))]
fn default_cache_dir() -> String {
    String::from("data/cache/import")
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_cache_ttl_secs() -> u64 {
    604_800 // 7 days
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_http_max_retries() -> u32 {
    3
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_http_retry_delay_secs() -> u64 {
    2
}

/// A single PTR hostname pattern used to identify backbone devices.
///
/// Entries are evaluated in definition order; the first match wins.
#[derive(Debug, Clone, Deserialize)]
pub struct PtrPattern {
    /// PTR domain suffix filter (e.g. `"example.ad.jp"`).
    /// When absent, the pattern is tried for every PTR record.
    pub domain: Option<String>,
    /// Regex applied to the full PTR string when the domain filter passes.
    /// Recognised named capture groups: `interface`, `device`, `device_role`,
    /// `facility`, `facing`, `customer_asn`.
    pub regex: String,
    /// Regex patterns applied to the full PTR hostname before regex matching.
    /// PTRs that match any entry are silently suppressed (not reported by
    /// `validate --ptr` and not matched by this pattern).
    #[serde(default)]
    pub excludes: Vec<String>,
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
    /// PTR hostname patterns used to identify backbone devices.
    /// Evaluated in order; the first matching pattern wins.
    #[serde(default)]
    pub ptr_patterns: Vec<PtrPattern>,
}

impl Default for ScanConfig {
    // NOTEST(cfg): serde default constructor — only exercised via TOML deserialization
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default() -> Self {
        Self {
            pps: default_scan_pps(),
            probes: default_scan_probes(),
            window: default_scan_window(),
            flush_count: default_scan_flush_count(),
            flush_interval_sec: default_scan_flush_interval_sec(),
            dns_concurrency: default_dns_concurrency(),
            doh_server: default_doh_server(),
            ptr_patterns: Vec::new(),
        }
    }
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_scan_pps() -> u32 {
    50
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_scan_probes() -> u32 {
    3
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_scan_window() -> usize {
    200
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_scan_flush_count() -> usize {
    100
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_scan_flush_interval_sec() -> u64 {
    5
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_dns_concurrency() -> usize {
    10
}

// NOTEST(cfg): serde default callback — returns constant string
#[cfg_attr(coverage_nightly, coverage(off))]
fn default_doh_server() -> String {
    String::from("cloudflare")
}

// NOTEST(cfg): serde default callback — returns constant string
#[cfg_attr(coverage_nightly, coverage(off))]
fn default_mmdb_path() -> PathBuf {
    PathBuf::from("data/output.mmdb")
}

/// Excel sheet classification used to select the appropriate match algorithm.
///
/// - `backbone`: infra/physical info at coarse CIDR granularity (/21–/24).
///   Matched via PTR capture groups or bidirectional CIDR containment.
/// - `hosting`: customer IP registration at /32 granularity.
///   Matched via exact CIDR equality only; `ptr_field` is not supported.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum SheetType {
    /// Infrastructure / backbone sheets (default).
    #[default]
    Backbone,
    /// Customer IP / hosting sheets.
    Hosting,
}

/// Configuration for a single Excel file import.
#[allow(dead_code, clippy::module_name_repetitions)]
#[derive(Debug, Clone, Deserialize)]
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
    /// Sheet classification: backbone (default) or hosting.
    #[serde(default)]
    pub sheettype: SheetType,
    /// Redundancy groups: each inner Vec is a set of sheet tab names whose
    /// duplicate CIDRs are permitted with each other.
    #[serde(default)]
    pub groups: Vec<Vec<String>>,
}

// NOTEST(cfg): serde default callback — trivial constant
#[cfg_attr(coverage_nightly, coverage(off))]
const fn default_header_row() -> u32 {
    1
}

/// Mapping from an Excel column header (or multiple headers) to an output field.
///
/// Exactly one of `sheet_name` and `sheet_names` must be set:
/// - `sheet_name`: maps a single Excel column header to `name`.
/// - `sheet_names`: merges multiple `Addresses`-type columns into one field
///   with CIDR-level deduplication (only valid for `type = "addresses"`).
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct ColumnMapping {
    /// Output field name.
    pub name: String,
    /// Single Excel column header. Mutually exclusive with `sheet_names`.
    #[serde(default)]
    pub sheet_name: Option<String>,
    /// Multiple Excel column headers to aggregate. Only valid with
    /// `type = "addresses"`. Mutually exclusive with `sheet_name`.
    #[serde(default)]
    pub sheet_names: Option<Vec<String>>,
    /// Data type for parsing.
    #[serde(rename = "type")]
    pub col_type: ColumnType,
    /// PTR capture group name used as a join key for PTR-to-xlsx matching.
    /// When set, `Config.normalize[ptr_field]` rules are applied to both
    /// the PTR-captured value and this column's value before comparison.
    /// Cannot be combined with `sheet_names`.
    #[serde(default)]
    pub ptr_field: Option<String>,
}

/// Supported column data types.
#[derive(Debug, Clone, Deserialize)]
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

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn enrich_config_defaults() {
        let cfg: EnrichConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.array_join_sep, ",");
        assert!(cfg.fields.is_empty());
    }

    #[test]
    fn enrich_field_type_default_is_auto() {
        let field: EnrichField = toml::from_str(r#"field = "ip_address""#).unwrap();
        assert_eq!(field.field_type, EnrichFieldType::Auto);
        assert!(field.output_name.is_none());
    }

    #[test]
    fn enrich_field_round_trip() {
        let toml_str = r#"
[[enrich.fields]]
field = "ip_address"
output_name = "IPAddr"

[[enrich.fields]]
field = "mmdb.asn"
output_name = "ASN"
type = "integer"

[[enrich.fields]]
field = "mmdb.tags"
type = "array_join"

[[enrich.fields]]
field = "mmdb.network"
type = "string"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let enrich = cfg.enrich.unwrap();
        assert_eq!(enrich.fields.len(), 4);
        assert_eq!(enrich.fields[0].field, "ip_address");
        assert_eq!(enrich.fields[0].output_name.as_deref(), Some("IPAddr"));
        assert_eq!(enrich.fields[0].field_type, EnrichFieldType::Auto);
        assert_eq!(enrich.fields[1].field_type, EnrichFieldType::Integer);
        assert_eq!(enrich.fields[2].field_type, EnrichFieldType::ArrayJoin);
        assert_eq!(enrich.fields[3].field_type, EnrichFieldType::String);
        assert!(enrich.fields[2].output_name.is_none());
    }

    #[test]
    fn enrich_absent_is_none() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.enrich.is_none());
    }
}
