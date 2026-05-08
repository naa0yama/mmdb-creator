//! Core data types for mmdb-creator `NDJSON` records.

use serde::{Deserialize, Serialize};

/// The merged `MMDB` record written to `NDJSON` and imported by mmdbctl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdbRecord {
    /// CIDR range or single address (/32, /128) — key for the `MMDB` tree.
    pub range: String,
    /// Record creation timestamp (ISO 8601 UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Record last-update timestamp (ISO 8601 UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// GeoLite2-compatible continent code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<Continent>,
    /// GeoLite2-compatible country ISO code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<Country>,
    /// ASN that announces this prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_number: Option<u32>,
    /// Organisation name for the announcing ASN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_organization: Option<String>,
    /// Data sourced from whois (TCP 43).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois: Option<WhoisData>,
    /// Data sourced from Excel (.xlsx) files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operational: Option<OperationalData>,
    /// Route data collected by the scan subcommand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routes: Option<RouteData>,
}

/// GeoLite2-compatible continent field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Continent {
    /// Two-letter continent code (e.g. "AS", "EU").
    pub code: String,
}

/// GeoLite2-compatible country field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Country {
    /// ISO 3166-1 alpha-2 country code (e.g. "JP").
    pub iso_code: String,
}

/// Data sourced from whois (TCP 43) queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisData {
    /// IP range string from inetnum field (e.g. "192.0.2.0 - 192.0.2.255")
    pub inetnum: String,
    /// Network name from the whois `netname` field.
    pub netname: String,
    /// Description from the whois `descr` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descr: Option<String>,
    /// ISO 3166-1 alpha-2 country code from the whois `country` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Data source RIR from the whois `source` field (e.g. "APNIC").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Last-modified timestamp from the whois `last-modified` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// AS number string from the aut-num whois object (e.g. "AS64496").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_num: Option<String>,
    /// AS name from the aut-num whois object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    /// AS description from the aut-num whois object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_descr: Option<String>,
}

/// Data from an aut-num whois object (ASN registry entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutNumData {
    /// The AS number string (e.g. "AS64496").
    pub aut_num: String,
    /// The `as-name` field from the aut-num object.
    pub as_name: String,
    /// The `descr` field from the aut-num object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descr: Option<String>,
}

/// Data sourced from Excel (.xlsx) files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalData {
    /// Source Excel filename.
    pub filename: String,
    /// Source sheet name within the Excel file.
    pub sheetname: String,
    /// Last-modified timestamp of the Excel file (ISO 8601 UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// Additional fields defined in the sheet column mapping.
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

/// Route data collected by the scan subcommand (scamper icmp-paris output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteData {
    /// scamper version string (from top-level `version` field).
    pub version: String,
    /// Timestamp when the trace measurement started (ISO 8601 UTC).
    pub measured_at: String,
    /// Source IP address of the scamper probe.
    pub source: String,
    /// Destination IP address probed.
    pub destination: String,
    /// Reason the trace stopped: COMPLETED, GAPLIMIT, or UNREACH.
    pub stop_reason: String,
    /// Ordered list of hops in the trace.
    pub hops: Vec<Hop>,
}

/// A single record written to `data/whois-cidr.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisRecord {
    /// Network prefix in CIDR notation (e.g. `"203.0.113.0/25"`).
    pub network: String,
    /// Whois data for this network.
    pub whois: WhoisData,
}

/// A single record written to `data/scan.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    /// Network prefix in CIDR notation — parent range from which the target IP was selected.
    pub range: String,
    /// Route data collected by scamper icmp-paris for this target.
    pub routes: RouteData,
}

/// A single hop in a scamper icmp-paris trace.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    /// 1-indexed hop number (derived from `probe_ttl`).
    pub hop: u32,
    /// IP address of the responding router; null for non-responding hops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Average RTT across probes for this hop in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_avg: Option<f64>,
    /// Best (minimum) RTT across probes for this hop in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_best: Option<f64>,
    /// Worst (maximum) RTT across probes for this hop in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_worst: Option<f64>,
    /// ICMP type of the reply (11=TTL exceeded, 0=echo reply); null for non-responding hops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    /// Autonomous system number; populated during post-scan enrichment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// Reverse DNS PTR record; populated during post-scan enrichment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
}
