//! Core data types for mmdb-creator `NDJSON` records.

use serde::{Deserialize, Serialize};

/// The merged `MMDB` record written to `NDJSON` and imported by mmdbctl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdbRecord {
    /// CIDR range or single address (/32, /128) — key for the `MMDB` tree.
    pub range: String,
    /// GeoLite2-compatible continent code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<Continent>,
    /// GeoLite2-compatible country ISO code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<Country>,
    /// ASN that announces this prefix (GeoLite2-ASN compatible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_number: Option<u32>,
    /// Organisation name for the announcing ASN (GeoLite2-ASN compatible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system_organization: Option<String>,
    /// Whois-derived metadata for this prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois: Option<WhoisExport>,
    /// Gateway device that serves this prefix, identified via PTR patterns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayExport>,
    /// Data sourced from Excel (.xlsx) files, keyed by sheettype ("backbone"/"hosting").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xlsx: Option<std::collections::HashMap<String, OperationalData>>,
    /// True when this record matched an xlsx row.
    pub xlsx_matched: bool,
    /// True when a gateway was successfully resolved.
    pub gateway_found: bool,
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

/// Whois-derived metadata exported to the MMDB record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisExport {
    /// IP range string from inetnum field (e.g. "192.0.2.0 - 192.0.2.255").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inetnum: Option<String>,
    /// Network name from the whois `netname` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netname: Option<String>,
    /// Description from the whois `descr` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descr: Option<String>,
    /// Data source RIR from the whois `source` field (e.g. "APNIC").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Last-modified timestamp from the whois `last-modified` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// Gateway device info exported to the MMDB record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayExport {
    /// IP address of the gateway hop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// PTR record of the gateway IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    /// Full device identifier parsed from PTR (e.g. `"rtr0101"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Role portion of the device name (e.g. `"rtr"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_role: Option<String>,
    /// Site or facility name parsed from PTR (e.g. `"colo05"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facility: Option<String>,
    /// Interface name parsed from PTR (e.g. `"xe-0-0-1"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Normalised facing direction: `"network"` / `"user"` / `"virtual"` /
    /// `"user_virtual"` / `"bgp_peer"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facing: Option<String>,
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

/// Structured device fields parsed from a matching PTR record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayDevice {
    /// Interface name (e.g. `"xe-0-0-1"`).
    pub interface: Option<String>,
    /// Full device identifier (e.g. `"rtr0101"`).
    pub device: Option<String>,
    /// Role portion of the device name (e.g. `"rtr"`).
    pub device_role: Option<String>,
    /// Site or facility name (e.g. `"dc01"`).
    pub facility: Option<String>,
    /// Normalised facing direction: `"network"` / `"user"` / `"virtual"` /
    /// `"user_virtual"` / `"bgp_peer"`.
    pub facing: Option<String>,
    /// BGP ASN for peering interfaces; present when PTR has an `as<N>.` prefix.
    pub customer_asn: Option<u32>,
}

/// Gateway information for a scanned range, always present in [`ScanGwRecord`].
///
/// All fields are serialised unconditionally so downstream parsers can rely on
/// key presence even when values are `null`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayInfo {
    /// IP address of the winning gateway hop.
    pub ip: Option<String>,
    /// PTR record of the gateway IP.
    pub ptr: Option<String>,
    /// Number of traces that voted for this gateway IP.
    pub votes: usize,
    /// Total number of traces for this range.
    pub total: usize,
    /// Resolution status: `"inservice"` / `"no_hops"` / `"no_ptr_match"`.
    pub status: String,
    /// Structured device info parsed from the PTR; `null` when not matched.
    pub device: Option<GatewayDevice>,
}

/// A range-aggregated gateway record written to `data/scanned.jsonl`.
///
/// One record per unique CIDR, produced by the GW resolution phase that runs
/// after PTR enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanGwRecord {
    /// Network prefix in CIDR notation — the scanned range.
    pub range: String,
    /// Network name from the whois `netname` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netname: Option<String>,
    /// Description from the whois `descr` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descr: Option<String>,
    /// AS number string from the aut-num whois object (e.g. `"AS64496"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_num: Option<String>,
    /// AS name from the aut-num whois object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    /// AS description from the aut-num whois object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_descr: Option<String>,
    /// IP range string from the whois `inetnum` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inetnum: Option<String>,
    /// ISO 3166-1 alpha-2 country code from the whois `country` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Data source RIR from the whois `source` field (e.g. `"APNIC"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois_source: Option<String>,
    /// Last-modified timestamp from the whois `last-modified` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois_last_modified: Option<String>,
    /// Gateway information; always present.
    pub gateway: GatewayInfo,
    /// TTL-aggregated hops up to and including the gateway hop.
    /// Empty when `gateway.status` is `"no_hops"`.
    /// Contains all aggregated hops when `gateway.status` is `"no_ptr_match"`.
    pub routes: Vec<Hop>,
    /// Host IP for narrow prefixes — reserved for a future host-analysis phase.
    #[serde(skip)]
    pub host_ip: Option<String>,
    /// PTR record of the host IP — reserved for a future host-analysis phase.
    #[serde(skip)]
    pub host_ptr: Option<String>,
    /// Timestamp of the earliest trace in this range (ISO 8601 UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_at: Option<String>,
    /// xlsx rows matched per sheettype ("backbone"/"hosting"); absent when no match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xlsx: Option<std::collections::HashMap<String, serde_json::Value>>,
    /// True when this record matched an xlsx row.
    #[serde(default)]
    pub xlsx_matched: bool,
    /// True when a gateway was successfully resolved.
    #[serde(default)]
    pub gateway_found: bool,
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
