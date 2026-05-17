//! Configuration and result types for DNS enrichment.

/// `DoH` server selection.
#[derive(Debug, Clone, Default)]
pub enum DohServer {
    /// Cloudflare `DoH` (`cloudflare-dns.com`).
    #[default]
    Cloudflare,
    /// Google `DoH` (`dns.google`).
    Google,
    /// Quad9 `DoH` (`dns.quad9.net`).
    Quad9,
    /// Custom `DoH` server.
    Custom {
        /// Server IP address string.
        ip: String,
        /// TLS server name for SNI.
        server_name: String,
    },
}

/// Configuration for the DNS enrichment resolver.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Query timeout in seconds (default: 5).
    pub timeout_sec: u64,
    /// Maximum concurrent DNS lookups (default: 10).
    pub max_concurrency: usize,
    /// Whether to resolve AS names via `AS<N>.asn.cymru.com` (default: true).
    pub resolve_as_name: bool,
    /// `DoH` provider to use (default: Cloudflare).
    pub doh_server: DohServer,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            timeout_sec: 5,
            max_concurrency: 10,
            resolve_as_name: true,
            doh_server: DohServer::default(),
        }
    }
}

/// Enrichment result for a single IP address.
///
/// All fields are `None` if the lookup failed or returned no data.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsEnrichResult {
    /// Autonomous System Number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// BGP prefix the IP belongs to (e.g. `"198.51.100.0/24"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Two-letter country code from Cymru origin record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Registry name (e.g. `"apnic"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Allocation date from Cymru origin record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocated: Option<String>,
    /// AS organisation name (trailing `, XX` country code stripped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    /// PTR reverse DNS hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_config_defaults() {
        let cfg = DnsConfig::default();
        assert_eq!(cfg.timeout_sec, 5);
        assert_eq!(cfg.max_concurrency, 10);
        assert!(cfg.resolve_as_name);
        assert!(matches!(cfg.doh_server, DohServer::Cloudflare));
    }

    #[test]
    fn dns_enrich_result_serde_round_trip() {
        let result = DnsEnrichResult {
            asn: Some(13335),
            prefix: Some("1.1.1.0/24".to_owned()),
            country: Some("US".to_owned()),
            registry: Some("arin".to_owned()),
            allocated: Some("2010-07-14".to_owned()),
            as_name: Some("CLOUDFLARENET".to_owned()),
            ptr: Some("one.one.one.one".to_owned()),
        };

        let json = serde_json::to_string(&result).expect("serialize");
        let decoded: DnsEnrichResult = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.asn, result.asn);
        assert_eq!(decoded.prefix, result.prefix);
        assert_eq!(decoded.country, result.country);
        assert_eq!(decoded.registry, result.registry);
        assert_eq!(decoded.allocated, result.allocated);
        assert_eq!(decoded.as_name, result.as_name);
        assert_eq!(decoded.ptr, result.ptr);
    }

    #[test]
    fn dns_enrich_result_skip_none_fields() {
        let result = DnsEnrichResult::default();
        let json = serde_json::to_string(&result).expect("serialize");
        assert_eq!(json, "{}");
    }
}
