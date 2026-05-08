//! Team Cymru ASN `TXT` lookup with `CIDR`-keyed cache.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hickory_resolver::proto::rr::RData;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::sync::{RwLock, Semaphore};
use tracing::warn;

use crate::resolver::AsyncResolver;
use crate::types::DnsConfig;

/// Resolved Cymru data for a prefix (origin + asname combined).
#[derive(Debug, Clone)]
pub struct CymruData {
    /// Autonomous System Number.
    pub asn: u32,
    /// BGP prefix the IP belongs to (e.g. `"198.51.100.0/24"`).
    pub prefix: String,
    /// Two-letter country code.
    pub country: String,
    /// Registry name (e.g. `"apnic"`).
    pub registry: String,
    /// Allocation date.
    pub allocated: String,
    /// AS organisation name with trailing `, XX` country code stripped.
    pub as_name: Option<String>,
}

/// Shared CIDR-keyed cache of resolved Cymru data.
type CymruCache = Arc<RwLock<HashMap<IpNet, CymruData>>>;

/// Per-ASN memo cache for AS name lookups.
type AsnMemo = Arc<RwLock<HashMap<u32, String>>>;

/// Look up ASN data for a list of IPs via Team Cymru DNS TXT (`DoH`).
///
/// Returns a map of each IP to its resolved [`CymruData`]. Individual lookup
/// failures are logged as warnings and the IP is omitted from the result.
/// Never returns an error — the returned map may be empty on complete failure.
// NOTEST(io): DNS TXT queries via DoH resolver — requires live DNS
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn lookup(
    ips: &[IpAddr],
    resolver: &AsyncResolver,
    config: &DnsConfig,
) -> HashMap<IpAddr, CymruData> {
    let cache: CymruCache = Arc::new(RwLock::new(HashMap::new()));
    let asn_memo: AsnMemo = Arc::new(RwLock::new(HashMap::new()));
    let semaphore = Arc::new(Semaphore::new(config.max_concurrency));

    // Sort input IPs for deterministic bucket grouping.
    let mut sorted = ips.to_vec();
    sorted.sort_unstable();

    // Group IPs into /26 (IPv4) or /66 (IPv6) buckets.
    let buckets = group_into_buckets(&sorted);

    let mut handles = Vec::new();
    for (_bucket, bucket_ips) in buckets {
        let resolver = resolver.clone();
        let config = config.clone();
        let cache = Arc::clone(&cache);
        let asn_memo = Arc::clone(&asn_memo);
        let semaphore = Arc::clone(&semaphore);

        let handle: tokio::task::JoinHandle<Option<HashMap<IpAddr, CymruData>>> =
            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.ok()?;
                Some(process_bucket(bucket_ips, &resolver, &config, &cache, &asn_memo).await)
            });
        handles.push(handle);
    }

    let mut results = HashMap::new();
    for handle in handles {
        match handle.await {
            Ok(Some(partial)) => results.extend(partial),
            Ok(None) => {} // semaphore closed
            Err(err) => warn!(?err, "cymru bucket task panicked"),
        }
    }
    results
}

/// Process a single bucket of IPs serially and return a partial result map.
// NOTEST(io): DNS TXT queries via resolver — depends on live DoH
#[cfg_attr(coverage_nightly, coverage(off))]
async fn process_bucket(
    bucket_ips: Vec<IpAddr>,
    resolver: &AsyncResolver,
    config: &DnsConfig,
    cache: &CymruCache,
    asn_memo: &AsnMemo,
) -> HashMap<IpAddr, CymruData> {
    let mut results = HashMap::new();

    for ip in bucket_ips {
        let cached = {
            let read = cache.read().await;
            find_in_cache(ip, &read)
        };
        if let Some(data) = cached {
            results.insert(ip, data);
            continue;
        }

        let origin_name = cymru_origin_name(ip);
        let txt_response = match resolver.txt_lookup(origin_name.as_str()).await {
            Ok(r) => r,
            Err(err) => {
                warn!(%ip, %err, "cymru origin TXT lookup failed");
                continue;
            }
        };

        let Some(txt_string) = txt_response.answers().iter().find_map(|rec| {
            if let RData::TXT(txt) = &rec.data {
                Some(txt.to_string())
            } else {
                None
            }
        }) else {
            warn!(%ip, "cymru origin TXT returned no records");
            continue;
        };

        let Some((asn, prefix, country, registry, allocated)) = parse_origin_txt(&txt_string)
        else {
            warn!(%ip, txt = %txt_string, "cymru origin TXT parse failed");
            continue;
        };

        let as_name = if config.resolve_as_name {
            let memo_hit = { asn_memo.read().await.get(&asn).cloned() };
            if let Some(name) = memo_hit {
                Some(name)
            } else {
                let asname_name = cymru_asname_name(asn);
                let txt = resolver.txt_lookup(asname_name.as_str()).await;
                let name: Option<String> = txt.ok().and_then(|r| {
                    r.answers().iter().find_map(|rec| {
                        if let RData::TXT(t) = &rec.data {
                            parse_asname_txt(&t.to_string())
                        } else {
                            None
                        }
                    })
                });
                if let Some(ref n) = name {
                    let mut memo = asn_memo.write().await;
                    memo.entry(asn).or_insert_with(|| n.clone());
                }
                name
            }
        } else {
            None
        };

        let prefix_net: IpNet = prefix.parse().unwrap_or_else(|_| ip_to_host_net(ip));
        let data = CymruData {
            asn,
            prefix,
            country,
            registry,
            allocated,
            as_name,
        };
        {
            let mut write = cache.write().await;
            write.entry(prefix_net).or_insert_with(|| data.clone());
        }
        results.insert(ip, data);
    }

    results
}

/// Convert an IP address to a host /32 or /128 [`IpNet`].
fn ip_to_host_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(
            Ipv4Net::new(v4, 32)
                .unwrap_or_else(|_| Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap_or_default()),
        ),
        IpAddr::V6(v6) => IpNet::V6(
            Ipv6Net::new(v6, 128)
                .unwrap_or_else(|_| Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap_or_default()),
        ),
    }
}

/// Group a sorted slice of IPs into /26 (IPv4) or /66 (IPv6) buckets.
///
/// Returns a `Vec` of `(bucket_net, ips)` pairs.
fn group_into_buckets(sorted_ips: &[IpAddr]) -> Vec<(IpNet, Vec<IpAddr>)> {
    let mut map: HashMap<IpNet, Vec<IpAddr>> = HashMap::new();

    for &ip in sorted_ips {
        let bucket = ip_bucket(ip);
        map.entry(bucket).or_default().push(ip);
    }

    let mut result: Vec<(IpNet, Vec<IpAddr>)> = map.into_iter().collect();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Compute the /26 (IPv4) or /66 (IPv6) bucket network for an IP.
fn ip_bucket(ip: IpAddr) -> IpNet {
    // Prefix lengths 26 (IPv4) and 66 (IPv6) are compile-time constants that
    // are always valid (26 ≤ 32 and 66 ≤ 128), so new() never fails here.
    match ip {
        IpAddr::V4(v4) => {
            let net = Ipv4Net::new(v4, 26).unwrap_or_else(|_| Ipv4Net::default());
            IpNet::V4(Ipv4Net::new(net.network(), 26).unwrap_or_default())
        }
        IpAddr::V6(v6) => {
            let net = Ipv6Net::new(v6, 66).unwrap_or_else(|_| Ipv6Net::default());
            IpNet::V6(Ipv6Net::new(net.network(), 66).unwrap_or_default())
        }
    }
}

/// Build origin TXT query name for an IP.
///
/// - IPv4: `"d.c.b.a.origin.asn.cymru.com"`
/// - IPv6: `"<nibbles-reversed>.origin6.asn.cymru.com"`
pub fn cymru_origin_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com")
        }
        IpAddr::V6(v6) => {
            let segments = v6.octets();
            // Expand all 16 bytes into 32 nibbles, then reverse.
            let nibbles: String = segments
                .iter()
                .flat_map(|&b| [(b & 0x0F), (b >> 4)])
                .map(|n| char::from_digit(u32::from(n), 16).unwrap_or('0'))
                .collect();
            format!("{nibbles}.origin6.asn.cymru.com")
        }
    }
}

/// Build AS name TXT query name.
///
/// Returns `"as<N>.asn.cymru.com"` (lowercase `as` prefix), e.g. `"as64496.asn.cymru.com"`.
pub fn cymru_asname_name(asn: u32) -> String {
    format!("as{asn}.asn.cymru.com")
}

/// Parse origin TXT record.
///
/// Expected format: `"64496 | 198.51.100.0/24 | JP | apnic | 2001-01-01"`
///
/// Returns `Some((asn, prefix, country, registry, allocated))` or `None` on
/// parse failure.
pub fn parse_origin_txt(txt: &str) -> Option<(u32, String, String, String, String)> {
    let parts: Vec<&str> = txt.splitn(5, '|').collect();
    // Parse the ASN field; if absent or not a valid u32, return None.
    let asn_str = parts.first()?;
    let asn: Option<u32> = asn_str.trim().parse().ok();
    let asn = asn?;
    let prefix = parts.get(1)?.trim().to_owned();
    let country = parts.get(2)?.trim().to_owned();
    let registry = parts.get(3)?.trim().to_owned();
    let allocated = parts.get(4)?.trim().to_owned();
    Some((asn, prefix, country, registry, allocated))
}

/// Parse AS name TXT record and return the organisation name.
///
/// Expected format: `"64496 | JP | apnic | 2001-01-01 | EXAMPLE-NET Example Network, Inc., JP"`
///
/// Returns the last pipe-delimited field with trailing `, XX` country suffix
/// stripped, or `None` if the record cannot be parsed.
pub fn parse_asname_txt(txt: &str) -> Option<String> {
    let parts: Vec<&str> = txt.splitn(5, '|').collect();
    let name = parts.get(4)?.trim();
    if name.is_empty() {
        return None;
    }
    Some(trim_country_suffix(name).to_owned())
}

/// Strip trailing `, XX` country suffix from an AS name.
///
/// Matches the pattern: ends with `, ` followed by exactly two uppercase ASCII
/// letters.  The check is done manually to avoid a regex dependency.
pub fn trim_country_suffix(name: &str) -> &str {
    let bytes = name.as_bytes();
    let len = bytes.len();
    // Need at least 4 bytes: ',' + ' ' + 'A' + 'A'.
    let trim_len = len.saturating_sub(4);
    if len >= 4
        && bytes.get(trim_len).copied() == Some(b',')
        && bytes.get(trim_len.saturating_add(1)).copied() == Some(b' ')
        && bytes
            .get(trim_len.saturating_add(2))
            .is_some_and(u8::is_ascii_uppercase)
        && bytes
            .get(trim_len.saturating_add(3))
            .is_some_and(u8::is_ascii_uppercase)
    {
        return &name[..trim_len];
    }
    name
}

/// Check if an IP is covered by any [`IpNet`] key in the cache map.
///
/// Returns the first matching [`CymruData`] clone, or `None`.
pub fn find_in_cache(ip: IpAddr, cache: &HashMap<IpNet, CymruData>) -> Option<CymruData> {
    cache
        .iter()
        .find(|(net, _)| net.contains(&ip))
        .map(|(_, data)| data.clone())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    // ── cymru_origin_name ────────────────────────────────────────────────────

    #[test]
    fn cymru_origin_name_ipv4() {
        let ip: IpAddr = "198.51.100.57".parse().unwrap();
        assert_eq!(cymru_origin_name(ip), "57.100.51.198.origin.asn.cymru.com");
    }

    #[test]
    fn cymru_origin_name_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let name = cymru_origin_name(ip);
        assert!(
            name.ends_with(".origin6.asn.cymru.com"),
            "expected suffix '.origin6.asn.cymru.com', got: {name}"
        );
    }

    // ── cymru_asname_name ────────────────────────────────────────────────────

    #[test]
    fn cymru_asname_name_format() {
        assert_eq!(cymru_asname_name(64496), "as64496.asn.cymru.com");
    }

    // ── parse_origin_txt ─────────────────────────────────────────────────────

    #[test]
    fn parse_origin_txt_valid() {
        let txt = "64496 | 198.51.100.0/24 | JP | apnic | 2001-01-01";
        let result = parse_origin_txt(txt);
        assert!(result.is_some());
        let (asn, prefix, country, registry, allocated) = result.unwrap();
        assert_eq!(asn, 64496);
        assert_eq!(prefix, "198.51.100.0/24");
        assert_eq!(country, "JP");
        assert_eq!(registry, "apnic");
        assert_eq!(allocated, "2001-01-01");
    }

    #[test]
    fn parse_origin_txt_malformed() {
        let result = parse_origin_txt("not | valid");
        assert!(result.is_none());
    }

    #[test]
    fn parse_origin_txt_empty() {
        assert!(parse_origin_txt("").is_none());
    }

    // ── parse_asname_txt ─────────────────────────────────────────────────────

    #[test]
    fn parse_asname_txt_with_country() {
        let txt = "64496 | JP | apnic | 2001-01-01 | EXAMPLE-NET Example Network, Inc., JP";
        let result = parse_asname_txt(txt);
        assert_eq!(result.as_deref(), Some("EXAMPLE-NET Example Network, Inc."));
    }

    #[test]
    fn parse_asname_txt_without_country() {
        let txt = "12345 | US | arin | 2000-01-01 | SOMENET";
        let result = parse_asname_txt(txt);
        assert_eq!(result.as_deref(), Some("SOMENET"));
    }

    // ── trim_country_suffix ──────────────────────────────────────────────────

    #[test]
    fn trim_country_suffix_strips() {
        assert_eq!(
            trim_country_suffix("EXAMPLE-NET Example Network, Inc., JP"),
            "EXAMPLE-NET Example Network, Inc."
        );
    }

    #[test]
    fn trim_country_suffix_simple() {
        assert_eq!(trim_country_suffix("CLOUDFLARENET, US"), "CLOUDFLARENET");
    }

    #[test]
    fn trim_country_suffix_with_hyphen_in_name() {
        assert_eq!(trim_country_suffix("AMAZON-02, US"), "AMAZON-02");
    }

    #[test]
    fn trim_country_suffix_no_suffix() {
        assert_eq!(
            trim_country_suffix("NO-COUNTRY-SUFFIX"),
            "NO-COUNTRY-SUFFIX"
        );
    }

    #[test]
    fn trim_country_suffix_preserves_non_matching() {
        // lowercase country code — should NOT be stripped.
        assert_eq!(trim_country_suffix("FOO, usa"), "FOO, usa");
    }

    #[test]
    fn trim_country_suffix_three_char_token_not_stripped() {
        // 3-char token after comma — must not trim.
        assert_eq!(
            trim_country_suffix("EXAMPLE, JP-EXTRA"),
            "EXAMPLE, JP-EXTRA"
        );
    }

    #[test]
    fn trim_country_suffix_mid_string_not_stripped() {
        // ", JP" appears in the middle, not at the end.
        assert_eq!(trim_country_suffix("A, JP B"), "A, JP B");
    }

    // ── find_in_cache ────────────────────────────────────────────────────────

    #[test]
    fn find_in_cache_hit() {
        let mut cache: HashMap<IpNet, CymruData> = HashMap::new();
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        let data = CymruData {
            asn: 64496,
            prefix: String::from("203.0.113.0/24"),
            country: String::from("US"),
            registry: String::from("arin"),
            allocated: String::from("2010-01-01"),
            as_name: None,
        };
        cache.insert(net, data);

        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        let found = find_in_cache(ip, &cache);
        assert!(found.is_some());
        assert_eq!(found.unwrap().asn, 64496);
    }

    #[test]
    fn find_in_cache_miss() {
        let mut cache: HashMap<IpNet, CymruData> = HashMap::new();
        let net: IpNet = "203.0.113.0/24".parse().unwrap();
        let data = CymruData {
            asn: 64496,
            prefix: String::from("203.0.113.0/24"),
            country: String::from("US"),
            registry: String::from("arin"),
            allocated: String::from("2010-01-01"),
            as_name: None,
        };
        cache.insert(net, data);

        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let found = find_in_cache(ip, &cache);
        assert!(found.is_none());
    }

    // ── ip_to_host_net ────────────────────────────────────────────────────────

    #[test]
    fn ip_to_host_net_ipv4_slash32() {
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let net = ip_to_host_net(ip);
        assert_eq!(net.prefix_len(), 32);
        assert_eq!(net.addr(), ip);
    }

    #[test]
    fn ip_to_host_net_ipv6_slash128() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let net = ip_to_host_net(ip);
        assert_eq!(net.prefix_len(), 128);
        assert_eq!(net.addr(), ip);
    }

    // ── ip_bucket ─────────────────────────────────────────────────────────────

    #[test]
    fn ip_bucket_ipv4_slash26() {
        let ip: IpAddr = "198.51.100.57".parse().unwrap();
        let bucket = ip_bucket(ip);
        assert_eq!(bucket.prefix_len(), 26);
        // 198.51.100.57 is in the .0/26 bucket (0..63).
        assert_eq!(bucket.addr().to_string(), "198.51.100.0");
    }

    #[test]
    fn ip_bucket_ipv4_second_slash26() {
        // 198.51.100.64 is the start of the .64/26 bucket.
        let ip: IpAddr = "198.51.100.64".parse().unwrap();
        let bucket = ip_bucket(ip);
        assert_eq!(bucket.prefix_len(), 26);
        assert_eq!(bucket.addr().to_string(), "198.51.100.64");
    }

    #[test]
    fn ip_bucket_ipv6_slash66() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let bucket = ip_bucket(ip);
        assert_eq!(bucket.prefix_len(), 66);
    }

    // ── group_into_buckets ────────────────────────────────────────────────────

    #[test]
    fn group_into_buckets_empty() {
        let buckets = group_into_buckets(&[]);
        assert!(buckets.is_empty());
    }

    #[test]
    fn group_into_buckets_same_bucket() {
        let ips: Vec<IpAddr> = vec![
            "198.51.100.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
        ];
        let buckets = group_into_buckets(&ips);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets.first().map(|(_, v)| v.len()), Some(2));
    }

    #[test]
    fn group_into_buckets_different_buckets() {
        let ips: Vec<IpAddr> = vec![
            "198.51.100.1".parse().unwrap(),  // .0/26
            "198.51.100.65".parse().unwrap(), // .64/26
        ];
        let buckets = group_into_buckets(&ips);
        assert_eq!(buckets.len(), 2);
        if let [(k0, _), (k1, _)] = buckets.as_slice() {
            assert!(k0 < k1);
        } else {
            panic!("expected exactly 2 buckets");
        }
    }

    #[test]
    fn parse_asname_txt_empty_name_returns_none() {
        let txt = "64496 | JP | apnic | 2001-01-01 | ";
        let result = parse_asname_txt(txt);
        assert!(result.is_none());
    }
}
