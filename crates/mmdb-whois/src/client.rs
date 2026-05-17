//! TCP port 43 whois client with rate limiting, exponential backoff retry, and local cache.
//!
//! APNIC does not support persistent connections (-k flag); each query opens
//! a new TCP connection. Sequential queries with inter-query delays are used
//! to stay within undisclosed rate limits.
//!
//! Successful responses are cached as JSON files under `{cache_dir}/whois-{cidr}.json`
//! and reused for `cache_ttl_secs` to avoid re-querying the same prefix.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context as _, Result, bail};
use ipnet::IpNet;
use mmdb_core::{
    config::WhoisConfig,
    types::{AutNumData, WhoisData},
};
use serde::{Deserialize, Serialize};
use tokio::{
    fs as tfs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    sync::Mutex,
    time,
};

use crate::rpsl::{inetnum_to_net, parse_iana_response, parse_referral, parse_rpsl_all};

/// Disk-serializable IANA cache entry.
#[derive(Debug, Serialize, Deserialize)]
struct IanaCacheEntry {
    block: String,
    server: String,
}

/// Whois client with built-in rate limiting, retry logic, and per-CIDR response cache.
#[allow(clippy::module_name_repetitions)]
pub struct WhoisClient {
    server: String,
    timeout: Duration,
    rate_limit: Duration,
    max_retries: u32,
    initial_backoff: Duration,
    cache_dir: PathBuf,
    cache_ttl: Duration,
    auto_rir: bool,
    iana_cache: Mutex<Option<HashMap<IpNet, String>>>,
}

impl std::fmt::Debug for WhoisClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhoisClient")
            .field("server", &self.server)
            .field("timeout", &self.timeout)
            .field("auto_rir", &self.auto_rir)
            .finish_non_exhaustive()
    }
}

impl WhoisClient {
    /// Create a client from [`WhoisConfig`].
    #[must_use]
    pub fn from_config(cfg: &WhoisConfig) -> Self {
        Self {
            server: cfg.server.clone(),
            timeout: Duration::from_secs(cfg.timeout_sec),
            rate_limit: Duration::from_millis(cfg.rate_limit_ms),
            max_retries: cfg.max_retries,
            initial_backoff: Duration::from_millis(cfg.initial_backoff_ms),
            cache_dir: PathBuf::from(&cfg.cache_dir),
            cache_ttl: Duration::from_secs(cfg.cache_ttl_secs),
            auto_rir: cfg.auto_rir,
            iana_cache: Mutex::new(None),
        }
    }

    /// Query a single prefix with retry on transient failures.
    ///
    /// If `autnum` is provided, its `as_num`/`as_name`/`as_descr` are embedded
    /// into every returned [`WhoisData`] before caching, so future cache reads
    /// already contain the AS fields without further enrichment.
    ///
    /// Cache filename: `whois-cidr-{family}-{sanitized}.jsonl`.
    ///
    /// # Errors
    ///
    /// Returns an error if all retry attempts are exhausted or a non-transient
    /// failure occurs.
    // NOTEST(io): TCP 43 whois query with file cache — depends on network and filesystem
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tracing::instrument(skip(self, autnum), fields(server = %self.server))]
    pub async fn query_cidr(
        &self,
        cidr: &IpNet,
        autnum: Option<&AutNumData>,
    ) -> Result<Vec<WhoisData>> {
        let cache_path = self
            .cache_dir
            .join(format!("whois-cidr-{}.jsonl", cidr_to_filename(cidr)));

        // Return cached result list if still fresh.
        // Also checks legacy filename formats for backward compatibility.
        let legacy_new = self
            .cache_dir
            .join(format!("whois-{}.json", cidr_to_filename(cidr)));
        let legacy_old = self
            .cache_dir
            .join(format!("whois-{}.json", cidr_to_legacy_filename(cidr)));
        let read_path = if is_cache_fresh(&cache_path, self.cache_ttl).await {
            Some(cache_path.clone())
        } else if is_cache_fresh(&legacy_new, self.cache_ttl).await {
            Some(legacy_new)
        } else if is_cache_fresh(&legacy_old, self.cache_ttl).await {
            Some(legacy_old)
        } else {
            None
        };
        if let Some(ref path) = read_path {
            tracing::debug!(cidr = %cidr, "whois: using cached response");
            let raw = tfs::read(path)
                .await
                .with_context(|| format!("failed to read whois cache for {cidr}"))?;
            // Support both NDJSON (new) and JSON array (legacy) cache formats.
            return if raw.first() == Some(&b'[') {
                serde_json::from_slice(&raw)
                    .with_context(|| format!("failed to parse whois cache for {cidr}"))
            } else {
                let mut results = Vec::new();
                for line in raw.split(|&b| b == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    let entry: WhoisData = serde_json::from_slice(line)
                        .with_context(|| format!("failed to parse whois cache line for {cidr}"))?;
                    results.push(entry);
                }
                Ok(results)
            };
        }

        let mut backoff = self.initial_backoff;

        for attempt in 0..=self.max_retries {
            match self.do_query(cidr).await {
                Ok(mut entries) => {
                    if let Some(an) = autnum {
                        for e in &mut entries {
                            embed_autnum(e, an);
                        }
                    }
                    if let Err(e) = self.write_cache_ndjson(&cache_path, cidr, &entries).await {
                        tracing::warn!(cidr = %cidr, error = %e, "whois: failed to write cache");
                    }
                    return Ok(entries);
                }
                Err(e) if is_rate_limited(&e) => {
                    let wait = Duration::from_secs(30);
                    tracing::warn!(
                        cidr = %cidr,
                        wait_secs = wait.as_secs(),
                        "whois: rate limited, backing off"
                    );
                    time::sleep(wait).await;
                }
                Err(e) if is_transient(&e) && attempt < self.max_retries => {
                    tracing::warn!(
                        cidr = %cidr,
                        attempt,
                        error = %e,
                        backoff_ms = backoff.as_millis(),
                        "whois: transient error, retrying"
                    );
                    time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("whois query failed for {cidr}"));
                }
            }
        }

        bail!("whois query exhausted all retries for {cidr}")
    }

    /// Query multiple prefixes sequentially with inter-query rate limiting.
    ///
    /// `autnum` is passed to each [`Self::query_cidr`] call so AS fields are
    /// embedded at query time and included in the cache.
    ///
    /// Each input CIDR may expand to multiple `(IpNet, WhoisData)` entries when the
    /// `-M` (more-specific) query finds sub-allocations within the queried prefix.
    /// The output `IpNet` is derived from each inetnum record, not from the input CIDR.
    /// Failed queries produce one `(input_cidr, Err(_))` entry.
    // NOTEST(io): batch TCP 43 whois queries — depends on network and file cache
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub async fn query_all(
        &self,
        cidrs: &[IpNet],
        autnum: Option<&AutNumData>,
    ) -> Vec<(IpNet, Result<WhoisData>)> {
        let total = cidrs.len();
        tracing::info!(total, auto_rir = self.auto_rir, fallback_server = %self.server, "whois: starting batch query");

        let mut results: Vec<(IpNet, Result<WhoisData>)> = Vec::with_capacity(total);
        let mut cache_hits: usize = 0;

        for (i, cidr) in cidrs.iter().enumerate() {
            let cache_path = self
                .cache_dir
                .join(format!("whois-cidr-{}.jsonl", cidr_to_filename(cidr)));
            let legacy_new = self
                .cache_dir
                .join(format!("whois-{}.json", cidr_to_filename(cidr)));
            let legacy_old = self
                .cache_dir
                .join(format!("whois-{}.json", cidr_to_legacy_filename(cidr)));
            let from_cache = is_cache_fresh(&cache_path, self.cache_ttl).await
                || is_cache_fresh(&legacy_new, self.cache_ttl).await
                || is_cache_fresh(&legacy_old, self.cache_ttl).await;
            if from_cache {
                cache_hits = cache_hits.saturating_add(1);
            }

            let progress = i.saturating_add(1);

            match self.query_cidr(cidr, autnum).await {
                Ok(entries) => {
                    let count = entries.len();
                    for data in entries {
                        // Derive the IpNet from the inetnum field; fall back to the queried CIDR.
                        let net = inetnum_to_net(&data.inetnum).unwrap_or_else(|| {
                            tracing::trace!(
                                cidr = %cidr,
                                inetnum = %data.inetnum,
                                "whois: inetnum not CIDR-aligned, using queried CIDR as key"
                            );
                            *cidr
                        });
                        results.push((net, Ok(data)));
                    }
                    tracing::info!(
                        progress,
                        total,
                        cidr = %cidr,
                        ok = true,
                        records = count,
                        cached = from_cache,
                        "whois: query complete"
                    );
                }
                Err(e) => {
                    tracing::info!(
                        progress,
                        total,
                        cidr = %cidr,
                        ok = false,
                        cached = from_cache,
                        "whois: query complete"
                    );
                    results.push((*cidr, Err(e)));
                }
            }

            // Apply inter-query delay after every query except the last.
            // Skip delay for cache hits since no network request was made.
            if progress < total && !from_cache {
                time::sleep(self.rate_limit).await;
            }
        }

        let queried = total.saturating_sub(cache_hits);
        tracing::info!(total, cache_hits, queried, "whois: batch query finished");
        results
    }

    /// Resolve the authoritative WHOIS server for `ip`.
    ///
    /// When `auto_rir` is disabled, returns the configured fallback server immediately.
    /// Otherwise checks the in-memory IANA cache (populated lazily from disk on first call),
    /// and on a miss queries `whois.iana.org` to discover the correct RIR server.
    /// Falls back to `self.server` on any IANA lookup failure.
    // NOTEST(io): IANA TCP 43 lookup and disk cache — depends on network and filesystem
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn resolve_server(&self, ip: IpAddr) -> String {
        if !self.auto_rir {
            return self.server.clone();
        }

        {
            let mut guard = self.iana_cache.lock().await;
            if guard.is_none() {
                let mut entries = HashMap::new();
                self.fill_iana_from_disk(&mut entries).await;
                *guard = Some(entries);
            }
            if let Some(entries) = guard.as_ref() {
                for (block, server) in entries {
                    if block.contains(&ip) {
                        return server.clone();
                    }
                }
            }
        }

        match self.iana_lookup(ip).await {
            Ok((block, server)) => {
                tracing::debug!(
                    ip = %ip,
                    block = %block,
                    server = %server,
                    "whois: IANA lookup resolved RIR server"
                );
                self.iana_cache
                    .lock()
                    .await
                    .get_or_insert_with(HashMap::new)
                    .insert(block, server.clone());
                if let Err(e) = self.save_iana_disk_cache(block, &server).await {
                    tracing::warn!(error = %e, "whois: failed to write IANA cache");
                }
                server
            }
            Err(e) => {
                tracing::warn!(
                    ip = %ip,
                    error = %e,
                    fallback = %self.server,
                    "whois: IANA lookup failed, using fallback server"
                );
                self.server.clone()
            }
        }
    }

    /// Query `whois.iana.org` for `ip` and return the delegation block and RIR server.
    // NOTEST(io): TCP 43 connection to whois.iana.org — depends on live network
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn iana_lookup(&self, ip: IpAddr) -> Result<(IpNet, String)> {
        let query = format!("{ip}\r\n");
        let response = self
            .tcp43_send(&query, "whois.iana.org")
            .await
            .with_context(|| format!("IANA whois query failed for {ip}"))?;
        parse_iana_response(&response)
            .with_context(|| format!("IANA whois response missing inetnum/refer for {ip}"))
    }

    // NOTEST(io): scans filesystem for IANA cache files — depends on filesystem state
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fill_iana_from_disk(&self, entries: &mut HashMap<IpNet, String>) {
        let Ok(mut dir) = tfs::read_dir(&self.cache_dir).await else {
            return;
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let has_json_ext = std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
            if !name.starts_with("whois-iana-") || !has_json_ext {
                continue;
            }
            let path = entry.path();
            if !is_cache_fresh(&path, self.cache_ttl).await {
                continue;
            }
            let Ok(raw) = tfs::read(&path).await else {
                continue;
            };
            let Ok(cached) = serde_json::from_slice::<IanaCacheEntry>(&raw) else {
                continue;
            };
            let Ok(block) = cached.block.parse::<IpNet>() else {
                continue;
            };
            entries.insert(block, cached.server);
        }
    }

    // NOTEST(io): file I/O — writes IANA cache entry to filesystem
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn save_iana_disk_cache(&self, block: IpNet, server: &str) -> Result<()> {
        let path = self
            .cache_dir
            .join(format!("whois-iana-{}.json", cidr_to_filename(&block)));
        if let Some(parent) = path.parent() {
            tfs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create IANA cache dir {}", parent.display()))?;
        }
        let entry = IanaCacheEntry {
            block: block.to_string(),
            server: server.to_owned(),
        };
        let json = serde_json::to_vec(&entry).context("failed to serialize IANA cache entry")?;
        tfs::write(&path, &json)
            .await
            .with_context(|| format!("failed to write IANA cache {}", path.display()))?;
        Ok(())
    }

    // NOTEST(io): file I/O — writes NDJSON cache to filesystem
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn write_cache_ndjson(
        &self,
        cache_path: &std::path::Path,
        cidr: &IpNet,
        entries: &[WhoisData],
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt as _;

        if let Some(parent) = cache_path.parent() {
            tfs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create whois cache dir {}", parent.display())
            })?;
        }
        let mut file = tfs::File::create(cache_path)
            .await
            .with_context(|| format!("failed to create whois cache for {cidr}"))?;
        for entry in entries {
            let line = serde_json::to_string(entry)
                .with_context(|| format!("failed to serialize whois entry for {cidr}"))?;
            file.write_all(line.as_bytes())
                .await
                .with_context(|| format!("failed to write whois cache line for {cidr}"))?;
            file.write_all(b"\n")
                .await
                .with_context(|| format!("failed to write newline in whois cache for {cidr}"))?;
        }
        file.flush()
            .await
            .with_context(|| format!("failed to flush whois cache for {cidr}"))?;
        tracing::debug!(
            cidr = %cidr,
            path = %cache_path.display(),
            records = entries.len(),
            "whois: cached response"
        );
        Ok(())
    }

    // NOTEST(io): delegates to query_server which makes TCP 43 connections
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn do_query(&self, cidr: &IpNet) -> Result<Vec<WhoisData>> {
        let server = self.resolve_server(cidr.network()).await;
        self.query_server(cidr, &server, 0).await
    }

    /// Query `server` and follow `refer:` referrals up to `MAX_REFERRAL_DEPTH`.
    // NOTEST(io): TCP 43 queries with referral following — depends on live network
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn query_server<'a>(
        &'a self,
        cidr: &'a IpNet,
        server: &'a str,
        depth: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<WhoisData>>> + Send + 'a>>
    {
        Box::pin(async move {
            const MAX_REFERRAL_DEPTH: u8 = 3;

            // Step 1: -M query — finds all inetnums contained within the queried CIDR.
            // Preferred over the bare query because BGP prefixes are typically aggregates
            // that contain many customer sub-allocations (e.g. /19 → multiple /25 entries).
            if depth == 0 {
                let response_m = self.tcp43_raw(cidr, server, true).await?;
                let entries_m = parse_rpsl_all(&response_m);
                if !entries_m.is_empty() {
                    tracing::debug!(cidr = %cidr, records = entries_m.len(), "whois: -M query hit");
                    return Ok(entries_m);
                }
            }

            // Step 2: bare query — finds the inetnum that contains or exactly matches the CIDR.
            // Fallback for prefixes that have a direct inetnum record but no sub-allocations
            // (e.g. a single /24 allocation with no further splits).
            let response = self.tcp43_raw(cidr, server, false).await?;
            let entries = parse_rpsl_all(&response);
            if !entries.is_empty() {
                return Ok(entries);
            }

            // Step 3: follow referral if any.
            if depth < MAX_REFERRAL_DEPTH
                && let Some(refer_to) = parse_referral(&response)
            {
                tracing::debug!(
                    cidr = %cidr,
                    from = server,
                    to = %refer_to,
                    "whois: following referral"
                );
                return self
                    .query_server(cidr, &refer_to, depth.saturating_add(1))
                    .await;
            }

            anyhow::bail!("whois response has no inetnum/inet6num for {cidr}")
        })
    }

    /// Send a raw TCP 43 query to `server` and return the full response text.
    ///
    /// When `more_specific` is `true`, adds `-M` to find sub-allocations contained
    /// within the queried CIDR.  Otherwise uses a bare query that returns the
    /// inetnum containing or exactly matching the CIDR.
    // NOTEST(io): pure query formatter — but called only from query_server (I/O) so excluded
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn tcp43_raw(&self, cidr: &IpNet, server: &str, more_specific: bool) -> Result<String> {
        let query = if more_specific {
            format!("-r -T inetnum,inet6num -M {cidr}\r\n")
        } else {
            format!("-r -T inetnum,inet6num {cidr}\r\n")
        };
        self.tcp43_send(&query, server).await
    }

    /// Open a TCP 43 connection to `server`, send `query`, and return the full response.
    // NOTEST(io): TCP connection — depends on live network
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn tcp43_send(&self, query: &str, server: &str) -> Result<String> {
        let addr = format!("{server}:43");

        let mut stream = time::timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .with_context(|| format!("timeout connecting to {addr}"))?
            .with_context(|| format!("failed to connect to {addr}"))?;

        time::timeout(self.timeout, stream.write_all(query.as_bytes()))
            .await
            .with_context(|| "timeout sending whois query")?
            .with_context(|| "failed to send whois query")?;

        let mut response = String::new();
        time::timeout(self.timeout, stream.read_to_string(&mut response))
            .await
            .with_context(|| "timeout reading whois response")?
            .with_context(|| "failed to read whois response")?;

        if is_rate_limited_response(&response) {
            bail!("RATE_LIMITED: server returned rate limit response");
        }

        Ok(response)
    }
}

/// Returns true if the error indicates the server is rate limiting us.
fn is_rate_limited(e: &anyhow::Error) -> bool {
    e.to_string().contains("RATE_LIMITED")
}

/// Returns true if the error is transient and worth retrying.
fn is_transient(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("timeout") || msg.contains("connection") || msg.contains("reset")
}

/// Convert a CIDR to a filesystem-safe filename component with address-family prefix.
///
/// Produces `ipv4-<addr>_<len>` or `ipv6-<addr>_<len>`, replacing `/` with `_`
/// and `:` with `-` so the result is safe as a filename on all platforms.
fn cidr_to_filename(cidr: &IpNet) -> String {
    let family = match cidr {
        IpNet::V4(_) => "ipv4",
        IpNet::V6(_) => "ipv6",
    };
    let sanitized = cidr.to_string().replace('/', "_").replace(':', "-");
    format!("{family}-{sanitized}")
}

/// Legacy filename format (without address-family prefix) used before the rename.
///
/// Checked as a fallback so that existing cache files remain usable after upgrading.
fn cidr_to_legacy_filename(cidr: &IpNet) -> String {
    cidr.to_string().replace('/', "_").replace(':', "-")
}

/// Embed AS fields from `autnum` into `data`.
fn embed_autnum(data: &mut WhoisData, autnum: &AutNumData) {
    data.as_num = Some(autnum.aut_num.clone());
    data.as_name = Some(autnum.as_name.clone());
    data.as_descr.clone_from(&autnum.descr);
}

/// Returns true if `path` exists and was modified within `ttl`.
// NOTEST(io): filesystem metadata check — depends on file system state
#[cfg_attr(coverage_nightly, coverage(off))]
async fn is_cache_fresh(path: &std::path::Path, ttl: Duration) -> bool {
    let Ok(meta) = tfs::metadata(path).await else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age < ttl)
}

/// Detect rate-limit responses by common APNIC/RIPE response patterns.
fn is_rate_limited_response(response: &str) -> bool {
    response.contains("ERROR:201") // RIPE/APNIC: "Too many connections"
        || response.contains("rate limit")
        || response.contains("Rate limit")
        || response.contains("too many queries")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client(auto_rir: bool) -> WhoisClient {
        WhoisClient {
            server: String::from("whois.example.net"),
            timeout: Duration::from_secs(10),
            rate_limit: Duration::from_millis(0),
            max_retries: 0,
            initial_backoff: Duration::from_millis(0),
            cache_dir: PathBuf::from("/tmp"),
            cache_ttl: Duration::from_secs(3600),
            auto_rir,
            iana_cache: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn resolve_server_returns_fallback_when_auto_rir_disabled() {
        let client = make_client(false);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let server = client.resolve_server(ip).await;
        assert_eq!(server, "whois.example.net");
    }

    #[tokio::test]
    async fn resolve_server_uses_memory_cache_hit() {
        let client = make_client(true);
        let block: IpNet = "198.51.100.0/24".parse().unwrap();
        {
            let mut guard = client.iana_cache.lock().await;
            *guard = Some(HashMap::from([(
                block,
                String::from("whois.cached-rir.net"),
            )]));
        }
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let server = client.resolve_server(ip).await;
        assert_eq!(server, "whois.cached-rir.net");
    }

    #[test]
    fn is_rate_limited_response_detects_patterns() {
        assert!(is_rate_limited_response("ERROR:201 Too many connections"));
        assert!(is_rate_limited_response("rate limit exceeded"));
        assert!(!is_rate_limited_response(
            "inetnum: 192.0.2.0 - 192.0.2.255"
        ));
    }

    #[test]
    fn is_rate_limited_detects_error_message() {
        let e = anyhow::anyhow!("RATE_LIMITED: server returned rate limit response");
        assert!(is_rate_limited(&e));
        let ok = anyhow::anyhow!("connection refused");
        assert!(!is_rate_limited(&ok));
    }

    #[test]
    fn is_transient_detects_timeout_and_connection() {
        assert!(is_transient(&anyhow::anyhow!(
            "timeout connecting to whois"
        )));
        assert!(is_transient(&anyhow::anyhow!("connection refused")));
        assert!(is_transient(&anyhow::anyhow!("connection reset by peer")));
        assert!(is_transient(&anyhow::anyhow!("reset by peer")));
        assert!(!is_transient(&anyhow::anyhow!("parse error")));
    }

    #[test]
    fn cidr_to_filename_ipv4() {
        let cidr: IpNet = "198.51.100.0/24".parse().unwrap();
        assert_eq!(cidr_to_filename(&cidr), "ipv4-198.51.100.0_24");
    }

    #[test]
    fn cidr_to_filename_ipv6() {
        let cidr: IpNet = "2001:db8::/32".parse().unwrap();
        assert_eq!(cidr_to_filename(&cidr), "ipv6-2001-db8--_32");
    }

    #[test]
    fn cidr_to_legacy_filename_ipv4() {
        let cidr: IpNet = "198.51.100.0/24".parse().unwrap();
        assert_eq!(cidr_to_legacy_filename(&cidr), "198.51.100.0_24");
    }

    #[test]
    fn embed_autnum_sets_as_fields() {
        use mmdb_core::types::{AutNumData, WhoisData};
        let autnum = AutNumData {
            aut_num: String::from("AS64496"),
            as_name: String::from("EXAMPLE-NET"),
            descr: Some(String::from("Example Network, Inc.")),
        };
        let mut data = WhoisData {
            inetnum: String::from("198.51.100.0/24"),
            netname: String::from("TEST-NET"),
            descr: None,
            country: None,
            source: None,
            last_modified: None,
            as_num: None,
            as_name: None,
            as_descr: None,
        };
        embed_autnum(&mut data, &autnum);
        assert_eq!(data.as_num.as_deref(), Some("AS64496"));
        assert_eq!(data.as_name.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(data.as_descr.as_deref(), Some("Example Network, Inc."));
    }
}
