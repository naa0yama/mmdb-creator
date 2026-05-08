//! TCP port 43 whois client with rate limiting, exponential backoff retry, and local cache.
//!
//! APNIC does not support persistent connections (-k flag); each query opens
//! a new TCP connection. Sequential queries with inter-query delays are used
//! to stay within undisclosed rate limits.
//!
//! Successful responses are cached as JSON files under `{cache_dir}/whois-{cidr}.json`
//! and reused for `cache_ttl_secs` to avoid re-querying the same prefix.

use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context as _, Result, bail};
use ipnet::IpNet;
use mmdb_core::{
    config::WhoisConfig,
    types::{AutNumData, WhoisData},
};
use tokio::{
    fs as tfs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time,
};

use crate::rpsl::{inetnum_to_net, parse_referral, parse_rpsl_all};

/// Whois client with built-in rate limiting, retry logic, and per-CIDR response cache.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct WhoisClient {
    server: String,
    timeout: Duration,
    rate_limit: Duration,
    max_retries: u32,
    initial_backoff: Duration,
    cache_dir: PathBuf,
    cache_ttl: Duration,
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
    pub async fn query_all(
        &self,
        cidrs: &[IpNet],
        autnum: Option<&AutNumData>,
    ) -> Vec<(IpNet, Result<WhoisData>)> {
        let total = cidrs.len();
        tracing::info!(total, server = %self.server, "whois: starting batch query");

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

    async fn do_query(&self, cidr: &IpNet) -> Result<Vec<WhoisData>> {
        self.query_server(cidr, &self.server.clone(), 0).await
    }

    /// Query `server` and follow `refer:` referrals up to `MAX_REFERRAL_DEPTH`.
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
            // Only attempted against the primary server; referral servers skip this step.
            if server == self.server {
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
    async fn tcp43_raw(&self, cidr: &IpNet, server: &str, more_specific: bool) -> Result<String> {
        let query = if more_specific {
            format!("-r -T inetnum,inet6num -M {cidr}\r\n")
        } else {
            format!("-r -T inetnum,inet6num {cidr}\r\n")
        };
        self.tcp43_send(&query, server).await
    }

    /// Open a TCP 43 connection to `server`, send `query`, and return the full response.
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

    #[test]
    fn is_rate_limited_response_detects_patterns() {
        assert!(is_rate_limited_response("ERROR:201 Too many connections"));
        assert!(is_rate_limited_response("rate limit exceeded"));
        assert!(!is_rate_limited_response(
            "inetnum: 192.0.2.0 - 192.0.2.255"
        ));
    }
}
