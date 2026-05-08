//! Announced prefix resolver using RIPE Stat.
//!
//! Data source:
//!   - RIPE Stat: <https://stat.ripe.net/data/announced-prefixes/data.json>
//!     BGP routing observations from ~1,300 RIPE RIS peers. Real-time.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{Context as _, Result};
use ipnet::IpNet;
use mmdb_core::{
    config::WhoisConfig,
    types::{AutNumData, WhoisData},
};
use serde::Deserialize;
use tokio::{fs as tfs, time};

/// User-Agent sent with every HTTP request.
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

/// REST API client for resolving ASN → announced CIDR list via RIPE Stat.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct PrefixClient {
    http: reqwest::Client,
    ripe_stat_rate_limit: Duration,
    ripe_stat_cache_dir: PathBuf,
    ripe_stat_cache_ttl: Duration,
    http_max_retries: u32,
    http_retry_delay: Duration,
}

impl PrefixClient {
    /// Create a client from [`WhoisConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn from_config(cfg: &WhoisConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .context("failed to build HTTP client for prefix resolution")?;

        Ok(Self {
            http,
            ripe_stat_rate_limit: Duration::from_millis(cfg.ripe_stat_rate_limit_ms),
            ripe_stat_cache_dir: PathBuf::from(&cfg.cache_dir),
            ripe_stat_cache_ttl: Duration::from_secs(cfg.cache_ttl_secs),
            http_max_retries: cfg.http_max_retries,
            http_retry_delay: Duration::from_secs(cfg.http_retry_delay_secs),
        })
    }

    /// Fetch announced prefixes for `asn` from RIPE Stat.
    ///
    /// # Errors
    ///
    /// Returns an error if the RIPE Stat request fails.
    pub async fn announced_prefixes(&self, asn: u32) -> Result<Vec<IpNet>> {
        let prefixes = self.ripe_stat(asn).await?;
        if prefixes.is_empty() {
            tracing::warn!(asn, "prefix: RIPE Stat returned empty prefix list");
        } else {
            tracing::info!(
                asn,
                count = prefixes.len(),
                "prefix: resolved via RIPE Stat"
            );
        }
        Ok(prefixes)
    }

    // ---- RIPE Stat ----

    async fn ripe_stat(&self, asn: u32) -> Result<Vec<IpNet>> {
        let cache_path = self
            .ripe_stat_cache_dir
            .join(format!("ripestat-prefixes-AS{asn}.jsonl"));

        // Return cached response if still fresh.
        if is_file_fresh(&cache_path, self.ripe_stat_cache_ttl).await {
            tracing::debug!(asn, "prefix: using cached RIPE Stat response");
            let raw = tfs::read(&cache_path)
                .await
                .with_context(|| format!("failed to read RIPE Stat cache for AS{asn}"))?;
            let body: RipeStatResponse = serde_json::from_slice(&raw)
                .with_context(|| format!("failed to parse RIPE Stat cache for AS{asn}"))?;
            return Ok(body
                .data
                .prefixes
                .into_iter()
                .filter_map(|p| parse_prefix_warn(&p.prefix))
                .collect());
        }

        let url = format!(
            "https://stat.ripe.net/data/announced-prefixes/data.json\
             ?resource=AS{asn}&sourceapp=mmdb-creator"
        );

        tracing::debug!(asn, "prefix: querying RIPE Stat");

        let resp = self
            .get_with_retry(&url)
            .await
            .with_context(|| format!("RIPE Stat request failed for AS{asn}"))?;

        let raw_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("failed to read RIPE Stat response for AS{asn}"))?;

        // Persist to cache before parsing so partial failures don't corrupt the file.
        if let Some(parent) = cache_path.parent() {
            tfs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create cache dir {}", parent.display()))?;
        }
        tfs::write(&cache_path, &raw_bytes).await.with_context(|| {
            format!(
                "failed to write RIPE Stat cache for AS{asn} to {}",
                cache_path.display()
            )
        })?;

        let body: RipeStatResponse = serde_json::from_slice(&raw_bytes)
            .with_context(|| format!("failed to parse RIPE Stat response for AS{asn}"))?;

        let prefixes = body
            .data
            .prefixes
            .into_iter()
            .filter_map(|p| parse_prefix_warn(&p.prefix))
            .collect();

        time::sleep(self.ripe_stat_rate_limit).await;

        Ok(prefixes)
    }

    // ---- RIPE Stat whois (ASN → aut-num object) ----

    /// Fetch aut-num data for `asn` via RIPE Stat `/data/whois/data.json`.
    ///
    /// Returns `as-num`, `as-name`, and `descr` from the first aut-num record.
    /// Result is cached at `{cache_dir}/ripestat-autnum-AS{asn}.jsonl`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or required fields are absent.
    pub async fn query_autnum(&self, asn: u32) -> Result<AutNumData> {
        let cache_path = self
            .ripe_stat_cache_dir
            .join(format!("ripestat-autnum-AS{asn}.jsonl"));

        if is_file_fresh(&cache_path, self.ripe_stat_cache_ttl).await {
            tracing::debug!(asn, "prefix: using cached ripestat whois response");
            let raw = tfs::read(&cache_path)
                .await
                .with_context(|| format!("failed to read ripestat whois cache for AS{asn}"))?;
            // Trim trailing newline for JSONL single-record files.
            return serde_json::from_slice(raw.trim_ascii_end())
                .with_context(|| format!("failed to parse ripestat whois cache for AS{asn}"));
        }

        let url = format!(
            "https://stat.ripe.net/data/whois/data.json\
             ?resource=AS{asn}&sourceapp=mmdb-creator"
        );

        tracing::debug!(asn, "prefix: querying RIPE Stat whois for aut-num");

        let resp = self
            .get_with_retry(&url)
            .await
            .with_context(|| format!("RIPE Stat whois request failed for AS{asn}"))?;

        let raw_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("failed to read RIPE Stat whois response for AS{asn}"))?;

        let body: RipeStatWhoisResponse = serde_json::from_slice(&raw_bytes)
            .with_context(|| format!("failed to parse RIPE Stat whois response for AS{asn}"))?;

        // The first record in `records` is the aut-num object.
        let record = body
            .data
            .records
            .into_iter()
            .next()
            .with_context(|| format!("RIPE Stat whois returned no records for AS{asn}"))?;

        let mut aut_num: Option<String> = None;
        let mut as_name: Option<String> = None;
        let mut descr: Option<String> = None;

        for kv in &record {
            match kv.key.as_str() {
                "aut-num" => aut_num.get_or_insert_with(|| kv.value.clone()),
                "as-name" => as_name.get_or_insert_with(|| kv.value.clone()),
                "descr" => descr.get_or_insert_with(|| kv.value.clone()),
                _ => continue,
            };
        }

        let data = AutNumData {
            aut_num: aut_num
                .with_context(|| format!("RIPE Stat whois missing aut-num for AS{asn}"))?,
            as_name: as_name
                .with_context(|| format!("RIPE Stat whois missing as-name for AS{asn}"))?,
            descr,
        };

        if let Some(parent) = cache_path.parent()
            && let Err(e) = tfs::create_dir_all(parent).await
        {
            tracing::warn!(path = %parent.display(), error = %e, "prefix: failed to create autnum cache dir");
        }
        match serde_json::to_vec(&data) {
            Ok(mut line) => {
                line.push(b'\n');
                if let Err(e) = tfs::write(&cache_path, &line).await {
                    tracing::warn!(path = %cache_path.display(), error = %e, "prefix: failed to write autnum cache");
                }
            }
            Err(e) => {
                tracing::warn!(asn, error = %e, "prefix: failed to serialize autnum for cache");
            }
        }
        tracing::debug!(asn, path = %cache_path.display(), "prefix: ripestat whois cached");

        time::sleep(self.ripe_stat_rate_limit).await;

        Ok(data)
    }

    // ---- RIPE Stat network-info (reverse prefix→ASN) ----

    /// Reverse-lookup the ASN for a prefix via RIPE Stat network-info API.
    ///
    /// Returns the first ASN from the `asns` array, or `None` if the list is empty.
    /// Result is cached at `{cache_dir}/ripestat-network-{family}-{sanitized}.jsonl`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response cannot be parsed.
    pub async fn reverse_lookup_asn(&self, prefix: &IpNet) -> Result<Option<u32>> {
        let family = match prefix {
            IpNet::V4(_) => "ipv4",
            IpNet::V6(_) => "ipv6",
        };
        let sanitized = prefix.to_string().replace('/', "_").replace(':', "-");
        let cache_path = self
            .ripe_stat_cache_dir
            .join(format!("ripestat-network-{family}-{sanitized}.jsonl"));

        if is_file_fresh(&cache_path, self.ripe_stat_cache_ttl).await {
            tracing::debug!(prefix = %prefix, "prefix: using cached network-info response");
            let raw = tfs::read(&cache_path).await.with_context(|| {
                format!("failed to read ripestat network-info cache for {prefix}")
            })?;
            let val: serde_json::Value = serde_json::from_slice(raw.trim_ascii_end())
                .with_context(|| {
                    format!("failed to parse ripestat network-info cache for {prefix}")
                })?;
            return Ok(val
                .get("asn")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()));
        }

        let url = format!(
            "https://stat.ripe.net/data/network-info/data.json\
             ?resource={prefix}&sourceapp=mmdb-creator"
        );

        tracing::debug!(prefix = %prefix, "prefix: querying RIPE Stat network-info");

        let resp = self
            .get_with_retry(&url)
            .await
            .with_context(|| format!("RIPE Stat network-info request failed for {prefix}"))?;

        let raw_bytes = resp.bytes().await.with_context(|| {
            format!("failed to read RIPE Stat network-info response for {prefix}")
        })?;

        if let Some(parent) = cache_path.parent() {
            tfs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create cache dir {}", parent.display()))?;
        }
        // Parse before writing cache so a bad response doesn't create a stale file.
        let body: NetworkInfoResponse = serde_json::from_slice(&raw_bytes).with_context(|| {
            format!("failed to parse RIPE Stat network-info response for {prefix}")
        })?;

        let asn = body.data.asns.into_iter().next();

        // Cache the resolved ASN as a single-value JSONL line.
        let cache_line = format!("{}\n", serde_json::json!({"asn": asn}));
        tfs::write(&cache_path, cache_line.as_bytes())
            .await
            .with_context(|| {
                format!(
                    "failed to write ripestat network-info cache for {prefix} to {}",
                    cache_path.display()
                )
            })?;

        time::sleep(self.ripe_stat_rate_limit).await;

        Ok(asn)
    }

    // ---- RIPE Stat whois (CIDR → inetnum object) ----

    /// Fetch whois data for a CIDR via RIPE Stat `/data/whois/data.json`.
    ///
    /// Parses all inetnum/inet6num records returned and optionally embeds
    /// `as_num`/`as_name`/`as_descr` from `autnum` into each record.
    /// Result is cached at `{cache_dir}/ripestat-cidr-{family}-{sanitized}.jsonl`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response cannot be parsed.
    pub async fn query_cidr_whois(
        &self,
        cidr: &IpNet,
        autnum: Option<&AutNumData>,
    ) -> Result<Vec<WhoisData>> {
        let family = match cidr {
            IpNet::V4(_) => "ipv4",
            IpNet::V6(_) => "ipv6",
        };
        let sanitized = cidr.to_string().replace('/', "_").replace(':', "-");
        let cache_path = self
            .ripe_stat_cache_dir
            .join(format!("ripestat-cidr-{family}-{sanitized}.jsonl"));

        if is_file_fresh(&cache_path, self.ripe_stat_cache_ttl).await {
            tracing::debug!(cidr = %cidr, "prefix: using cached ripestat cidr whois");
            return read_ndjson_cache::<WhoisData>(&cache_path, cidr).await;
        }

        let url = format!(
            "https://stat.ripe.net/data/whois/data.json\
             ?resource={cidr}&sourceapp=mmdb-creator"
        );

        tracing::debug!(cidr = %cidr, "prefix: querying RIPE Stat whois for cidr");

        let resp = self
            .get_with_retry(&url)
            .await
            .with_context(|| format!("RIPE Stat cidr whois request failed for {cidr}"))?;

        let raw_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("failed to read RIPE Stat cidr whois response for {cidr}"))?;

        let body: RipeStatWhoisResponse = serde_json::from_slice(&raw_bytes)
            .with_context(|| format!("failed to parse RIPE Stat cidr whois response for {cidr}"))?;

        // Extract all inetnum/inet6num records.
        let mut entries: Vec<WhoisData> = body
            .data
            .records
            .iter()
            .filter_map(|record| parse_ripestat_whois_record(record, autnum))
            .collect();

        if entries.is_empty() {
            anyhow::bail!("RIPE Stat cidr whois returned no inetnum records for {cidr}");
        }

        write_ndjson_cache(&cache_path, cidr, &entries).await;
        tracing::debug!(cidr = %cidr, records = entries.len(), "prefix: ripestat cidr cached");

        // Embed autnum if not already present (autnum may change but cache won't update
        // until TTL expires; re-embedding ensures the returned slice is consistent).
        if let Some(an) = autnum {
            for e in &mut entries {
                apply_autnum(e, an);
            }
        }

        time::sleep(self.ripe_stat_rate_limit).await;

        Ok(entries)
    }

    // ---- HTTP helper ----

    /// GET with retry (connection errors + 5xx), following redirects.
    ///
    /// Mirrors `curl -sfSL --retry 3 --retry-delay 2 --retry-connrefused`.
    async fn get_with_retry(&self, url: &str) -> Result<reqwest::Response> {
        let mut delay = self.http_retry_delay;

        for attempt in 0..=self.http_max_retries {
            match self.http.get(url).send().await {
                Ok(resp) if resp.status().is_server_error() => {
                    let status = resp.status();
                    if attempt < self.http_max_retries {
                        tracing::warn!(
                            url,
                            attempt,
                            %status,
                            delay_secs = delay.as_secs(),
                            "http: server error, retrying"
                        );
                        time::sleep(delay).await;
                        delay = delay.saturating_mul(2);
                    } else {
                        anyhow::bail!("HTTP {status} after {attempt} retries: {url}");
                    }
                }
                Ok(resp) => {
                    return resp
                        .error_for_status()
                        .with_context(|| format!("HTTP error for {url}"));
                }
                Err(e) if is_retryable_error(&e) && attempt < self.http_max_retries => {
                    tracing::warn!(
                        url,
                        attempt,
                        error = %e,
                        delay_secs = delay.as_secs(),
                        "http: transient error, retrying"
                    );
                    time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("HTTP request failed: {url}"));
                }
            }
        }

        anyhow::bail!("http: exhausted retries for {url}")
    }
}

// ---- helpers ----

/// Parse one RIPE Stat whois record (Vec<KV>) into `WhoisData` if it is an inetnum/inet6num object.
fn parse_ripestat_whois_record(
    record: &[RipeStatWhoisKv],
    autnum: Option<&AutNumData>,
) -> Option<WhoisData> {
    let mut inetnum: Option<String> = None;
    let mut netname: Option<String> = None;
    let mut descr: Option<String> = None;
    let mut country: Option<String> = None;
    let mut source: Option<String> = None;
    let mut last_modified: Option<String> = None;

    for kv in record {
        match kv.key.as_str() {
            "inetnum" | "inet6num" => inetnum.get_or_insert_with(|| kv.value.clone()),
            "netname" => netname.get_or_insert_with(|| kv.value.clone()),
            "descr" => descr.get_or_insert_with(|| kv.value.clone()),
            "country" => country.get_or_insert_with(|| kv.value.clone()),
            "source" => source.get_or_insert_with(|| kv.value.clone()),
            "last-modified" => last_modified.get_or_insert_with(|| kv.value.clone()),
            _ => continue,
        };
    }

    let inetnum = inetnum?;
    let netname = netname?;

    let mut data = WhoisData {
        inetnum,
        netname,
        descr,
        country,
        source,
        last_modified,
        as_num: None,
        as_name: None,
        as_descr: None,
    };

    if let Some(an) = autnum {
        apply_autnum(&mut data, an);
    }

    Some(data)
}

/// Copy `as_num`/`as_name`/`as_descr` from `AutNumData` into `WhoisData`.
fn apply_autnum(data: &mut WhoisData, autnum: &AutNumData) {
    data.as_num = Some(autnum.aut_num.clone());
    data.as_name = Some(autnum.as_name.clone());
    data.as_descr.clone_from(&autnum.descr);
}

fn parse_prefix_warn(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>()
        .map_err(|e| {
            tracing::warn!(prefix = s, error = %e, "prefix: skipping unparseable prefix");
            e
        })
        .ok()
}

/// Returns true if the error is worth retrying (connection-level, not HTTP-level).
fn is_retryable_error(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_timeout() || e.is_request()
}

/// Returns true if `path` exists and was modified within `ttl`.
async fn is_file_fresh(path: &Path, ttl: Duration) -> bool {
    let Ok(meta) = tfs::metadata(path).await else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age: Duration| age < ttl)
}

/// Read an NDJSON cache file and deserialize each non-empty line into `T`.
async fn read_ndjson_cache<T>(
    path: &Path,
    label: &(impl std::fmt::Display + Sync),
) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    let raw = tfs::read(path)
        .await
        .with_context(|| format!("failed to read cache for {label}"))?;
    let mut results = Vec::new();
    for line in raw.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let entry: T = serde_json::from_slice(line)
            .with_context(|| format!("failed to parse cache line for {label}"))?;
        results.push(entry);
    }
    Ok(results)
}

/// Write `entries` to `path` as NDJSON (one JSON object per line).
///
/// Logs warnings on individual line failures rather than failing the whole write,
/// because the cache is best-effort and a partial write is recoverable on next fetch.
async fn write_ndjson_cache<T>(path: &Path, label: &(impl std::fmt::Display + Sync), entries: &[T])
where
    T: serde::Serialize + Sync,
{
    use tokio::io::AsyncWriteExt as _;

    if let Some(parent) = path.parent()
        && let Err(e) = tfs::create_dir_all(parent).await
    {
        tracing::warn!(path = %parent.display(), error = %e, "prefix: failed to create cache dir");
    }
    let file = match tfs::File::create(path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "prefix: failed to create cache file");
            return;
        }
    };
    let mut file = file;
    for entry in entries {
        match serde_json::to_string(entry) {
            Ok(line) => {
                if let Err(e) = file.write_all(line.as_bytes()).await {
                    tracing::warn!(label = %label, error = %e, "prefix: failed to write cache line");
                }
                if let Err(e) = file.write_all(b"\n").await {
                    tracing::warn!(label = %label, error = %e, "prefix: failed to write cache newline");
                }
            }
            Err(e) => {
                tracing::warn!(label = %label, error = %e, "prefix: failed to serialize entry for cache");
            }
        }
    }
    if let Err(e) = file.flush().await {
        tracing::warn!(label = %label, error = %e, "prefix: failed to flush cache");
    }
}

// ---- response schemas ----

#[derive(Debug, Deserialize)]
struct RipeStatResponse {
    data: RipeStatData,
}

#[derive(Debug, Deserialize)]
struct RipeStatData {
    prefixes: Vec<RipeStatPrefix>,
}

#[derive(Debug, Deserialize)]
struct RipeStatPrefix {
    prefix: String,
}

#[derive(Debug, Deserialize)]
struct NetworkInfoResponse {
    data: NetworkInfoData,
}

#[derive(Debug, Deserialize)]
struct NetworkInfoData {
    asns: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct RipeStatWhoisResponse {
    data: RipeStatWhoisData,
}

#[derive(Debug, Deserialize)]
struct RipeStatWhoisData {
    records: Vec<Vec<RipeStatWhoisKv>>,
}

#[derive(Debug, Deserialize)]
struct RipeStatWhoisKv {
    key: String,
    value: String,
}
