//! PTR reverse lookup via `DoH`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::resolver::AsyncResolver;
use crate::types::DnsConfig;

/// Resolve PTR records for a set of IP addresses via `DoH`.
///
/// Returns a map of IP → first PTR hostname. IPs that fail resolution
/// are omitted from the result (failure logged as `warn`).
pub async fn lookup(
    ips: &[IpAddr],
    resolver: &AsyncResolver,
    config: &DnsConfig,
) -> HashMap<IpAddr, String> {
    let sem = Arc::new(Semaphore::new(config.max_concurrency));
    let mut set = JoinSet::new();

    for &ip in ips {
        let sem = Arc::clone(&sem);
        let resolver = resolver.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            match resolver.reverse_lookup(ip).await {
                Ok(resp) => {
                    use hickory_resolver::proto::rr::RData;
                    let name = resp.answers().iter().find_map(|r| {
                        if let RData::PTR(ptr) = &r.data {
                            Some(ptr.to_string())
                        } else {
                            None
                        }
                    })?;
                    let name = name.trim_end_matches('.').to_owned();
                    Some((ip, name))
                }
                Err(e) => {
                    tracing::warn!(ip = %ip, error = %e, "ptr: reverse lookup failed");
                    None
                }
            }
        });
    }

    let mut results = HashMap::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some((ip, name))) = res {
            results.insert(ip, name);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_trailing_dot_from_hostname() {
        let name = "one.one.one.one.";
        let trimmed = name.trim_end_matches('.').to_owned();
        assert_eq!(trimmed, "one.one.one.one");
    }

    #[test]
    fn trim_no_dot_unchanged() {
        let name = "example.com";
        let trimmed = name.trim_end_matches('.').to_owned();
        assert_eq!(trimmed, "example.com");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn lookup_cloudflare_ptr() {
        use crate::resolver::build_resolver;
        use crate::types::DohServer;

        let config = DnsConfig::default();
        let resolver =
            build_resolver(&DohServer::Cloudflare, config.timeout_sec).expect("build resolver");
        let ip: IpAddr = "1.1.1.1".parse().expect("parse ip");
        let result = lookup(&[ip], &resolver, &config).await;
        assert!(result.contains_key(&ip), "expected PTR record for 1.1.1.1");
        assert_eq!(
            result.get(&ip).expect("PTR entry must exist"),
            "one.one.one.one"
        );
    }
}
