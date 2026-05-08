//! `DoH` resolver construction.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use hickory_resolver::Resolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, NameServerConfig, QUAD9, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use crate::types::DohServer;

/// Concrete async resolver type backed by the Tokio runtime.
pub type AsyncResolver = Resolver<TokioRuntimeProvider>;

/// Build a `DoH` resolver from a [`DohServer`] selection.
///
/// # Errors
///
/// Returns an error if the resolver cannot be initialised.
pub fn build_resolver(server: &DohServer, timeout_sec: u64) -> Result<AsyncResolver> {
    let config = match server {
        DohServer::Cloudflare => ResolverConfig::https(&CLOUDFLARE),
        DohServer::Google => ResolverConfig::https(&GOOGLE),
        DohServer::Quad9 => ResolverConfig::https(&QUAD9),
        DohServer::Custom { ip, server_name } => {
            let ip_addr: std::net::IpAddr = ip
                .parse()
                .with_context(|| format!("invalid DoH server IP: {ip}"))?;
            let ns = NameServerConfig::https(ip_addr, Arc::from(server_name.as_str()), None);
            ResolverConfig::from_parts(None, vec![], vec![ns])
        }
    };

    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().timeout = Duration::from_secs(timeout_sec);
    builder.build().context("failed to build DoH resolver")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cloudflare_resolver_succeeds() {
        let result = build_resolver(&DohServer::Cloudflare, 5);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn build_custom_resolver_invalid_ip_errors() {
        let result = build_resolver(
            &DohServer::Custom {
                ip: String::from("not-an-ip"),
                server_name: String::from("dns.example.com"),
            },
            5,
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_custom_resolver_valid_ip_succeeds() {
        let result = build_resolver(
            &DohServer::Custom {
                ip: String::from("9.9.9.9"),
                server_name: String::from("dns.quad9.net"),
            },
            5,
        );
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }
}
