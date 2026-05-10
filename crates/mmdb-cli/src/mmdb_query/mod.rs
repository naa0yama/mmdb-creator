//! `mmdb query` subcommand: look up IP addresses in an MMDB file.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::Value;

const RULE_WIDTH: usize = 70;

/// Run the `mmdb query` subcommand.
///
/// Opens `mmdb_path`, looks up each IP in `ips`, and prints a vertical
/// key/value table to stdout for each address.
///
/// # Errors
///
/// Returns an error if `mmdb_path` cannot be opened or if any string in `ips`
/// is not a valid IP address.
// NOTEST(io): requires a real MMDB file on disk
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn run(mmdb_path: &Path, ips: &[String]) -> Result<()> {
    if ips.is_empty() {
        anyhow::bail!("no IP addresses specified");
    }

    let reader = maxminddb::Reader::open_readfile(mmdb_path)
        .with_context(|| format!("failed to open MMDB {}", mmdb_path.display()))?;

    for ip_str in ips {
        let ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("invalid IP address: {ip_str}"))?;

        print_query_result(&reader, ip_str, ip);
    }

    Ok(())
}

/// Print a single IP lookup result as a vertical key/value table.
// NOTEST(io): requires a live maxminddb::Reader and writes to stdout
#[cfg_attr(coverage_nightly, coverage(off))]
fn print_query_result<S: AsRef<[u8]>>(reader: &maxminddb::Reader<S>, ip_str: &str, ip: IpAddr) {
    let header = format!("===[ {ip_str} ]");
    let pad = RULE_WIDTH.saturating_sub(header.len());
    #[allow(clippy::print_stdout)]
    {
        println!("{}{}", header, "=".repeat(pad));
    }

    let value = reader
        .lookup(ip)
        .ok()
        .and_then(|r| r.decode::<Value>().ok().flatten());

    #[allow(clippy::print_stdout)]
    {
        match value {
            None => {
                println!("(not found)");
            }
            Some(v) => {
                let mut rows: Vec<(String, String)> = Vec::new();
                flatten_value("", &v, &mut rows);

                let key_width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);

                for (k, val) in &rows {
                    println!("{k:<key_width$}  {val}");
                }
            }
        }

        println!("{}", "=".repeat(RULE_WIDTH));
        println!();
    }
}

/// Recursively flatten a JSON value into `(dotted.key, string_value)` pairs.
///
/// Nested objects use dot-separated key paths. Arrays are joined with `, `.
fn flatten_value(prefix: &str, value: &Value, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_value(&key, v, out);
            }
        }
        Value::Array(arr) => {
            let joined = arr
                .iter()
                .map(value_to_display_string)
                .collect::<Vec<_>>()
                .join(", ");
            out.push((prefix.to_owned(), joined));
        }
        _ => {
            out.push((prefix.to_owned(), value_to_display_string(value)));
        }
    }
}

/// Convert a JSON leaf value to a display string (strips outer quotes for strings).
fn value_to_display_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::from("null"),
        _ => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn flatten(v: &Value) -> Vec<(String, String)> {
        let mut out = Vec::new();
        flatten_value("", v, &mut out);
        out
    }

    #[test]
    fn flatten_scalar_string() {
        let rows = flatten(&json!("hello"));
        assert_eq!(rows, vec![(String::new(), String::from("hello"))]);
    }

    #[test]
    fn flatten_scalar_number() {
        let rows = flatten(&json!(64496));
        assert_eq!(rows, vec![(String::new(), String::from("64496"))]);
    }

    #[test]
    fn flatten_flat_object() {
        let v = json!({"asn": 64496, "country": "JP"});
        let rows = flatten(&v);
        assert!(rows.contains(&(String::from("asn"), String::from("64496"))));
        assert!(rows.contains(&(String::from("country"), String::from("JP"))));
    }

    #[test]
    fn flatten_nested_object() {
        let v = json!({"gateway": {"ip": "198.51.100.1", "device": "rtr01"}});
        let rows = flatten(&v);
        assert!(rows.contains(&(String::from("gateway.ip"), String::from("198.51.100.1"))));
        assert!(rows.contains(&(String::from("gateway.device"), String::from("rtr01"))));
    }

    #[test]
    fn flatten_deeply_nested() {
        let v = json!({"a": {"b": {"c": "deep"}}});
        let rows = flatten(&v);
        assert_eq!(rows, vec![(String::from("a.b.c"), String::from("deep"))]);
    }

    #[test]
    fn flatten_array_joined() {
        let v = json!({"tags": ["x", "y", "z"]});
        let rows = flatten(&v);
        assert_eq!(rows, vec![(String::from("tags"), String::from("x, y, z"))]);
    }

    #[test]
    fn flatten_empty_object() {
        let rows = flatten(&json!({}));
        assert!(rows.is_empty());
    }

    #[test]
    fn flatten_null_leaf() {
        let v = json!({"field": null});
        let rows = flatten(&v);
        assert_eq!(rows, vec![(String::from("field"), String::from("null"))]);
    }

    #[test]
    fn value_to_display_string_strips_quotes() {
        assert_eq!(value_to_display_string(&json!("hello")), "hello");
    }

    #[test]
    fn value_to_display_string_number() {
        assert_eq!(value_to_display_string(&json!(42)), "42");
    }

    #[test]
    fn value_to_display_string_bool() {
        assert_eq!(value_to_display_string(&json!(true)), "true");
    }

    #[test]
    fn value_to_display_string_null() {
        assert_eq!(value_to_display_string(&Value::Null), "null");
    }
}
