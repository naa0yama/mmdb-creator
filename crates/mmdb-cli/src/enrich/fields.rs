//! Field flattening, projection, and array-joining utilities for the enrich pipeline.

use mmdb_core::config::{EnrichField, EnrichFieldType};
use serde_json::{Map, Value};

/// A flattened field path with its JSON type tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldInfo {
    /// Dot-notation path (e.g. `"mmdb.operational.host"`).
    pub path: String,
    /// JSON type tag: `"string"`, `"number"`, `"bool"`, `"list"`, `"null"`, `"object"`.
    pub type_tag: &'static str,
}

/// Recursively walk `value` and collect all nodes (both intermediate Object
/// nodes and leaf nodes) as [`FieldInfo`] entries.
///
/// `prefix` is the dot-notation path accumulated from ancestor keys. Pass an
/// empty string at the call site for the root value.
///
/// Rules:
/// - Object node: emits an entry with `type_tag = "object"` **and** recurses
///   into children.
/// - Array: emits an entry with `type_tag = "list"`; does **not** recurse.
/// - Scalars (`String`, `Number`, `Bool`, `Null`): emit the corresponding tag.
/// - When `prefix` is empty the root non-Object scalar is emitted with an
///   empty `path`.
#[must_use]
pub fn flatten_fields(prefix: &str, value: &Value) -> Vec<FieldInfo> {
    let mut out = Vec::new();
    collect_fields(prefix, value, &mut out);
    out
}

fn collect_fields(prefix: &str, value: &Value, out: &mut Vec<FieldInfo>) {
    match value {
        Value::Object(map) => {
            // Emit the object node itself (skip the synthetic empty root).
            if !prefix.is_empty() {
                out.push(FieldInfo {
                    path: prefix.to_owned(),
                    type_tag: "object",
                });
            }
            for (k, v) in map {
                let child_path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                collect_fields(&child_path, v, out);
            }
        }
        Value::Array(_) => {
            out.push(FieldInfo {
                path: prefix.to_owned(),
                type_tag: "list",
            });
        }
        Value::String(_) => {
            out.push(FieldInfo {
                path: prefix.to_owned(),
                type_tag: "string",
            });
        }
        Value::Number(_) => {
            out.push(FieldInfo {
                path: prefix.to_owned(),
                type_tag: "number",
            });
        }
        Value::Bool(_) => {
            out.push(FieldInfo {
                path: prefix.to_owned(),
                type_tag: "bool",
            });
        }
        Value::Null => {
            out.push(FieldInfo {
                path: prefix.to_owned(),
                type_tag: "null",
            });
        }
    }
}

/// Walk `value` by splitting `path` on `'.'` and following Object keys.
///
/// Returns `None` if any key is missing or a non-Object is encountered mid-path.
pub(super) fn get_by_dotpath<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for key in path.split('.') {
        current = current.as_object()?.get(key)?;
    }
    Some(current)
}

/// Project and type-coerce fields from a flat JSON record using an ordered field list.
///
/// Each [`EnrichField`] selects a value by dot-notation path, applies optional
/// `output_name` renaming and `field_type` coercion, and emits a flat key-value pair.
/// Output is always flat (dot-notation keys).
///
/// On coercion failure the raw value is kept and a warning is logged.
#[must_use]
pub fn project_fields(record: &Value, fields: &[EnrichField], array_join_sep: &str) -> Value {
    let all_fields = flatten_fields("", record);
    let mut map = Map::new();

    // Paths that have their own explicit EnrichField entry.  When expanding an
    // object subtree, leaves that appear here are skipped — they will be emitted
    // (with their own output_name / type) by their own EnrichField iteration.
    let explicit_paths: std::collections::HashSet<&str> =
        fields.iter().map(|ef| ef.field.as_str()).collect();

    for ef in fields {
        let output_key = ef
            .output_name
            .as_deref()
            .unwrap_or(ef.field.as_str())
            .to_owned();
        let subtree_prefix = format!("{}.", ef.field);

        // Collect matching FieldInfo entries: exact match OR subtree under object path.
        let matched: Vec<&FieldInfo> = all_fields
            .iter()
            .filter(|info| {
                (info.path == ef.field || info.path.starts_with(&subtree_prefix))
                    && info.type_tag != "object"
            })
            .collect();

        // Warn when the config lists an object-type path (no leaf with that exact path).
        let has_exact_leaf = all_fields
            .iter()
            .any(|f| f.path == ef.field && f.type_tag != "object");
        let is_object_field = !has_exact_leaf && !matched.is_empty();
        if is_object_field {
            tracing::warn!(
                field = %ef.field,
                "enrich: object field in config — use leaf paths instead; subtree will be expanded"
            );
        }

        if matched.len() == 1 && matched.first().is_some_and(|m| m.path == ef.field) {
            // Single leaf — apply type coercion.
            let Some(val) = get_by_dotpath(record, &ef.field) else {
                continue;
            };
            let coerced = coerce_value(val, ef.field_type, array_join_sep, &ef.field);
            map.insert(output_key, coerced);
        } else {
            // Object subtree — emit flat sub-keys under output_key prefix.
            // Skip leaves that have their own explicit EnrichField entry; those
            // will be emitted with the correct output_name by their own iteration.
            for info in matched {
                if info.path != ef.field && explicit_paths.contains(info.path.as_str()) {
                    continue;
                }
                let Some(val) = get_by_dotpath(record, &info.path) else {
                    continue;
                };
                // Subtree keys: replace leading `ef.field` with `output_key`.
                let sub_key = if info.path == ef.field {
                    output_key.clone()
                } else {
                    format!(
                        "{output_key}{}",
                        &info.path[ef.field.len()..] // keeps the leading '.'
                    )
                };
                let coerced = coerce_value(val, ef.field_type, array_join_sep, &info.path);
                map.insert(sub_key, coerced);
            }
        }
    }

    Value::Object(map)
}

/// Apply [`EnrichFieldType`] coercion to a JSON value.
///
/// Returns the coerced value. On failure logs a warning and returns the raw value.
fn coerce_value(
    val: &Value,
    field_type: EnrichFieldType,
    array_join_sep: &str,
    path: &str,
) -> Value {
    match field_type {
        EnrichFieldType::Auto => val.clone(),
        EnrichFieldType::String => Value::String(scalar_to_string(val)),
        EnrichFieldType::Integer => val.as_i64().map_or_else(
            || {
                val.as_str().map_or_else(
                    || {
                        tracing::warn!(path, raw = %val, "enrich: integer coercion failed");
                        val.clone()
                    },
                    |s| {
                        s.parse::<i64>().map_or_else(
                            |_| {
                                tracing::warn!(path, raw = %val, "enrich: integer coercion failed");
                                val.clone()
                            },
                            |n| Value::Number(n.into()),
                        )
                    },
                )
            },
            |n| Value::Number(n.into()),
        ),
        EnrichFieldType::Bool => val.as_bool().map_or_else(
            || {
                val.as_str().map_or_else(
                    || {
                        tracing::warn!(path, raw = %val, "enrich: bool coercion failed");
                        val.clone()
                    },
                    |s| match s.to_lowercase().as_str() {
                        "true" | "1" | "yes" => Value::Bool(true),
                        "false" | "0" | "no" => Value::Bool(false),
                        _ => {
                            tracing::warn!(path, raw = %val, "enrich: bool coercion failed");
                            val.clone()
                        }
                    },
                )
            },
            Value::Bool,
        ),
        EnrichFieldType::ArrayJoin => {
            if let Value::Array(arr) = val {
                if arr.iter().all(|e| !e.is_object()) {
                    let joined = arr
                        .iter()
                        .map(scalar_to_string)
                        .collect::<Vec<_>>()
                        .join(array_join_sep);
                    Value::String(joined)
                } else {
                    val.clone()
                }
            } else {
                val.clone()
            }
        }
    }
}

/// Convert a scalar JSON value to its display string representation.
fn scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::from("null"),
        // Arrays and objects should not appear here (filtered by all_scalar check).
        Value::Array(_) | Value::Object(_) => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- flatten_fields ---

    #[test]
    fn flatten_fields_flat_object() {
        let v = json!({"ip": "198.51.100.1", "asn": 64496});
        let fields = flatten_fields("", &v);
        assert!(
            fields
                .iter()
                .any(|f| f.path == "ip" && f.type_tag == "string")
        );
        assert!(
            fields
                .iter()
                .any(|f| f.path == "asn" && f.type_tag == "number")
        );
    }

    #[test]
    fn flatten_fields_nested_object() {
        let v = json!({"mmdb": {"autonomous_system_number": 64496, "operational": {"host": "border1"}}});
        let fields = flatten_fields("", &v);
        // Object nodes appear
        assert!(
            fields
                .iter()
                .any(|f| f.path == "mmdb" && f.type_tag == "object")
        );
        assert!(
            fields
                .iter()
                .any(|f| f.path == "mmdb.operational" && f.type_tag == "object")
        );
        // Leaf nodes appear
        assert!(
            fields
                .iter()
                .any(|f| f.path == "mmdb.autonomous_system_number" && f.type_tag == "number")
        );
        assert!(
            fields
                .iter()
                .any(|f| f.path == "mmdb.operational.host" && f.type_tag == "string")
        );
    }

    #[test]
    fn flatten_fields_array_is_list() {
        let v = json!({"tags": ["a", "b"]});
        let fields = flatten_fields("", &v);
        assert!(
            fields
                .iter()
                .any(|f| f.path == "tags" && f.type_tag == "list")
        );
    }

    #[test]
    fn flatten_fields_null() {
        let v = json!({"x": null});
        let fields = flatten_fields("", &v);
        assert!(fields.iter().any(|f| f.path == "x" && f.type_tag == "null"));
    }

    // --- project_fields (new EnrichField API) ---

    fn ef(field: &str) -> EnrichField {
        EnrichField {
            field: field.to_owned(),
            output_name: None,
            field_type: EnrichFieldType::String,
        }
    }

    fn ef_named(field: &str, name: &str) -> EnrichField {
        EnrichField {
            field: field.to_owned(),
            output_name: Some(name.to_owned()),
            field_type: EnrichFieldType::String,
        }
    }

    fn ef_typed(field: &str, ft: EnrichFieldType) -> EnrichField {
        EnrichField {
            field: field.to_owned(),
            output_name: None,
            field_type: ft,
        }
    }

    #[test]
    fn project_fields_flat_exact_leaf() {
        let record = json!({"ip": "198.51.100.1", "asn": 64496, "extra": "drop"});
        let fields = vec![ef("ip"), ef("asn")];
        let out = project_fields(&record, &fields, ",");
        assert_eq!(out["ip"], json!("198.51.100.1"));
        assert_eq!(out["asn"], json!("64496")); // String coercion
        assert!(out.get("extra").is_none());
    }

    #[test]
    fn project_fields_output_name_rename() {
        let record = json!({"ip_address": "198.51.100.1", "mmdb": {"asn": 64496}});
        let fields = vec![
            ef_named("ip_address", "IPAddr"),
            ef_named("mmdb.asn", "ASN"),
        ];
        let out = project_fields(&record, &fields, ",");
        assert_eq!(out["IPAddr"], json!("198.51.100.1"));
        assert_eq!(out["ASN"], json!("64496")); // String coercion
        assert!(out.get("ip_address").is_none());
        assert!(out.get("mmdb.asn").is_none());
    }

    #[test]
    fn project_fields_integer_coercion() {
        let record = json!({"asn": 64496, "str_num": "64497"});
        let fields = vec![
            ef_typed("asn", EnrichFieldType::Integer),
            ef_typed("str_num", EnrichFieldType::Integer),
        ];
        let out = project_fields(&record, &fields, ",");
        assert_eq!(out["asn"], json!(64496));
        assert_eq!(out["str_num"], json!(64497));
    }

    #[test]
    fn project_fields_bool_coercion() {
        let record = json!({"active": true, "flag": "yes", "disabled": "false"});
        let fields = vec![
            ef_typed("active", EnrichFieldType::Bool),
            ef_typed("flag", EnrichFieldType::Bool),
            ef_typed("disabled", EnrichFieldType::Bool),
        ];
        let out = project_fields(&record, &fields, ",");
        assert_eq!(out["active"], json!(true));
        assert_eq!(out["flag"], json!(true));
        assert_eq!(out["disabled"], json!(false));
    }

    #[test]
    fn project_fields_auto_preserves_original_types() {
        let record = json!({"ip": "198.51.100.1", "asn": 64496, "active": true, "score": 1.5});
        let fields = vec![
            ef_typed("ip", EnrichFieldType::Auto),
            ef_typed("asn", EnrichFieldType::Auto),
            ef_typed("active", EnrichFieldType::Auto),
            ef_typed("score", EnrichFieldType::Auto),
        ];
        let out = project_fields(&record, &fields, ",");
        // Auto must not coerce — original JSON types preserved.
        assert_eq!(out["ip"], json!("198.51.100.1"));
        assert_eq!(out["asn"], json!(64496));
        assert_eq!(out["active"], json!(true));
        assert_eq!(out["score"], json!(1.5));
    }

    #[test]
    fn project_fields_array_join() {
        let record = json!({"tags": ["a", "b", "c"]});
        let fields = vec![ef_typed("tags", EnrichFieldType::ArrayJoin)];
        let out = project_fields(&record, &fields, ",");
        assert_eq!(out["tags"], json!("a,b,c"));
    }

    #[test]
    fn project_fields_array_of_objects_not_joined() {
        let record = json!({"items": [{"x": 1}, {"x": 2}]});
        let fields = vec![ef_typed("items", EnrichFieldType::ArrayJoin)];
        let out = project_fields(&record, &fields, ",");
        assert_eq!(out["items"], json!([{"x": 1}, {"x": 2}]));
    }

    #[test]
    fn project_fields_coercion_failure_keeps_raw() {
        let record = json!({"val": "not-a-number"});
        let fields = vec![ef_typed("val", EnrichFieldType::Integer)];
        let out = project_fields(&record, &fields, ",");
        // Raw value kept on failure.
        assert_eq!(out["val"], json!("not-a-number"));
    }

    #[test]
    fn project_fields_object_subtree_flat() {
        let record = json!({"ip": "198.51.100.1", "mmdb": {"asn": 64496, "operational": {"host": "border1"}}});
        let fields = vec![
            ef("ip"),
            EnrichField {
                field: "mmdb.operational".to_owned(),
                output_name: None,
                field_type: EnrichFieldType::String,
            },
        ];
        let out = project_fields(&record, &fields, ",");
        assert_eq!(out["ip"], json!("198.51.100.1"));
        assert_eq!(out["mmdb.operational.host"], json!("border1"));
        assert!(out.get("mmdb.asn").is_none());
    }

    /// Selecting a parent object + an individual child with `output_name` must not
    /// produce the original dot-notation key alongside the renamed key.
    #[test]
    fn project_fields_subtree_plus_individual_leaf_no_duplicate() {
        let record = json!({
            "ip": "198.51.100.1",
            "mmdb": {
                "asn": 64496,
                "operational": {"host": "border1", "role": "core"}
            }
        });
        // Parent subtree selected; one child also listed with output_name.
        let fields = vec![
            ef("ip"),
            EnrichField {
                field: "mmdb".to_owned(),
                output_name: None,
                field_type: EnrichFieldType::String,
            },
            ef_named("mmdb.asn", "ASN"),
        ];
        let out = project_fields(&record, &fields, ",");
        // Renamed key must appear.
        assert_eq!(out["ASN"], json!("64496"));
        // Original dot-notation key must NOT appear (no duplicate).
        assert!(out.get("mmdb.asn").is_none());
        // Other subtree leaves must still appear.
        assert_eq!(out["mmdb.operational.host"], json!("border1"));
        assert_eq!(out["mmdb.operational.role"], json!("core"));
    }
}
