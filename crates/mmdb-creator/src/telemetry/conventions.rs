//! mmdb_creator-prefixed semantic conventions for app-specific telemetry.
//!
//! Mirrors the layout of `opentelemetry_semantic_conventions::{metric,
//! attribute}` to provide a single source of truth for `mmdb_creator.*` names
//! across all signals (metrics today, tracing/logs in the future).
//! Use these constants instead of string literals to avoid typos and drift.

pub mod metric {
    pub const RUN_DURATION: &str = "mmdb_creator.run.duration";
    pub const IMPORT_DURATION: &str = "mmdb_creator.import.duration";
    pub const EXPORT_DURATION: &str = "mmdb_creator.export.duration";
    pub const SCAN_DURATION: &str = "mmdb_creator.scan.duration";
}

pub mod attribute {
    pub const COMMAND: &str = "mmdb_creator.command";
    #[allow(dead_code)]
    pub const DATA_SOURCE: &str = "mmdb_creator.data_source";
}
