//! Application metric instruments.
//!
//! Create a [`Meters`] instance once via [`Meters::default`] after the global
//! `MeterProvider` has been initialized, then pass it by shared reference to
//! every function that records measurements.

// ---------------------------------------------------------------------------
// OTel implementation (feature = "otel")
// ---------------------------------------------------------------------------

#[cfg(feature = "process-metrics")]
mod process;

#[cfg(feature = "otel")]
use crate::telemetry::conventions::{attribute as app_attr, metric as app_metric};
#[cfg(feature = "otel")]
use opentelemetry::metrics::Histogram;

/// Collected `OTel` metric instruments for this application.
///
/// All instruments are created once and reused — do not construct per-request.
/// The `_process` field keeps observable process metric callbacks registered
/// for the lifetime of this struct (requires the `process-metrics` feature).
#[cfg(feature = "otel")]
pub struct Meters {
    run_duration: Histogram<f64>,
    #[allow(dead_code)]
    import_duration: Histogram<f64>,
    #[allow(dead_code)]
    export_duration: Histogram<f64>,
    #[allow(dead_code)]
    scan_duration: Histogram<f64>,
    #[cfg(all(feature = "process-metrics", not(miri)))]
    _process: process::ProcessMetricHandles,
}

#[cfg(feature = "otel")]
impl std::fmt::Debug for Meters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Meters").finish_non_exhaustive()
    }
}

#[cfg(feature = "otel")]
impl Default for Meters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "otel")]
impl Meters {
    /// Create all application instruments from the global `MeterProvider`.
    ///
    /// Call exactly once after `opentelemetry::global::set_meter_provider` has
    /// been called. When the `process-metrics` feature is enabled (default),
    /// process metric observable callbacks are also registered here.
    // NOTEST(cfg): requires a global MeterProvider to be initialized — covered only in main()
    #[must_use]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new() -> Self {
        let meter = opentelemetry::global::meter(env!("CARGO_PKG_NAME"));

        Self {
            run_duration: meter
                .f64_histogram(app_metric::RUN_DURATION)
                .with_unit("s")
                .with_description("End-to-end command execution latency")
                .build(),
            import_duration: meter
                .f64_histogram(app_metric::IMPORT_DURATION)
                .with_unit("s")
                .with_description("Import subcommand execution latency")
                .build(),
            export_duration: meter
                .f64_histogram(app_metric::EXPORT_DURATION)
                .with_unit("s")
                .with_description("Export subcommand execution latency")
                .build(),
            scan_duration: meter
                .f64_histogram(app_metric::SCAN_DURATION)
                .with_unit("s")
                .with_description("Scan subcommand execution latency")
                .build(),
            #[cfg(all(feature = "process-metrics", not(miri)))]
            _process: process::ProcessMetricHandles::register(&meter),
        }
    }

    /// Record end-to-end command execution latency.
    ///
    /// `command` should be one of `"import"`, `"export"`, or `"scan"`.
    pub fn record_run_duration(&self, duration_s: f64, command: &str) {
        self.run_duration.record(
            duration_s,
            &[opentelemetry::KeyValue::new(
                app_attr::COMMAND,
                command.to_owned(),
            )],
        );
    }

    /// Record import subcommand execution latency with data source attribution.
    ///
    /// `source` should be one of `"whois"` or `"xlsx"`.
    #[allow(dead_code)]
    pub fn record_import_duration(&self, duration_s: f64, source: &str) {
        self.import_duration.record(
            duration_s,
            &[opentelemetry::KeyValue::new(
                app_attr::DATA_SOURCE,
                source.to_owned(),
            )],
        );
    }

    /// Record export subcommand execution latency.
    #[allow(dead_code)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn record_export_duration(&self, duration_s: f64) {
        self.export_duration.record(duration_s, &[]);
    }

    /// Record scan subcommand execution latency.
    #[allow(dead_code)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn record_scan_duration(&self, duration_s: f64) {
        self.scan_duration.record(duration_s, &[]);
    }
}

// ---------------------------------------------------------------------------
// No-op stub (feature != "otel")
// ---------------------------------------------------------------------------

/// No-op metric instruments used when the `otel` feature is disabled.
#[cfg(not(feature = "otel"))]
#[derive(Debug, Default)]
pub struct Meters;

#[cfg(not(feature = "otel"))]
impl Meters {
    /// Record end-to-end command execution latency (no-op).
    pub fn record_run_duration(&self, _duration_s: f64, _command: &str) {}
    /// Record import subcommand execution latency (no-op).
    #[allow(dead_code)]
    pub fn record_import_duration(&self, _duration_s: f64, _source: &str) {}
    /// Record export subcommand execution latency (no-op).
    #[allow(dead_code)]
    pub fn record_export_duration(&self, _duration_s: f64) {}
    /// Record scan subcommand execution latency (no-op).
    #[allow(dead_code)]
    pub fn record_scan_duration(&self, _duration_s: f64) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "otel"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use crate::telemetry::conventions::{attribute as app_attr, metric as app_metric};
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter, SdkMeterProvider,
        data::{AggregatedMetrics, MetricData},
    };

    fn test_provider() -> (SdkMeterProvider, InMemoryMetricExporter) {
        let exporter = InMemoryMetricExporter::default();
        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        (provider, exporter)
    }

    fn find_metric<'a>(
        metrics: &'a [opentelemetry_sdk::metrics::data::ResourceMetrics],
        name: &str,
    ) -> Option<&'a opentelemetry_sdk::metrics::data::Metric> {
        metrics
            .iter()
            .flat_map(opentelemetry_sdk::metrics::data::ResourceMetrics::scope_metrics)
            .flat_map(opentelemetry_sdk::metrics::data::ScopeMetrics::metrics)
            .find(|m| m.name() == name)
    }

    #[test]
    fn run_duration_histogram_records_with_command_attribute() {
        use opentelemetry::KeyValue;

        let (provider, exporter) = test_provider();
        let meter = provider.meter("test");

        let histogram = meter
            .f64_histogram(app_metric::RUN_DURATION)
            .with_unit("s")
            .with_description("End-to-end command execution latency")
            .build();

        histogram.record(0.5, &[KeyValue::new(app_attr::COMMAND, "import")]);
        histogram.record(1.0, &[KeyValue::new(app_attr::COMMAND, "export")]);

        provider.force_flush().expect("flush failed");

        let metrics = exporter.get_finished_metrics().expect("no data");
        let metric = find_metric(&metrics, app_metric::RUN_DURATION)
            .expect("mmdb_creator.run.duration not found");

        let count = match metric.data() {
            AggregatedMetrics::F64(MetricData::Histogram(hist)) => hist
                .data_points()
                .map(opentelemetry_sdk::metrics::data::HistogramDataPoint::count)
                .sum::<u64>(),
            other => panic!("unexpected metric type: {other:?}"),
        };
        assert_eq!(count, 2);

        provider.shutdown().unwrap();
    }

    #[test]
    fn import_duration_histogram_records_with_source_attribute() {
        use opentelemetry::KeyValue;

        let (provider, exporter) = test_provider();
        let meter = provider.meter("test");

        let histogram = meter
            .f64_histogram(app_metric::IMPORT_DURATION)
            .with_unit("s")
            .with_description("Import subcommand execution latency")
            .build();

        histogram.record(2.0, &[KeyValue::new(app_attr::DATA_SOURCE, "whois")]);
        histogram.record(0.3, &[KeyValue::new(app_attr::DATA_SOURCE, "xlsx")]);

        provider.force_flush().expect("flush failed");

        let metrics = exporter.get_finished_metrics().expect("no data");
        let metric = find_metric(&metrics, app_metric::IMPORT_DURATION)
            .expect("mmdb_creator.import.duration not found");

        let count = match metric.data() {
            AggregatedMetrics::F64(MetricData::Histogram(hist)) => hist
                .data_points()
                .map(opentelemetry_sdk::metrics::data::HistogramDataPoint::count)
                .sum::<u64>(),
            other => panic!("unexpected metric type: {other:?}"),
        };
        assert_eq!(count, 2);

        provider.shutdown().unwrap();
    }
}
