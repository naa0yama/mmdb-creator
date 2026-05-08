//! mmdb-creator — CLI tool for creating `MaxMind` `MMDB` databases.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod backup;
mod cache;
mod cli;
mod export;
mod import;
#[cfg(unix)]
mod scan;
mod telemetry;
mod validate;

use std::io::Write as _;

use anyhow::Context as _;
use clap::Parser as _;
use tracing_subscriber::filter::EnvFilter;
#[cfg(not(feature = "otel"))]
use tracing_subscriber::fmt;
#[cfg(feature = "otel")]
use tracing_subscriber::layer::SubscriberExt as _;
#[cfg(feature = "otel")]
use tracing_subscriber::util::SubscriberInitExt as _;

use mmdb_core::config::Config;

use crate::telemetry::metrics::Meters;

const APP_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (rev:", env!("GIT_HASH"), ")",);

// NOTEST(io): CLI entry point — stdin/stdout I/O and config loading
#[cfg_attr(coverage_nightly, coverage(off))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install TLS crypto provider for reqwest (required by rustls-no-provider feature).
    // Ignored if a provider is already installed (e.g., across tests).
    let _ = rustls::crypto::ring::default_provider().install_default();

    #[cfg(not(feature = "otel"))]
    {
        fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }

    #[cfg(feature = "otel")]
    let otel_providers = init_otel();

    let meters = Meters::default();

    let args = cli::Args::parse();

    if !args.config.exists() {
        let config_path = args.config.display().to_string();
        #[allow(clippy::print_stdout)]
        {
            print!("Config file '{config_path}' not found. Create it? (y/N): ");
        }
        std::io::stdout()
            .flush()
            .context("failed to flush stdout")?;
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("failed to read user input")?;
        if input.trim().eq_ignore_ascii_case("y") {
            std::fs::write(&args.config, Config::template())
                .with_context(|| format!("failed to create config {config_path}"))?;
            tracing::info!("created config template at {config_path}");
            return Ok(());
        }
        anyhow::bail!("config file not found: {config_path}");
    }

    let config = Config::load(&args.config)?;

    // Lightweight startup validation: check [[sheets]] files exist and header_row >= 1.
    // Skip for `validate` subcommand (it runs its own full validation).
    if !matches!(args.command, cli::Command::Validate { .. })
        && let Some(sheets) = &config.sheets
    {
        for (idx, sheet) in sheets.iter().enumerate() {
            if !sheet.filename.exists() {
                anyhow::bail!(
                    "sheets[{idx}].filename '{}' does not exist (run 'validate' for details)",
                    sheet.filename.display()
                );
            }
            if sheet.header_row < 1 {
                anyhow::bail!("sheets[{idx}].header_row must be >= 1 (run 'validate' for details)");
            }
        }
    }

    {
        let root = tracing::info_span!("main");
        let _guard = root.enter();

        let start = std::time::Instant::now();
        let command_name = match &args.command {
            cli::Command::Import { .. } => "import",
            cli::Command::Export { .. } => "export",
            cli::Command::Scan { .. } => "scan",
            cli::Command::Validate { .. } => "validate",
        };

        match args.command {
            cli::Command::Import {
                force,
                whois,
                xlsx,
                asn,
                ip,
            } => {
                import::run(&config, force, whois, xlsx, asn, ip).await?;
            }
            cli::Command::Export { out } => export::run(&config, &out).await?,
            cli::Command::Scan {
                force,
                enrich_only,
                ip,
            } => {
                #[cfg(unix)]
                scan::run(&config, force, enrich_only, ip.as_deref()).await?;
                #[cfg(not(unix))]
                {
                    let _ = (force, enrich_only, ip);
                    anyhow::bail!("scan subcommand requires Unix; use WSL2 on Windows");
                }
            }
            cli::Command::Validate { init_sheets } => {
                validate::run(&config, init_sheets)?;
            }
        }

        meters.record_run_duration(start.elapsed().as_secs_f64(), command_name);
    }

    #[cfg(feature = "otel")]
    shutdown_otel(otel_providers);

    Ok(())
}

/// Providers returned by `OTel` initialization for shutdown.
#[cfg(feature = "otel")]
type OtelProviders = (
    Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
    Option<opentelemetry_sdk::logs::SdkLoggerProvider>,
);

/// Build an `OTel` `Resource` for this process.
///
/// `OTEL_SERVICE_NAME` env var overrides the compiled-in package name.
// NOTEST(cfg): OTel resource construction — only meaningful with live OTLP endpoint
#[cfg(feature = "otel")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn build_resource() -> opentelemetry_sdk::Resource {
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| String::from(env!("CARGO_PKG_NAME")));
    opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name)
        .with_attributes([
            opentelemetry::KeyValue::new(
                opentelemetry_semantic_conventions::attribute::SERVICE_VERSION,
                env!("CARGO_PKG_VERSION"),
            ),
            opentelemetry::KeyValue::new(
                opentelemetry_semantic_conventions::attribute::SERVICE_INSTANCE_ID,
                gethostname::gethostname().to_string_lossy().into_owned(),
            ),
            opentelemetry::KeyValue::new(
                opentelemetry_semantic_conventions::attribute::VCS_REF_HEAD_REVISION,
                env!("GIT_HASH"),
            ),
        ])
        .build()
}

// NOTEST(cfg): OTel init requires OTLP endpoint — covered by integration trace tests
/// Initialize `OTel` tracing, logging, and metrics providers.
#[cfg(feature = "otel")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn init_otel() -> OtelProviders {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,opentelemetry=off"));
    let fmt_layer = tracing_subscriber::fmt::layer();

    let (otel_trace_layer, tp, mp, lp, otel_log_layer) =
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .filter(|ep| !ep.is_empty())
            .and_then(|_| {
                let resource = build_resource();

                // --- Traces (batch: non-blocking, suitable for production) ---
                let span_exporter = opentelemetry_otlp::SpanExporter::builder()
                    .with_http()
                    .build()
                    .ok()?;
                let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(span_exporter)
                    .build();
                opentelemetry::global::set_text_map_propagator(
                    opentelemetry_sdk::propagation::TraceContextPropagator::new(),
                );
                opentelemetry::global::set_tracer_provider(tracer_provider.clone());
                let tracer = opentelemetry::trace::TracerProvider::tracer(
                    &tracer_provider,
                    env!("CARGO_PKG_NAME"),
                );
                let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);

                // --- Logs (batch: non-blocking) ---
                let log_exporter = opentelemetry_otlp::LogExporter::builder()
                    .with_http()
                    .build()
                    .ok()?;
                let logger_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(log_exporter)
                    .build();
                let log_layer =
                    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                        &logger_provider,
                    );

                // --- Metrics (PeriodicReader: exports every 5 s) ---
                let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
                    .with_http()
                    .build()
                    .ok()?;
                let metric_reader =
                    opentelemetry_sdk::metrics::PeriodicReader::builder(metric_exporter)
                        .with_interval(std::time::Duration::from_secs(5))
                        .build();
                let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                    .with_resource(resource)
                    .with_reader(metric_reader)
                    .build();
                opentelemetry::global::set_meter_provider(meter_provider.clone());

                Some((
                    Some(trace_layer),
                    Some(tracer_provider),
                    Some(meter_provider),
                    Some(logger_provider),
                    Some(log_layer),
                ))
            })
            .unwrap_or((None, None, None, None, None));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_trace_layer)
        .with(otel_log_layer)
        .init();

    (tp, mp, lp)
}

// NOTEST(cfg): OTel shutdown requires live providers — covered by integration trace tests
/// Shut down `OTel` providers in reverse initialization order.
#[cfg(feature = "otel")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn shutdown_otel((tracer_provider, meter_provider, logger_provider): OtelProviders) {
    if let Some(provider) = tracer_provider
        && let Err(e) = provider.shutdown()
    {
        tracing::warn!("failed to shutdown OTel tracer provider: {e}");
    }
    if let Some(provider) = meter_provider {
        if let Err(e) = provider.force_flush() {
            tracing::warn!("failed to flush OTel meter provider: {e}");
        }
        if let Err(e) = provider.shutdown() {
            tracing::warn!("failed to shutdown OTel meter provider: {e}");
        }
    }
    if let Some(provider) = logger_provider
        && let Err(e) = provider.shutdown()
    {
        tracing::warn!("failed to shutdown OTel logger provider: {e}");
    }
}
