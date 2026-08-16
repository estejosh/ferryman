//! OTLP trace export: spans from the agent loop, exported to an OpenTelemetry
//! collector so a fleet of agents can be observed from one place.
//!
//! This is the observability layer for bolting Ferryman onto an orchestrator
//! (hone) that runs a collector. The ledger answers *what happened*; these
//! spans answer *how long each phase took* - claim, run, submit, review - with
//! the task and engine attached.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

/// Install an OTLP tracer and tracing subscriber when an endpoint is set.
///
/// Looks at `FERRYMAN_OTLP_ENDPOINT`, then `OTEL_EXPORTER_OTLP_ENDPOINT`. With
/// no endpoint this is a no-op, so an agent without a collector runs exactly as
/// it always did. A collector that cannot be reached must never stop the agent.
pub fn init() {
    let endpoint = match std::env::var("FERRYMAN_OTLP_ENDPOINT")
        .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT"))
    {
        Ok(endpoint) if !endpoint.is_empty() => endpoint,
        _ => return,
    };

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
    {
        Ok(exporter) => exporter,
        Err(_) => return,
    };
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("ferryman");
    // Register globally so the batch exporter flushes at exit; the provider must
    // outlive the tracer, and this keeps it alive for the process lifetime.
    opentelemetry::global::set_tracer_provider(provider);

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();
}
