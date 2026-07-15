//! Component 6 (`docs/revamp/C3-m5-second-consumer-design.md`
//! §"Componentes"): "OTel neutro correlacionável" — the kernel emits its own
//! generic GenAI spans (`gen_ai.*` attributes, SEAM #4) with zero knowledge
//! of the host's business object; the HOST correlates a span back to its own
//! object using only public data it already has (the owner-scoped session
//! id from `SessionManager::load_most_recent_id_for`, a public
//! `bastion_runtime::session::SessionManager` method). The Core never learns
//! about "tickets"/"cases"/whatever the host calls its objects.
//!
//! A real host would export to OTLP/stdout; this in-process capturing
//! exporter stands in for that so the example can assert on what the kernel
//! emitted without depending on parsing stdout or standing up a collector.

use std::sync::{Arc, Mutex};

use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};

/// Captures every exported span in-process.
#[derive(Debug, Clone, Default)]
pub struct CapturingExporter {
    spans: Arc<Mutex<Vec<SpanData>>>,
}

impl CapturingExporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// All spans exported so far (`SimpleSpanProcessor` exports synchronously
    /// at `Span::end()`, so this is up to date the instant the producing
    /// call — e.g. `AgentLoop::run_turn_for` — returns).
    pub fn snapshot(&self) -> Vec<SpanData> {
        self.spans
            .lock()
            .expect("CapturingExporter mutex poisoned")
            .clone()
    }
}

impl SpanExporter for CapturingExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.spans
            .lock()
            .expect("CapturingExporter mutex poisoned")
            .extend(batch);
        Ok(())
    }
}

/// Initializes a real OTel SDK `TracerProvider` wired to `exporter` via a
/// `SimpleSpanProcessor` (synchronous — no batching delay, so assertions
/// right after a turn completes already see its spans).
///
/// MUST run before `AgentLoop::new()` — otherwise spans created inside the
/// kernel are silently dropped by a no-op tracer (the same PITFALL 6
/// `src/main.rs`'s `init_otel_provider` documents for the real app).
pub fn init_otel(exporter: CapturingExporter) -> SdkTracerProvider {
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    opentelemetry::global::set_tracer_provider(provider.clone());
    provider
}
