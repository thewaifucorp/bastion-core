//! Metering: the one place a model call is admitted, traced, priced and
//! charged (BUP-02/03/04/05).
//!
//! [`CostMeter`] wraps a single provider call:
//!
//! 1. **Admission** ([`CostMeter::admit`], BEFORE the call): a metered call
//!    must have a price ([`Pricing::ensure_priced`]) and the day's money
//!    budget must not be spent. Subscription and local calls are never
//!    blocked by either — they cost no metered dollars.
//! 2. **Span**: one `chat {model}` client span per call, carrying the OTel
//!    GenAI usage attributes and the cost attributes
//!    (`<ns>.cost.usd`, `<ns>.cost.price_table`, `<ns>.cost.billing`,
//!    `<ns>.owner`; the namespace comes from [`Pricing::attribute_namespace`]).
//! 3. **Charge**: the SAME dollar figure written on the span is added to the
//!    daily budget, to the session's running total and to the caller's
//!    [`MeterScope`] (a turn, or a background job). Budget and span can
//!    therefore never disagree.
//!
//! [`MeteredProvider`] is the same meter shaped as a [`Provider`], so code
//! that only receives a `SharedProvider` (the persona router/runner, the
//! Cabinet, the Reflector, compaction) is metered without knowing it.

use std::sync::{Arc, Mutex};

use futures_util::StreamExt as _;
use opentelemetry::global::BoxedSpan;
use opentelemetry::trace::{Span as _, SpanKind, Tracer as _};
use opentelemetry::{global as otel_global, KeyValue};

use super::{CallCost, Pricing};
use crate::provider::{Provider, SharedProvider, StreamChunk};
use crate::session::SessionManager;
use crate::task::UsageAccum;
use crate::types::{
    BastionError, CallConfig, CostBasis, LlmResponse, Message, MessageContent, Role, TokenUsage,
    UsageBuckets,
};

/// Who a metered call is attributed to, and the running usage of that
/// attribution unit (one conversation turn, or one background job).
#[derive(Debug, Default)]
pub struct MeterScope {
    session_id: Option<String>,
    owner: Option<String>,
    usage: Mutex<UsageAccum>,
}

impl MeterScope {
    /// A conversation turn: calls are attributed to `owner` and folded into
    /// `session_id`'s running total.
    pub fn turn(session_id: impl Into<String>, owner: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            session_id: Some(session_id.into()),
            owner: Some(owner.into()),
            usage: Mutex::new(UsageAccum::default()),
        })
    }

    /// Work outside any session (the Reflector, a scheduled job).
    pub fn background(owner: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            session_id: None,
            owner,
            usage: Mutex::new(UsageAccum::default()),
        })
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    /// Usage accumulated in this scope so far.
    pub fn usage(&self) -> UsageAccum {
        *self.usage.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn add(&self, delta: &UsageAccum) {
        self.usage
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .merge_from(delta);
    }
}

/// Prices, traces and charges model calls. Cheap to build; share via `Arc`.
#[derive(Clone)]
pub struct CostMeter {
    pricing: Arc<Pricing>,
    ledger: Option<SessionManager>,
    daily_budget_usd: Option<f64>,
}

impl CostMeter {
    /// A meter that prices and traces calls but enforces no money budget
    /// and records nothing durable.
    pub fn new(pricing: Arc<Pricing>) -> Self {
        Self {
            pricing,
            ledger: None,
            daily_budget_usd: None,
        }
    }

    /// Record dollars and session totals in `ledger`; `daily_budget_usd`
    /// is the cap checked before every metered call.
    pub fn with_ledger(mut self, ledger: SessionManager, daily_budget_usd: f64) -> Self {
        self.ledger = Some(ledger);
        self.daily_budget_usd = Some(daily_budget_usd);
        self
    }

    pub fn pricing(&self) -> &Pricing {
        &self.pricing
    }

    /// Admission, run BEFORE a call to `provider`: a metered call needs a
    /// price for the model (BUP-02, [`BastionError::PriceUnknown`]) and an
    /// unspent daily budget ([`BastionError::BudgetExceeded`]).
    pub async fn admit(&self, provider: &dyn Provider) -> anyhow::Result<()> {
        let basis = provider.cost_basis();
        if !basis.is_metered() {
            return Ok(());
        }
        self.pricing
            .ensure_priced(basis, provider.reports_cost(), provider.model_name())?;
        if let (Some(ledger), Some(limit)) = (&self.ledger, self.daily_budget_usd) {
            if !ledger.check_budget(limit).await? {
                anyhow::bail!(BastionError::BudgetExceeded);
            }
        }
        Ok(())
    }

    /// Run an ALREADY ADMITTED `complete` call: span, call, price, charge.
    pub async fn call(
        &self,
        provider: &dyn Provider,
        scope: &MeterScope,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        self.instrument(provider, scope, provider.complete(messages, config))
            .await
    }

    /// Like [`CostMeter::call`] for `complete_cancellable`.
    pub async fn call_cancellable(
        &self,
        provider: &dyn Provider,
        scope: &MeterScope,
        messages: &[Message],
        config: &CallConfig,
        cancel: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<LlmResponse> {
        self.instrument(
            provider,
            scope,
            provider.complete_cancellable(messages, config, cancel),
        )
        .await
    }

    async fn instrument(
        &self,
        provider: &dyn Provider,
        scope: &MeterScope,
        call: impl std::future::Future<Output = anyhow::Result<LlmResponse>>,
    ) -> anyhow::Result<LlmResponse> {
        let name = provider.name();
        let model = provider.model_name().to_owned();
        let basis = provider.cost_basis();
        let mut span = self.start_span(name, &model, scope);
        match call.await {
            Ok(response) => {
                let finish = if response.tool_calls.is_some() {
                    "tool_calls"
                } else {
                    "stop"
                };
                span.set_attribute(KeyValue::new("gen_ai.response.finish_reasons", finish));
                // SECURITY: output content only on explicit opt-in (PII — T-05-05-01).
                if std::env::var("BASTION_OTEL_CONTENT_EVENTS").as_deref() == Ok("true") {
                    span.set_attribute(KeyValue::new(
                        "gen_ai.output.messages",
                        response.text.clone(),
                    ));
                }
                self.finish(&mut span, &model, basis, scope, &response.usage)
                    .await;
                span.end();
                Ok(response)
            }
            Err(e) => {
                // A fixed type, never the message: a provider error may echo
                // request/response content.
                span.set_attribute(KeyValue::new("error.type", "provider_error"));
                span.end();
                Err(e)
            }
        }
    }

    fn start_span(&self, system: &str, model: &str, scope: &MeterScope) -> BoxedSpan {
        let tracer = otel_global::tracer("bastion");
        let mut attrs = vec![
            KeyValue::new("gen_ai.operation.name", "chat"),
            KeyValue::new("gen_ai.system", system.to_owned()),
            KeyValue::new("gen_ai.request.model", model.to_owned()),
        ];
        if let Some(sid) = scope.session_id() {
            attrs.push(KeyValue::new("gen_ai.conversation.id", sid.to_owned()));
        }
        if let Some(owner) = scope.owner() {
            attrs.push(KeyValue::new(
                format!("{}.owner", self.pricing.attribute_namespace()),
                owner.to_owned(),
            ));
        }
        tracer
            .span_builder(format!("chat {model}"))
            .with_kind(SpanKind::Client)
            .with_attributes(attrs)
            .start(&tracer)
    }

    /// Price a finished call, write it on `span`, and charge it.
    async fn finish(
        &self,
        span: &mut BoxedSpan,
        requested_model: &str,
        basis: CostBasis,
        scope: &MeterScope,
        usage: &TokenUsage,
    ) -> CallCost {
        let cost = self.pricing.cost_of_call(basis, requested_model, usage);
        let buckets = usage.buckets();
        span.set_attributes(call_attributes(
            self.pricing.attribute_namespace(),
            usage.response_model.as_deref(),
            &buckets,
            &cost,
        ));
        if basis.is_metered() && cost.usd.is_none() {
            // Only reachable when a provider that promised a reported cost
            // did not send one for a model the table does not know.
            tracing::error!(
                event = "model_call_unpriced",
                model = %requested_model,
                response_model = usage.response_model.as_deref().unwrap_or(""),
                "a metered call finished without a price; its dollars are unknown"
            );
        }
        self.charge(scope, &UsageAccum::from_call(&buckets, &cost), &cost)
            .await;
        cost
    }

    async fn charge(&self, scope: &MeterScope, delta: &UsageAccum, cost: &CallCost) {
        scope.add(delta);
        let Some(ledger) = &self.ledger else {
            return;
        };
        if cost.basis.is_metered() {
            if let Some(usd) = cost.usd {
                if let Err(e) = ledger.update_budget(usd).await {
                    tracing::warn!(error = %e, "failed to update budget");
                }
            }
        }
        if let Some(sid) = scope.session_id() {
            if let Err(e) = ledger.record_session_usage(sid, delta).await {
                tracing::warn!(error = %e, "failed to record session usage");
            }
        }
    }

    /// BUP-03: tokens an external runtime (a harness on the operator's own
    /// login) reported for one turn or task. Emits one `chat {runtime_id}`
    /// span with `billing = subscription` and `cost.usd = 0`, and folds the
    /// tokens into `scope` and the session total. Never touches the money
    /// budget.
    pub async fn record_runtime_usage(
        &self,
        scope: &MeterScope,
        runtime_id: &str,
        input_tokens: u64,
        output_tokens: u64,
        coverage: bastion_agent_runtime::BudgetCoverage,
    ) {
        let mut span = self.start_span(runtime_id, runtime_id, scope);
        let cost = CallCost {
            basis: CostBasis::Subscription,
            usd: Some(0.0),
            price_table: self.pricing.table_version().to_owned(),
            source: super::CostSource::NotMetered,
        };
        let buckets = UsageBuckets {
            input: input_tokens,
            output: output_tokens,
            ..Default::default()
        };
        span.set_attributes(call_attributes(
            self.pricing.attribute_namespace(),
            None,
            &buckets,
            &cost,
        ));
        span.end();
        let delta = UsageAccum::from_runtime_usage(input_tokens, output_tokens, coverage);
        self.charge(scope, &delta, &cost).await;
    }
}

/// Span attributes of one priced call.
///
/// Token keys: `gen_ai.usage.input_tokens`/`output_tokens` are the OTel
/// totals (input includes cache reads/writes, output includes reasoning,
/// whatever convention the provider used); cache and reasoning counts use
/// the OTel GenAI keys Langfuse's OTel ingestion reads
/// (`gen_ai.usage.cache_read.input_tokens`,
/// `gen_ai.usage.cache_creation.input_tokens`,
/// `gen_ai.usage.reasoning.output_tokens`). The previous
/// `gen_ai.usage.cache_read_tokens`/`cache_write_tokens` keys are still
/// emitted for one release so existing dashboards keep working. All counts
/// are always emitted, zero included, so "measured zero" is distinguishable
/// from "not wired".
pub(crate) fn call_attributes(
    namespace: &str,
    response_model: Option<&str>,
    b: &UsageBuckets,
    cost: &CallCost,
) -> Vec<KeyValue> {
    let mut attrs = vec![
        KeyValue::new("gen_ai.usage.input_tokens", b.input_total() as i64),
        KeyValue::new("gen_ai.usage.output_tokens", b.output_total() as i64),
        KeyValue::new("gen_ai.usage.cache_read.input_tokens", b.cache_read as i64),
        KeyValue::new(
            "gen_ai.usage.cache_creation.input_tokens",
            b.cache_write as i64,
        ),
        KeyValue::new("gen_ai.usage.reasoning.output_tokens", b.reasoning as i64),
        // Deprecated keys, kept for one release.
        KeyValue::new("gen_ai.usage.cache_read_tokens", b.cache_read as i64),
        KeyValue::new("gen_ai.usage.cache_write_tokens", b.cache_write as i64),
        KeyValue::new(
            format!("{namespace}.cost.price_table"),
            cost.price_table.clone(),
        ),
        KeyValue::new(format!("{namespace}.cost.billing"), cost.basis.as_str()),
    ];
    if let Some(model) = response_model {
        attrs.push(KeyValue::new("gen_ai.response.model", model.to_owned()));
    }
    if let Some(usd) = cost.usd {
        attrs.push(KeyValue::new(format!("{namespace}.cost.usd"), usd));
    }
    attrs
}

/// A [`CostMeter`] shaped as a [`Provider`]: forwards to whatever provider
/// `target` currently holds (so a hot swap on the shared handle is seen),
/// admitting and metering every call under one [`MeterScope`].
///
/// `model_name()` is a snapshot taken when the wrapper was built (a
/// borrowed `&str` cannot be read through the async lock); every other
/// accessor, and all metering, reads the live provider.
pub struct MeteredProvider {
    target: SharedProvider,
    meter: Arc<CostMeter>,
    scope: Arc<MeterScope>,
    model: String,
    name: &'static str,
    context_limit: usize,
    json_schema: bool,
    basis: CostBasis,
    reports_cost: bool,
}

impl MeteredProvider {
    /// Wrap `target` into a new shared handle that meters every call.
    pub async fn wrap(
        target: SharedProvider,
        meter: Arc<CostMeter>,
        scope: Arc<MeterScope>,
    ) -> SharedProvider {
        let (model, name, context_limit, json_schema, basis, reports_cost) = {
            let p = target.read().await;
            (
                p.model_name().to_owned(),
                p.name(),
                p.context_limit(),
                p.supports_json_schema(),
                p.cost_basis(),
                p.reports_cost(),
            )
        };
        Arc::new(tokio::sync::RwLock::new(Box::new(MeteredProvider {
            target,
            meter,
            scope,
            model,
            name,
            context_limit,
            json_schema,
            basis,
            reports_cost,
        })))
    }
}

#[async_trait::async_trait]
impl Provider for MeteredProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        let p = self.target.read().await;
        self.meter.admit(&**p).await?;
        self.meter.call(&**p, &self.scope, messages, config).await
    }

    /// Routed through [`Provider::complete`] (same shape every concrete
    /// provider's own `complete_simple` uses) so the call is metered.
    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        let messages = [Message {
            role: Role::User,
            content: MessageContent::Text(prompt.to_owned()),
        }];
        let config = CallConfig {
            max_tokens: 2048,
            ..Default::default()
        };
        Ok(self.complete(&messages, &config).await?.text)
    }

    fn context_limit(&self) -> usize {
        self.target
            .try_read()
            .map(|p| p.context_limit())
            .unwrap_or(self.context_limit)
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn name(&self) -> &'static str {
        self.target
            .try_read()
            .map(|p| p.name())
            .unwrap_or(self.name)
    }

    fn supports_json_schema(&self) -> bool {
        self.target
            .try_read()
            .map(|p| p.supports_json_schema())
            .unwrap_or(self.json_schema)
    }

    fn cost_basis(&self) -> CostBasis {
        self.target
            .try_read()
            .map(|p| p.cost_basis())
            .unwrap_or(self.basis)
    }

    fn reports_cost(&self) -> bool {
        self.target
            .try_read()
            .map(|p| p.reports_cost())
            .unwrap_or(self.reports_cost)
    }

    async fn stream(
        &self,
        messages: &[Message],
        config: &CallConfig,
        cancel: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<
        std::pin::Pin<Box<dyn futures_util::Stream<Item = anyhow::Result<StreamChunk>> + Send>>,
    > {
        let p = self.target.read().await;
        self.meter.admit(&**p).await?;
        let model = p.model_name().to_owned();
        let basis = p.cost_basis();
        let mut span = self.meter.start_span(p.name(), &model, &self.scope);
        let inner = match p.stream(messages, config, cancel).await {
            Ok(s) => s,
            Err(e) => {
                span.set_attribute(KeyValue::new("error.type", "provider_error"));
                span.end();
                return Err(e);
            }
        };
        drop(p);
        let span = Arc::new(tokio::sync::Mutex::new(Some(span)));
        let meter = self.meter.clone();
        let scope = self.scope.clone();
        let metered = inner.then(move |item| {
            let meter = meter.clone();
            let scope = scope.clone();
            let span = span.clone();
            let model = model.clone();
            async move {
                if let Ok(StreamChunk::Usage(usage)) = &item {
                    if let Some(mut s) = span.lock().await.take() {
                        meter.finish(&mut s, &model, basis, &scope, usage).await;
                        s.end();
                    }
                }
                item
            }
        });
        Ok(Box::pin(metered))
    }

    async fn complete_cancellable(
        &self,
        messages: &[Message],
        config: &CallConfig,
        cancel: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<LlmResponse> {
        let p = self.target.read().await;
        self.meter.admit(&**p).await?;
        self.meter
            .call_cancellable(&**p, &self.scope, messages, config, cancel)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pricing::CostSource;

    fn attr<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a KeyValue> {
        attrs.iter().find(|kv| kv.key.as_str() == key)
    }

    #[test]
    fn call_attributes_carry_totals_buckets_and_cost() {
        let b = UsageBuckets {
            input: 600,
            output: 180,
            cache_read: 400,
            cache_write: 0,
            reasoning: 120,
        };
        let cost = CallCost {
            basis: CostBasis::Metered,
            usd: Some(0.0125),
            price_table: "langfuse@abc".into(),
            source: CostSource::Table,
        };
        let a = call_attributes("ns", Some("gpt-4o-2024-08-06"), &b, &cost);
        let v = |k: &str| attr(&a, k).map(|kv| kv.value.to_string());
        assert_eq!(v("gen_ai.usage.input_tokens").as_deref(), Some("1000"));
        assert_eq!(v("gen_ai.usage.output_tokens").as_deref(), Some("300"));
        assert_eq!(
            v("gen_ai.usage.cache_read.input_tokens").as_deref(),
            Some("400")
        );
        assert_eq!(
            v("gen_ai.usage.cache_creation.input_tokens").as_deref(),
            Some("0")
        );
        assert_eq!(
            v("gen_ai.usage.reasoning.output_tokens").as_deref(),
            Some("120")
        );
        assert_eq!(v("gen_ai.usage.cache_read_tokens").as_deref(), Some("400"));
        assert_eq!(v("gen_ai.usage.cache_write_tokens").as_deref(), Some("0"));
        assert_eq!(v("ns.cost.usd").as_deref(), Some("0.0125"));
        assert_eq!(v("ns.cost.price_table").as_deref(), Some("langfuse@abc"));
        assert_eq!(v("ns.cost.billing").as_deref(), Some("metered"));
        assert_eq!(
            v("gen_ai.response.model").as_deref(),
            Some("gpt-4o-2024-08-06")
        );
    }

    #[test]
    fn unknown_cost_omits_the_usd_attribute() {
        let cost = CallCost {
            basis: CostBasis::Metered,
            usd: None,
            price_table: "langfuse@abc".into(),
            source: CostSource::Unknown,
        };
        let a = call_attributes("ns", None, &UsageBuckets::default(), &cost);
        assert!(attr(&a, "ns.cost.usd").is_none());
        assert!(attr(&a, "gen_ai.response.model").is_none());
    }
}
