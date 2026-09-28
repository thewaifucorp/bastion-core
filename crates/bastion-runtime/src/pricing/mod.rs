//! Model pricing: the dollars a metered model call costs (BUP-01/02/06).
//!
//! Bastion checks its money budgets (`daily_budget_usd`, a task's
//! `max_cost_usd`, the Reflector's `budget_usd`) BEFORE it calls a model, so
//! the kernel needs prices at run time, offline, with no backend. They come
//! from one place:
//!
//! - **The packaged table** — an unmodified copy of Langfuse's
//!   `default-model-prices.json` (MIT), vendored under
//!   `crates/bastion-runtime/pricing/` with its license notice and the
//!   upstream commit it was taken from (`upstream.json`). It is embedded in
//!   the binary with `include_str!` and parsed once. It is refreshed by a
//!   scheduled job that opens a pull request (`scripts/update-model-prices.sh`),
//!   never downloaded at run time.
//! - **An operator override** — a file in the SAME format, loaded from a
//!   path the host configures. Its entries are matched BEFORE the packaged
//!   table, and a price that came from it is reported with the table
//!   version suffixed `+override`.
//!
//! No price lives in Rust code. Resolution follows the table's own
//! semantics: the model actually used (the response's model when the
//! provider names one, else the requested model) is matched against each
//! entry's `matchPattern`; the entry's non-default pricing tiers are tried
//! by ascending `priority` (a tier applies when all its conditions hold, an
//! unknown input makes a condition false), falling back to the default
//! tier; each disjoint usage bucket ([`UsageBuckets`]) is priced by the
//! first price key present for it.
//!
//! A model with no price is [`PriceOutcome::Unknown`], never `0`. What a
//! caller does with that is policy: the agent loop refuses to START a
//! metered call it cannot price ([`Pricing::ensure_priced`], BUP-02); a
//! call on a subscription or a local model is never metered and costs `0`
//! by definition ([`CostBasis`]).

pub mod meter;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;

use crate::types::{BastionError, CostBasis, TokenUsage, UsageBuckets};

pub use meter::{CostMeter, MeterScope, MeteredProvider};

/// The packaged table, vendored unmodified.
const BUNDLED_TABLE: &str = include_str!("../../pricing/langfuse-model-prices.json");
/// Where the packaged table came from; its `version` field names it.
const BUNDLED_UPSTREAM: &str = include_str!("../../pricing/upstream.json");

/// `price_table` value for a call whose dollars the provider itself
/// reported (e.g. OpenRouter's `usage.cost`) — no table was consulted.
pub const PROVIDER_REPORTED: &str = "provider-reported";

/// Suffix appended to the table version when an override entry priced the call.
const OVERRIDE_SUFFIX: &str = "+override";

/// Namespace of the cost telemetry attributes (`<ns>.cost.usd`, …) when the
/// host sets none. A host that reports into a platform with its own
/// attribute namespace sets it with [`Pricing::with_attribute_namespace`].
const DEFAULT_ATTRIBUTE_NAMESPACE: &str = "bastion";

/// Why a price table could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PricingError {
    /// The override file could not be read.
    #[error("reading pricing override file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The override file is not a valid price table (same format as the
    /// packaged Langfuse table).
    #[error("pricing override file {path} is invalid: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

// ---------------------------------------------------------------------------
// Table format (Langfuse `default-model-prices.json`)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawModel {
    model_name: String,
    match_pattern: String,
    #[serde(default)]
    pricing_tiers: Vec<RawTier>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTier {
    #[serde(default)]
    name: String,
    #[serde(default)]
    is_default: bool,
    #[serde(default)]
    priority: i64,
    #[serde(default)]
    conditions: Vec<serde_json::Value>,
    #[serde(default)]
    prices: HashMap<String, f64>,
}

#[derive(Deserialize)]
struct RawUpstream {
    version: String,
}

/// Which observation attributes a `source` condition reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttributeSource {
    ModelParameters,
    Metadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
}

impl Comparison {
    fn parse(op: &str) -> Option<Self> {
        Some(match op {
            "gt" => Comparison::Gt,
            "gte" => Comparison::Gte,
            "lt" => Comparison::Lt,
            "lte" => Comparison::Lte,
            "eq" => Comparison::Eq,
            "neq" => Comparison::Neq,
            _ => return None,
        })
    }

    fn holds(self, lhs: f64, rhs: f64) -> bool {
        match self {
            Comparison::Gt => lhs > rhs,
            Comparison::Gte => lhs >= rhs,
            Comparison::Lt => lhs < rhs,
            Comparison::Lte => lhs <= rhs,
            Comparison::Eq => lhs == rhs,
            Comparison::Neq => lhs != rhs,
        }
    }
}

/// One tier condition, mirroring Langfuse's matcher
/// (`packages/shared/src/server/pricing-tiers/matcher.ts`).
#[derive(Debug, Clone)]
enum Condition {
    /// `{source, key, operator: "in", values}` — the attribute must be
    /// present and equal to one of `values`.
    Attribute {
        source: AttributeSource,
        key: String,
        values: Vec<serde_json::Value>,
    },
    /// `{usageDetailPattern, operator, value, caseSensitive}` — the sum of
    /// every usage detail whose key matches the pattern is compared with
    /// `value`.
    Usage {
        pattern: Regex,
        comparison: Comparison,
        value: f64,
    },
    /// A condition shape or operator this matcher does not know: never holds.
    Never,
}

impl Condition {
    fn parse(raw: &serde_json::Value) -> Result<Self, String> {
        if let Some(source) = raw.get("source").and_then(|v| v.as_str()) {
            let source = match source {
                "model_parameters" => AttributeSource::ModelParameters,
                "metadata" => AttributeSource::Metadata,
                _ => return Ok(Condition::Never),
            };
            if raw.get("operator").and_then(|v| v.as_str()) != Some("in") {
                return Ok(Condition::Never);
            }
            let key = raw
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("condition with `source` has no `key`")?
                .to_owned();
            let values = raw
                .get("values")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            return Ok(Condition::Attribute {
                source,
                key,
                values,
            });
        }
        if let Some(pattern) = raw.get("usageDetailPattern").and_then(|v| v.as_str()) {
            let Some(comparison) = raw
                .get("operator")
                .and_then(|v| v.as_str())
                .and_then(Comparison::parse)
            else {
                return Ok(Condition::Never);
            };
            let Some(value) = raw.get("value").and_then(|v| v.as_f64()) else {
                return Ok(Condition::Never);
            };
            let case_sensitive = raw
                .get("caseSensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let source = if case_sensitive {
                pattern.to_owned()
            } else {
                format!("(?i){pattern}")
            };
            let pattern = Regex::new(&source)
                .map_err(|e| format!("usageDetailPattern `{pattern}` does not compile: {e}"))?;
            return Ok(Condition::Usage {
                pattern,
                comparison,
                value,
            });
        }
        Ok(Condition::Never)
    }

    fn holds(&self, usage: &[(&str, u64)], attributes: &TierAttributes) -> bool {
        match self {
            Condition::Attribute {
                source,
                key,
                values,
            } => {
                let map = match source {
                    AttributeSource::ModelParameters => &attributes.model_parameters,
                    AttributeSource::Metadata => &attributes.metadata,
                };
                map.get(key).is_some_and(|v| values.contains(v))
            }
            Condition::Usage {
                pattern,
                comparison,
                value,
            } => {
                let sum: u64 = usage
                    .iter()
                    .filter(|(k, _)| pattern.is_match(k))
                    .map(|(_, n)| *n)
                    .sum();
                comparison.holds(sum as f64, *value)
            }
            Condition::Never => false,
        }
    }
}

#[derive(Debug, Clone)]
struct Tier {
    name: String,
    conditions: Vec<Condition>,
    prices: HashMap<String, f64>,
}

impl Tier {
    /// Langfuse: a non-default tier with no conditions never matches; all
    /// conditions must hold (AND).
    fn applies(&self, usage: &[(&str, u64)], attributes: &TierAttributes) -> bool {
        !self.conditions.is_empty() && self.conditions.iter().all(|c| c.holds(usage, attributes))
    }

    fn price_of(&self, keys: &[&str]) -> Option<f64> {
        keys.iter().find_map(|k| self.prices.get(*k).copied())
    }

    /// Dollars for `b`, or `None` when the tier has no input or no output
    /// price (it cannot price a chat call).
    fn cost(&self, b: &UsageBuckets) -> Option<f64> {
        let input = self.price_of(&["input", "input_tokens"])?;
        let output = self.price_of(&["output", "output_tokens"])?;
        let cache_read = self
            .price_of(&[
                "input_cache_read",
                "input_cached_tokens",
                "cache_read_input_tokens",
            ])
            .unwrap_or(input);
        let cache_write = self
            .price_of(&[
                "input_cache_creation",
                "cache_creation_input_tokens",
                "input_cache_write_tokens",
                "cache_write_tokens",
            ])
            .unwrap_or(input);
        let reasoning = self
            .price_of(&[
                "output_reasoning",
                "output_reasoning_tokens",
                "reasoning_tokens",
            ])
            .unwrap_or(output);
        Some(
            b.input as f64 * input
                + b.output as f64 * output
                + b.cache_read as f64 * cache_read
                + b.cache_write as f64 * cache_write
                + b.reasoning as f64 * reasoning,
        )
    }
}

#[derive(Debug, Clone)]
struct ModelEntry {
    name: String,
    pattern: Regex,
    /// Non-default tiers, ascending `priority`.
    tiers: Vec<Tier>,
    default_tier: Option<Tier>,
}

impl ModelEntry {
    fn tier_for(&self, usage: &[(&str, u64)], attributes: &TierAttributes) -> Option<&Tier> {
        self.tiers
            .iter()
            .find(|t| t.applies(usage, attributes))
            .or(self.default_tier.as_ref())
    }
}

/// A parsed price table (packaged or override).
#[derive(Debug, Clone)]
struct PriceTable {
    models: Vec<ModelEntry>,
}

impl PriceTable {
    fn parse(json: &str) -> Result<Self, String> {
        let raw: Vec<RawModel> = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let mut models = Vec::with_capacity(raw.len());
        for m in raw {
            let pattern = Regex::new(&m.match_pattern)
                .map_err(|e| format!("matchPattern of `{}` does not compile: {e}", m.model_name))?;
            let mut tiers = Vec::new();
            let mut default_tier = None;
            for t in m.pricing_tiers {
                let conditions = t
                    .conditions
                    .iter()
                    .map(Condition::parse)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("`{}` tier `{}`: {e}", m.model_name, t.name))?;
                let tier = Tier {
                    name: t.name,
                    conditions,
                    prices: t.prices,
                };
                if t.is_default {
                    default_tier.get_or_insert(tier);
                } else {
                    tiers.push((t.priority, tier));
                }
            }
            tiers.sort_by_key(|(priority, _)| *priority);
            models.push(ModelEntry {
                name: m.model_name,
                pattern,
                tiers: tiers.into_iter().map(|(_, t)| t).collect(),
                default_tier,
            });
        }
        Ok(PriceTable { models })
    }

    fn find(&self, model: &str) -> Option<&ModelEntry> {
        self.models.iter().find(|m| m.pattern.is_match(model))
    }
}

struct Bundled {
    table: PriceTable,
    version: String,
}

/// The packaged table, parsed once. A defect in the embedded data (guarded
/// by this module's tests) yields an EMPTY table rather than a panic: every
/// metered call then fails closed with [`BastionError::PriceUnknown`].
fn bundled() -> &'static Bundled {
    static BUNDLED: OnceLock<Bundled> = OnceLock::new();
    BUNDLED.get_or_init(|| {
        let version = serde_json::from_str::<RawUpstream>(BUNDLED_UPSTREAM)
            .map(|u| u.version)
            .unwrap_or_else(|e| {
                tracing::error!(event = "price_table_upstream_invalid", error = %e);
                "unknown".to_owned()
            });
        let table = PriceTable::parse(BUNDLED_TABLE).unwrap_or_else(|e| {
            tracing::error!(event = "price_table_invalid", error = %e);
            PriceTable { models: Vec::new() }
        });
        Bundled { table, version }
    })
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Observation attributes a tier condition may read. Bastion sends no
/// `service_tier`/`speed` model parameters today, so this is empty on the
/// agent loop's path and the default (or a usage-conditioned) tier applies.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TierAttributes {
    pub model_parameters: BTreeMap<String, serde_json::Value>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// The price of one call's usage.
#[derive(Debug, Clone, PartialEq)]
pub enum PriceOutcome {
    /// Priced from a table entry.
    Priced {
        usd: f64,
        /// `langfuse@<commit>` or `langfuse@<commit>+override`.
        table_version: String,
        /// The `modelName` of the entry that matched.
        model: String,
        /// The pricing tier that applied.
        tier: String,
    },
    /// No entry (override or packaged) prices this model.
    Unknown,
}

/// Where a call's dollars came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostSource {
    /// The provider reported the real cost (`TokenUsage::actual_cost_usd`).
    ProviderReported,
    /// Priced from the table (packaged or override).
    Table,
    /// Subscription or local: no metered dollars.
    NotMetered,
    /// Metered, but nothing could price it.
    Unknown,
}

/// The cost of one model call, as recorded on its span and in the budget —
/// the same number in both places (BUP-05).
#[derive(Debug, Clone, PartialEq)]
pub struct CallCost {
    pub basis: CostBasis,
    /// Dollars; `None` only for a metered call nothing could price.
    pub usd: Option<f64>,
    /// `langfuse@<commit>`, `…+override`, or [`PROVIDER_REPORTED`].
    pub price_table: String,
    pub source: CostSource,
}

impl CallCost {
    /// Fidelity of `usd` as a task/turn usage figure: a provider-reported
    /// cost and a not-metered `0` are exact (`Reported`), a table price is
    /// `Estimated`, an unpriced call is `Unknown`.
    pub fn coverage(&self) -> bastion_agent_runtime::BudgetCoverage {
        use bastion_agent_runtime::BudgetCoverage;
        match self.source {
            CostSource::ProviderReported | CostSource::NotMetered => BudgetCoverage::Reported,
            CostSource::Table => BudgetCoverage::Estimated,
            CostSource::Unknown => BudgetCoverage::Unknown,
        }
    }
}

/// Model pricing: the packaged table plus an optional operator override.
///
/// Cheap to share (`Arc<Pricing>`); immutable once built.
#[derive(Debug, Clone)]
pub struct Pricing {
    overrides: Option<PriceTable>,
    override_path: Option<PathBuf>,
    override_hint: Option<String>,
    attribute_namespace: String,
}

impl Default for Pricing {
    fn default() -> Self {
        Self::bundled()
    }
}

impl Pricing {
    /// The packaged table only.
    pub fn bundled() -> Self {
        Self {
            overrides: None,
            override_path: None,
            override_hint: None,
            attribute_namespace: DEFAULT_ATTRIBUTE_NAMESPACE.to_owned(),
        }
    }

    /// The packaged table plus the override file at `path` (same format),
    /// whose entries are matched first. A missing or invalid file is an
    /// error: an operator who configured an override expects it to apply.
    pub fn with_override_file(mut self, path: impl Into<PathBuf>) -> Result<Self, PricingError> {
        let path = path.into();
        let json = std::fs::read_to_string(&path).map_err(|source| PricingError::Read {
            path: path.clone(),
            source,
        })?;
        self = self.with_override_json(&json, path)?;
        Ok(self)
    }

    /// Like [`Pricing::with_override_file`], from an in-memory document;
    /// `origin` is the path reported in errors and hints.
    pub fn with_override_json(
        mut self,
        json: &str,
        origin: impl Into<PathBuf>,
    ) -> Result<Self, PricingError> {
        let origin = origin.into();
        let table = PriceTable::parse(json).map_err(|reason| PricingError::Invalid {
            path: origin.clone(),
            reason,
        })?;
        self.overrides = Some(table);
        self.override_path = Some(origin);
        Ok(self)
    }

    /// Text telling an operator how to add a price, used in
    /// [`BastionError::PriceUnknown`] (e.g. the host's config key). Without
    /// it the hint names the override file, or says none is configured.
    pub fn with_override_hint(mut self, hint: impl Into<String>) -> Self {
        self.override_hint = Some(hint.into());
        self
    }

    /// Namespace of the cost span attributes (`<ns>.cost.usd`,
    /// `<ns>.cost.price_table`, `<ns>.cost.billing`, `<ns>.owner`).
    /// Defaults to `bastion`.
    pub fn with_attribute_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.attribute_namespace = namespace.into();
        self
    }

    /// The configured attribute namespace.
    pub fn attribute_namespace(&self) -> &str {
        &self.attribute_namespace
    }

    /// Version of the packaged table (`langfuse@<short commit>`).
    pub fn table_version(&self) -> &str {
        &bundled().version
    }

    /// The override file, when one is configured.
    pub fn override_path(&self) -> Option<&Path> {
        self.override_path.as_deref()
    }

    /// Find the entry for `model`: the override first, then the packaged
    /// table. Returns the entry and whether it came from the override.
    fn entry(&self, model: &str) -> Option<(&ModelEntry, bool)> {
        if let Some(e) = self.overrides.as_ref().and_then(|t| t.find(model)) {
            return Some((e, true));
        }
        bundled().table.find(model).map(|e| (e, false))
    }

    /// Price `usage` for the first of `models` that has an entry (pass the
    /// response model before the requested one). An entry that matches but
    /// cannot price the call (no input/output price in the selected tier)
    /// is [`PriceOutcome::Unknown`] — it never falls through to a different
    /// entry for another name.
    pub fn price(
        &self,
        models: &[&str],
        usage: &UsageBuckets,
        attributes: &TierAttributes,
    ) -> PriceOutcome {
        let details = usage_details(usage);
        for model in models.iter().filter(|m| !m.is_empty()) {
            let Some((entry, from_override)) = self.entry(model) else {
                continue;
            };
            let Some(tier) = entry.tier_for(&details, attributes) else {
                return PriceOutcome::Unknown;
            };
            let Some(usd) = tier.cost(usage) else {
                return PriceOutcome::Unknown;
            };
            return PriceOutcome::Priced {
                usd,
                table_version: self.version_label(from_override),
                model: entry.name.clone(),
                tier: tier.name.clone(),
            };
        }
        PriceOutcome::Unknown
    }

    /// Whether a metered call to `model` can be priced (its default tier
    /// has an input and an output price).
    pub fn has_price(&self, model: &str) -> bool {
        self.entry(model).is_some_and(|(e, _)| {
            e.default_tier
                .as_ref()
                .or(e.tiers.first())
                .is_some_and(|t| t.cost(&UsageBuckets::default()).is_some())
        })
    }

    /// BUP-02 admission check, run BEFORE a call: a metered call to a model
    /// with no price is refused with an actionable error. Subscription and
    /// local calls always pass; so does a provider that reports its own
    /// per-request cost (`reports_cost`), since that figure wins anyway.
    pub fn ensure_priced(
        &self,
        basis: CostBasis,
        reports_cost: bool,
        model: &str,
    ) -> Result<(), BastionError> {
        if !basis.is_metered() || reports_cost || self.has_price(model) {
            return Ok(());
        }
        Err(BastionError::PriceUnknown {
            model: model.to_owned(),
            table: self.table_version().to_owned(),
            hint: self.hint(),
        })
    }

    /// The cost of a finished call. A provider-reported cost wins; a
    /// subscription or local call costs `0`; otherwise the table prices the
    /// response model, falling back to `requested_model`.
    pub fn cost_of_call(
        &self,
        basis: CostBasis,
        requested_model: &str,
        usage: &TokenUsage,
    ) -> CallCost {
        if !basis.is_metered() {
            return CallCost {
                basis,
                usd: Some(0.0),
                price_table: self.table_version().to_owned(),
                source: CostSource::NotMetered,
            };
        }
        if let Some(real) = usage.actual_cost_usd {
            return CallCost {
                basis,
                usd: Some(real),
                price_table: PROVIDER_REPORTED.to_owned(),
                source: CostSource::ProviderReported,
            };
        }
        let models: Vec<&str> = usage
            .response_model
            .as_deref()
            .into_iter()
            .chain(std::iter::once(requested_model))
            .collect();
        match self.price(&models, &usage.buckets(), &TierAttributes::default()) {
            PriceOutcome::Priced {
                usd, table_version, ..
            } => CallCost {
                basis,
                usd: Some(usd),
                price_table: table_version,
                source: CostSource::Table,
            },
            PriceOutcome::Unknown => CallCost {
                basis,
                usd: None,
                price_table: self.table_version().to_owned(),
                source: CostSource::Unknown,
            },
        }
    }

    /// Upper bound of a call's dollars before it runs: `input_tokens` of
    /// uncached input and the full `max_output_tokens` of output. `None`
    /// when the model has no price. Used where a budget must cover a single
    /// call in advance (the Reflector's per-tick `budget_usd`).
    pub fn estimate_ceiling(
        &self,
        model: &str,
        input_tokens: u64,
        max_output_tokens: u64,
    ) -> Option<f64> {
        let buckets = UsageBuckets {
            input: input_tokens,
            output: max_output_tokens,
            ..Default::default()
        };
        match self.price(&[model], &buckets, &TierAttributes::default()) {
            PriceOutcome::Priced { usd, .. } => Some(usd),
            PriceOutcome::Unknown => None,
        }
    }

    fn version_label(&self, from_override: bool) -> String {
        if from_override {
            format!("{}{OVERRIDE_SUFFIX}", self.table_version())
        } else {
            self.table_version().to_owned()
        }
    }

    fn hint(&self) -> String {
        match (&self.override_hint, &self.override_path) {
            (Some(hint), _) => hint.clone(),
            (None, Some(path)) => format!("override file: {}", path.display()),
            (None, None) => "no override file is configured".to_owned(),
        }
    }
}

/// Usage details under the keys Langfuse's own ingestion produces, so a
/// usage-conditioned tier (`usageDetailPattern`) sees what it expects.
fn usage_details(b: &UsageBuckets) -> [(&'static str, u64); 5] {
    [
        ("input", b.input),
        ("input_cached_tokens", b.cache_read),
        ("input_cache_creation", b.cache_write),
        ("output", b.output),
        ("output_reasoning_tokens", b.reasoning),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UsageConvention;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-12
    }

    fn priced(outcome: &PriceOutcome) -> f64 {
        match outcome {
            PriceOutcome::Priced { usd, .. } => *usd,
            PriceOutcome::Unknown => panic!("expected a price, got Unknown"),
        }
    }

    #[test]
    fn bundled_table_parses_and_every_pattern_compiles() {
        let raw: Vec<serde_json::Value> = serde_json::from_str(BUNDLED_TABLE).unwrap();
        let table = PriceTable::parse(BUNDLED_TABLE).unwrap();
        assert_eq!(table.models.len(), raw.len());
        assert!(table.models.len() > 100);
    }

    #[test]
    fn bundled_version_comes_from_upstream_metadata() {
        let upstream: serde_json::Value = serde_json::from_str(BUNDLED_UPSTREAM).unwrap();
        assert_eq!(
            Pricing::bundled().table_version(),
            upstream["version"].as_str().unwrap()
        );
        assert!(Pricing::bundled().table_version().starts_with("langfuse@"));
    }

    #[test]
    fn anthropic_sonnet_resolves_under_bedrock_and_vertex_names() {
        let p = Pricing::bundled();
        let usage = UsageBuckets {
            input: 1_000,
            output: 500,
            cache_read: 2_000,
            cache_write: 100,
            reasoning: 0,
        };
        let attrs = TierAttributes::default();
        let direct = priced(&p.price(&["claude-sonnet-4-5"], &usage, &attrs));
        let bedrock = priced(&p.price(
            &["us.anthropic.claude-sonnet-4-5-20250929-v1:0"],
            &usage,
            &attrs,
        ));
        let vertex = priced(&p.price(&["claude-sonnet-4-5@20250929"], &usage, &attrs));
        assert!(close(direct, bedrock) && close(direct, vertex));
        // input 3e-6, output 1.5e-5, cache read 3e-7, cache creation 3.75e-6.
        let expected = 1_000.0 * 3e-6 + 500.0 * 1.5e-5 + 2_000.0 * 3e-7 + 100.0 * 3.75e-6;
        assert!(close(direct, expected), "{direct} != {expected}");
    }

    #[test]
    fn openai_cached_prompt_tokens_are_priced_at_the_cache_rate() {
        let p = Pricing::bundled();
        // prompt_tokens=10_000 (4_000 cached), completion_tokens=1_000.
        let usage = TokenUsage {
            input_tokens: 10_000,
            output_tokens: 1_000,
            cache_read: 4_000,
            convention: UsageConvention::Inclusive,
            ..Default::default()
        };
        let cost = p.cost_of_call(CostBasis::Metered, "gpt-4o", &usage);
        // gpt-4o: input 2.5e-6, cached 1.25e-6, output 1e-5.
        let expected = 6_000.0 * 2.5e-6 + 4_000.0 * 1.25e-6 + 1_000.0 * 1e-5;
        assert_eq!(cost.source, CostSource::Table);
        assert!(close(cost.usd.unwrap(), expected));
        assert_eq!(cost.price_table, p.table_version());
    }

    #[test]
    fn two_models_of_one_provider_price_differently() {
        let p = Pricing::bundled();
        let usage = TokenUsage {
            input_tokens: 1_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        let a = p
            .cost_of_call(CostBasis::Metered, "gpt-4o", &usage)
            .usd
            .unwrap();
        let b = p
            .cost_of_call(CostBasis::Metered, "gpt-4o-mini", &usage)
            .usd
            .unwrap();
        assert!(a > b && b > 0.0);
    }

    #[test]
    fn usage_conditioned_tier_applies_above_its_threshold() {
        let p = Pricing::bundled();
        let attrs = TierAttributes::default();
        let small = UsageBuckets {
            input: 100_000,
            output: 1_000,
            ..Default::default()
        };
        let large = UsageBuckets {
            input: 300_000,
            output: 1_000,
            ..Default::default()
        };
        let (
            PriceOutcome::Priced {
                tier: small_tier, ..
            },
            PriceOutcome::Priced {
                tier: large_tier, ..
            },
        ) = (
            p.price(&["gemini-2.5-pro"], &small, &attrs),
            p.price(&["gemini-2.5-pro"], &large, &attrs),
        )
        else {
            panic!("gemini-2.5-pro must be priced");
        };
        assert_eq!(small_tier, "Standard");
        assert_eq!(large_tier, "Large Context");
    }

    #[test]
    fn model_parameter_tier_needs_the_parameter() {
        let p = Pricing::bundled();
        let usage = UsageBuckets {
            input: 1_000,
            output: 1_000,
            ..Default::default()
        };
        let standard = priced(&p.price(&["gpt-4o"], &usage, &TierAttributes::default()));
        let mut attrs = TierAttributes::default();
        attrs
            .model_parameters
            .insert("service_tier".into(), serde_json::json!("priority"));
        let fast = priced(&p.price(&["gpt-4o"], &usage, &attrs));
        assert!(fast > standard);
    }

    #[test]
    fn response_model_wins_over_requested_model() {
        let p = Pricing::bundled();
        let usage = TokenUsage {
            input_tokens: 1_000,
            output_tokens: 1_000,
            response_model: Some("gpt-4o-mini".into()),
            ..Default::default()
        };
        let as_mini = p
            .cost_of_call(
                CostBasis::Metered,
                "gpt-4o-mini",
                &TokenUsage {
                    response_model: None,
                    ..usage.clone()
                },
            )
            .usd;
        assert_eq!(
            p.cost_of_call(CostBasis::Metered, "gpt-4o", &usage).usd,
            as_mini
        );
    }

    #[test]
    fn override_is_matched_first_and_labelled() {
        let json = r#"[{"id":"x","modelName":"gpt-4o","matchPattern":"(?i)^gpt-4o$",
            "pricingTiers":[{"name":"Standard","isDefault":true,"priority":0,"conditions":[],
            "prices":{"input":1e-6,"output":2e-6}}]}]"#;
        let p = Pricing::bundled()
            .with_override_json(json, "/etc/bastion/prices.json")
            .unwrap();
        let usage = TokenUsage {
            input_tokens: 1_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        let cost = p.cost_of_call(CostBasis::Metered, "gpt-4o", &usage);
        assert!(close(cost.usd.unwrap(), 1_000.0 * 1e-6 + 1_000.0 * 2e-6));
        assert_eq!(cost.price_table, format!("{}+override", p.table_version()));
        // A model the override does not name still comes from the package.
        let other = p.cost_of_call(CostBasis::Metered, "gpt-4o-mini", &usage);
        assert_eq!(other.price_table, p.table_version());
    }

    #[test]
    fn unknown_model_is_unknown_and_fails_closed_before_the_call() {
        let p = Pricing::bundled().with_override_hint("set [pricing] overrides");
        let usage = TokenUsage {
            input_tokens: 10,
            output_tokens: 10,
            ..Default::default()
        };
        let cost = p.cost_of_call(CostBasis::Metered, "no-such-model-xyz", &usage);
        assert_eq!(cost.usd, None);
        assert_eq!(cost.source, CostSource::Unknown);
        let err = p
            .ensure_priced(CostBasis::Metered, false, "no-such-model-xyz")
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no-such-model-xyz"), "{msg}");
        assert!(msg.contains("set [pricing] overrides"), "{msg}");
    }

    #[test]
    fn unknown_model_runs_once_an_override_prices_it() {
        let json = r#"[{"modelName":"house-model","matchPattern":"^house-model$",
            "pricingTiers":[{"name":"Standard","isDefault":true,"priority":0,"conditions":[],
            "prices":{"input":4e-6,"output":8e-6}}]}]"#;
        let p = Pricing::bundled()
            .with_override_json(json, "prices.json")
            .unwrap();
        assert!(p
            .ensure_priced(CostBasis::Metered, false, "house-model")
            .is_ok());
        let usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            ..Default::default()
        };
        let cost = p.cost_of_call(CostBasis::Metered, "house-model", &usage);
        assert!(close(cost.usd.unwrap(), 100.0 * 4e-6 + 50.0 * 8e-6));
    }

    #[test]
    fn subscription_and_local_cost_zero_and_always_pass() {
        let p = Pricing::bundled();
        let usage = TokenUsage {
            input_tokens: 1_000,
            output_tokens: 1_000,
            ..Default::default()
        };
        for basis in [CostBasis::Subscription, CostBasis::Local] {
            assert!(p.ensure_priced(basis, false, "anything").is_ok());
            let cost = p.cost_of_call(basis, "anything", &usage);
            assert_eq!(cost.usd, Some(0.0));
            assert_eq!(cost.source, CostSource::NotMetered);
        }
    }

    #[test]
    fn provider_reported_cost_wins_over_the_table() {
        let p = Pricing::bundled();
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            actual_cost_usd: Some(0.0021),
            ..Default::default()
        };
        let cost = p.cost_of_call(CostBasis::Metered, "gpt-4o", &usage);
        assert_eq!(cost.usd, Some(0.0021));
        assert_eq!(cost.price_table, PROVIDER_REPORTED);
        assert!(p
            .ensure_priced(CostBasis::Metered, true, "unlisted")
            .is_ok());
    }

    #[test]
    fn reasoning_tokens_fall_back_to_the_output_price() {
        let json = r#"[{"modelName":"r","matchPattern":"^r$","pricingTiers":[{"name":"S",
            "isDefault":true,"priority":0,"conditions":[],"prices":{"input":1e-6,"output":3e-6}}]}]"#;
        let p = Pricing::bundled()
            .with_override_json(json, "o.json")
            .unwrap();
        let usage = TokenUsage {
            input_tokens: 0,
            output_tokens: 100,
            reasoning_tokens: 40,
            ..Default::default()
        };
        let cost = p.cost_of_call(CostBasis::Metered, "r", &usage);
        assert!(close(cost.usd.unwrap(), 100.0 * 3e-6));
    }

    #[test]
    fn invalid_override_is_an_error() {
        let err = Pricing::bundled()
            .with_override_json("{not json", "bad.json")
            .unwrap_err();
        assert!(matches!(err, PricingError::Invalid { .. }));
        let err = Pricing::bundled()
            .with_override_file("/definitely/not/here.json")
            .unwrap_err();
        assert!(matches!(err, PricingError::Read { .. }));
    }

    #[test]
    fn estimate_ceiling_prices_the_full_output_allowance() {
        let p = Pricing::bundled();
        let ceiling = p.estimate_ceiling("gpt-4o", 1_000, 800).unwrap();
        assert!(close(ceiling, 1_000.0 * 2.5e-6 + 800.0 * 1e-5));
        assert_eq!(p.estimate_ceiling("no-such-model-xyz", 1, 1), None);
    }
}
