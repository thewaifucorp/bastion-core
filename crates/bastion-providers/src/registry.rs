use super::{
    anthropic::AnthropicProvider, gemini::GeminiProvider, groq::GroqProvider,
    ollama::OllamaProvider, openai::OpenAIProvider, openrouter::OpenRouterProvider, Provider,
    SharedProvider,
};
use std::sync::Arc;
use tokio::sync::RwLock;

pub fn resolve_provider(model_name: &str) -> anyhow::Result<Box<dyn Provider>> {
    resolve_provider_with_credential(model_name, None)
}

/// Same dispatch as [`resolve_provider`], for a caller that already resolved
/// a credential (e.g. a product-level secret backend, `BASTION_SECRETS_DIR`
/// file, or a future non-API-key auth flow) and wants to hand it to the
/// provider constructor directly instead of the provider reading
/// `std::env` itself.
///
/// `credential: None` is byte-for-byte [`resolve_provider`]'s old behavior —
/// every constructor's own env lookup, unchanged, so every existing caller
/// keeps working without touching this function. `credential: Some(key)`
/// routes to each provider's `with_api_key` constructor instead, bypassing
/// `std::env` entirely for the secret. Ollama takes no credential (it has no
/// secret to inject) and Ollama's arm ignores `credential` by design.
pub fn resolve_provider_with_credential(
    model_name: &str,
    credential: Option<&str>,
) -> anyhow::Result<Box<dyn Provider>> {
    if model_name == "claude_code" || model_name == "opencode" {
        anyhow::bail!(
            "'{model_name}' is an external agent runtime id, not a model provider; \
             register it through bastion-agent-runtime"
        );
    }

    if model_name.starts_with("claude") {
        Ok(Box::new(match credential {
            Some(key) => AnthropicProvider::with_api_key(model_name, key),
            None => AnthropicProvider::new(model_name),
        }))
    } else if model_name.starts_with("gpt")
        || model_name.starts_with("o1")
        || model_name.starts_with("o3")
    {
        Ok(Box::new(match credential {
            Some(key) => OpenAIProvider::with_api_key(model_name, key),
            None => OpenAIProvider::new(model_name),
        }))
    } else if model_name.starts_with("gemini") {
        Ok(Box::new(match credential {
            Some(key) => GeminiProvider::with_api_key(model_name, key),
            None => GeminiProvider::new(model_name),
        }))
    } else if let Some(groq_model) = model_name.strip_prefix("groq/") {
        // `groq/<model>` — checked BEFORE the generic `/` (OpenRouter) branch. The prefix is
        // stripped so the bare Groq id is sent upstream (it may itself contain a `/`, e.g.
        // `groq/qwen/qwen3-32b` → `qwen/qwen3-32b`).
        Ok(Box::new(match credential {
            Some(key) => GroqProvider::with_api_key(groq_model, key),
            None => GroqProvider::new(groq_model),
        }))
    } else if model_name.contains('/') {
        // OpenRouter slugs are namespaced: `vendor/model[:tag]` (e.g. `:free`).
        Ok(Box::new(match credential {
            Some(key) => OpenRouterProvider::with_api_key(model_name, key),
            None => OpenRouterProvider::new(model_name),
        }))
    } else {
        Ok(Box::new(OllamaProvider::new(model_name)))
    }
}

/// A3 `ProviderResolver` implementation (M2 step 3b): the registry-backed
/// resolver `main.rs` injects into the loop's `provider_resolver` field —
/// production's fallback-ladder rung 3 (D-10) delegates here, exactly like
/// the old direct `registry::resolve_provider` call it replaces.
pub struct RegistryProviderResolver;

impl bastion_runtime::agent::ports::ProviderResolver for RegistryProviderResolver {
    fn resolve(&self, model: &str) -> anyhow::Result<Box<dyn Provider>> {
        resolve_provider(model)
    }
}

/// Resolve the `Provider` instance the offline Reflector should call (LEARN-05: budget,
/// interval AND model are configurable independently).
///
/// Mirrors `PersonaRegistry::provider_model_for`'s tier-based-default shape: an explicit,
/// non-empty `configured_model` always wins and gets its own freshly-built provider instance
/// (via [`resolve_provider`]); unset/empty falls back to `default_model` — the SAME model the
/// main agent provider already runs on — in which case `default_provider` is reused verbatim
/// (no redundant duplicate instance), preserving the pre-fix default behavior exactly.
pub fn resolve_reflector_provider(
    configured_model: Option<&str>,
    default_model: &str,
    default_provider: SharedProvider,
) -> anyhow::Result<SharedProvider> {
    let resolved = match configured_model {
        Some(m) if !m.trim().is_empty() => m,
        _ => default_model,
    };
    if resolved == default_model {
        Ok(default_provider)
    } else {
        Ok(Arc::new(RwLock::new(resolve_provider(resolved)?)))
    }
}

/// Test-only helper: resolve which provider kind a model name maps to
/// without constructing the provider (which reads env vars).
#[doc(hidden)]
pub fn resolve_provider_kind(model_name: &str) -> &'static str {
    if model_name == "claude_code" || model_name == "opencode" {
        "agent_runtime"
    } else if model_name.starts_with("claude") {
        "anthropic"
    } else if model_name.starts_with("gpt")
        || model_name.starts_with("o1")
        || model_name.starts_with("o3")
    {
        "openai"
    } else if model_name.starts_with("gemini") {
        "gemini"
    } else if model_name.starts_with("groq/") {
        "groq"
    } else if model_name.contains('/') {
        "openrouter"
    } else {
        "ollama"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- resolve_provider_with_credential (provider secret injection) ----
    // The whole point of this constructor path is building a provider WITHOUT
    // touching std::env — these run safely in any CI environment, unlike a
    // bare `resolve_provider` call for a keyed provider (which reads real env
    // vars and panics if unset).

    #[test]
    fn resolve_provider_with_credential_builds_anthropic_without_env() {
        let provider = resolve_provider_with_credential("claude-opus-4-7", Some("sk-test-key"))
            .expect("resolve with an injected credential must not touch std::env");
        assert_eq!(provider.name(), "anthropic");
        assert_eq!(provider.model_name(), "claude-opus-4-7");
    }

    #[test]
    fn resolve_provider_with_credential_builds_openai_without_env() {
        let provider = resolve_provider_with_credential("gpt-4o", Some("sk-test-key"))
            .expect("resolve with an injected credential must not touch std::env");
        assert_eq!(provider.name(), "openai");
        assert_eq!(provider.model_name(), "gpt-4o");
    }

    #[test]
    fn resolve_provider_with_credential_builds_gemini_without_env() {
        let provider = resolve_provider_with_credential("gemini-2.0-flash", Some("test-key"))
            .expect("resolve with an injected credential must not touch std::env");
        assert_eq!(provider.name(), "gemini");
        assert_eq!(provider.model_name(), "gemini-2.0-flash");
    }

    #[test]
    fn resolve_provider_with_credential_builds_groq_without_env() {
        let provider =
            resolve_provider_with_credential("groq/llama-3.1-8b-instant", Some("test-key"))
                .expect("resolve with an injected credential must not touch std::env");
        assert_eq!(provider.name(), "groq");
        // The `groq/` prefix is stripped before construction — model_name()
        // must report the bare id, matching resolve_provider's own behavior.
        assert_eq!(provider.model_name(), "llama-3.1-8b-instant");
    }

    #[test]
    fn resolve_provider_with_credential_builds_openrouter_without_env() {
        let provider = resolve_provider_with_credential(
            "meta-llama/llama-3.3-70b-instruct:free",
            Some("test-key"),
        )
        .expect("resolve with an injected credential must not touch std::env");
        assert_eq!(provider.name(), "openrouter");
    }

    #[test]
    fn resolve_provider_with_credential_none_matches_resolve_provider_for_ollama() {
        // Ollama has no secret to inject — `credential` is ignored by design,
        // so both entry points must behave identically for it.
        let via_credential = resolve_provider_with_credential("llama3", Some("ignored"))
            .expect("ollama never reads a credential");
        let via_plain = resolve_provider("llama3").expect("ollama never reads env either");
        assert_eq!(via_credential.name(), via_plain.name());
        assert_eq!(via_credential.model_name(), via_plain.model_name());
    }

    #[test]
    fn resolve_provider_with_credential_rejects_agent_runtime_ids_same_as_resolve_provider() {
        match resolve_provider_with_credential("claude_code", Some("ignored")) {
            Err(e) => assert!(e.to_string().contains("external agent runtime id")),
            Ok(_) => panic!("claude_code must not resolve as a model provider"),
        }
    }

    #[test]
    fn resolve_provider_kind_anthropic() {
        assert_eq!(resolve_provider_kind("claude-opus-4-7"), "anthropic");
        assert_eq!(resolve_provider_kind("claude-sonnet-4-5"), "anthropic");
    }

    #[test]
    fn resolve_provider_kind_openai() {
        assert_eq!(resolve_provider_kind("gpt-4o"), "openai");
        assert_eq!(resolve_provider_kind("o1-mini"), "openai");
        assert_eq!(resolve_provider_kind("o3-mini"), "openai");
    }

    #[test]
    fn resolve_provider_kind_ollama() {
        assert_eq!(resolve_provider_kind("llama3"), "ollama");
        assert_eq!(resolve_provider_kind("mistral"), "ollama");
    }

    #[test]
    fn resolve_provider_kind_gemini() {
        assert_eq!(resolve_provider_kind("gemini-2.0-flash"), "gemini");
        assert_eq!(resolve_provider_kind("gemini-3-pro-preview"), "gemini");
    }

    #[test]
    fn resolve_provider_kind_agent_runtime() {
        assert_eq!(resolve_provider_kind("claude_code"), "agent_runtime");
        assert_eq!(resolve_provider_kind("opencode"), "agent_runtime");
    }

    #[test]
    fn resolve_provider_rejects_agent_runtime_ids() {
        match resolve_provider("claude_code") {
            Err(e) => assert!(e.to_string().contains("external agent runtime id")),
            Ok(_) => panic!("claude_code must not resolve as a model provider"),
        }
        match resolve_provider("opencode") {
            Err(e) => assert!(e.to_string().contains("external agent runtime id")),
            Ok(_) => panic!("opencode must not resolve as a model provider"),
        }
    }

    #[test]
    fn resolve_provider_kind_groq() {
        // `groq/` prefix wins over the generic `/` OpenRouter branch, even when the
        // bare Groq id itself contains a `/` (e.g. qwen/qwen3-32b).
        assert_eq!(resolve_provider_kind("groq/llama-3.1-8b-instant"), "groq");
        assert_eq!(resolve_provider_kind("groq/qwen/qwen3-32b"), "groq");
        // Without the prefix, a namespaced slug still routes to OpenRouter.
        assert_eq!(resolve_provider_kind("qwen/qwen3-32b"), "openrouter");
    }

    #[test]
    fn resolve_provider_kind_openrouter() {
        assert_eq!(
            resolve_provider_kind("meta-llama/llama-3.3-70b-instruct:free"),
            "openrouter"
        );
        assert_eq!(
            resolve_provider_kind("deepseek/deepseek-chat-v3-0324:free"),
            "openrouter"
        );
        assert_eq!(
            resolve_provider_kind("google/gemma-2-9b-it:free"),
            "openrouter"
        );
    }

    // ---- resolve_reflector_provider (LEARN-05 gap fix) ----
    // Uses ollama-style model names only — the only provider kind that never reads an
    // API key env var, so these tests are safe to run in any CI environment.

    #[tokio::test]
    async fn resolve_reflector_provider_reuses_default_when_unset() {
        let default_provider: SharedProvider =
            Arc::new(RwLock::new(resolve_provider("llama3").expect("resolve")));
        let default_clone = default_provider.clone();
        let resolved = resolve_reflector_provider(None, "llama3", default_provider)
            .expect("resolve_reflector_provider");
        assert!(
            Arc::ptr_eq(&resolved, &default_clone),
            "unset [reflector].model must reuse the exact default agent provider instance"
        );
    }

    #[tokio::test]
    async fn resolve_reflector_provider_reuses_default_when_configured_is_blank() {
        let default_provider: SharedProvider =
            Arc::new(RwLock::new(resolve_provider("llama3").expect("resolve")));
        let default_clone = default_provider.clone();
        let resolved = resolve_reflector_provider(Some("   "), "llama3", default_provider)
            .expect("resolve_reflector_provider");
        assert!(
            Arc::ptr_eq(&resolved, &default_clone),
            "a blank [reflector].model must be treated as unset, never routed as a model id"
        );
    }

    #[tokio::test]
    async fn resolve_reflector_provider_builds_distinct_provider_when_configured_differs() {
        let default_provider: SharedProvider =
            Arc::new(RwLock::new(resolve_provider("llama3").expect("resolve")));
        let default_clone = default_provider.clone();
        let resolved = resolve_reflector_provider(Some("mistral"), "llama3", default_provider)
            .expect("resolve_reflector_provider");
        assert!(
            !Arc::ptr_eq(&resolved, &default_clone),
            "a distinct configured model must build a fresh provider, not reuse the default"
        );
        let guard = resolved.read().await;
        assert_eq!(
            guard.model_name(),
            "mistral",
            "the Reflector-specific provider must be built from the configured model"
        );
    }
}
