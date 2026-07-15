//! SEAM #2 — TurnContext provider.
//!
//! O AgentLoop mantém `Vec<Box<dyn TurnContextProvider>>`. Em `build_system_prompt`,
//! cada provider é consultado e seus blocos são concatenados ao system prompt.
//!
//! **Regra de fronteira (LOCKED):** o core NÃO interpreta o conteúdo dos blocos.
//! O provider decide o formato; o core só inclui. Isso permite que uma integração externa
//! injete `<active_object>...</active_object>` sem que o core conheça o schema.

use crate::memory::PrivacyTier;

/// Um bloco de contexto opaco para injeção no system prompt.
///
/// `content` é texto livre — o AgentLoop inclui diretamente, sem interpretar.
/// `max_tier` indica o tier máximo dos dados no bloco, usado pelo egress check.
///
/// SECURITY (Pitfall 5): o egress check deve usar `max_tier` do conteúdo injetado,
/// não apenas o tier da persona — beliefs LocalOnly no system prompt vazam se o
/// check usar só o tier da persona (que pode ser CloudOk).
///
/// Deriva `Debug`/`Clone`/`PartialEq` (achado #1 do Loop 3-E): um segundo consumidor
/// que injeta blocos via SEAM #2 precisa poder `assert_eq!`/logar o que foi construído
/// sem destructurar campo a campo. Puramente aditivo — zero mudança de comportamento.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextBlock {
    pub content: String,
    pub max_tier: PrivacyTier,
}

/// Provedor de blocos de contexto para um turn.
///
/// Implementadores devem retornar blocos opacos para o turn atual.
/// O AgentLoop inclui cada bloco no system prompt sem interpretar seu conteúdo.
///
/// Exemplos de uso:
/// - `IdentityProvider`: injeta o bloco de identidade (M1) para o owner.
/// - `MemoryRagProvider`: busca beliefs relevantes e injeta como contexto RAG.
/// - Integração externa: injeta `<active_object>` sem que o core conheça o schema.
#[async_trait::async_trait]
pub trait TurnContextProvider: Send + Sync {
    /// Retorna blocos de contexto opacos para o turn atual.
    ///
    /// `persona` é o nome da persona ativa resolvida pelo router (ou `None` quando
    /// nenhuma casou). Providers que fazem recall de memória devem escopá-lo por
    /// persona: `retrieve_tagged(owner, persona)` traz os beliefs desta persona +
    /// os globais (untagged), nunca os de outra persona.
    ///
    /// Retornar `Vec::new()` é válido (ex: sem identidade no primeiro uso = onboarding).
    /// Implementações devem ser rápidas (sem I/O pesado) — são chamadas em todo turn.
    async fn context_for_turn(
        &self,
        owner: &str,
        turn_msg: &str,
        persona: Option<&str>,
    ) -> Vec<ContextBlock>;
}
