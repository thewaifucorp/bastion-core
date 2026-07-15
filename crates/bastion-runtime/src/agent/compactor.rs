use crate::provider::Provider;
use crate::session::SessionManager;
use crate::types::{ContentPart, Message, MessageContent, Role};

pub struct AutoCompact {
    /// Token ratio threshold to trigger compaction. Default: 0.80 (D-08).
    pub threshold: f64,
    /// Number of recent messages to preserve verbatim. Default: 20 (D-09, AI-SPEC §4b.4).
    pub keep_last: usize,
}

impl Default for AutoCompact {
    fn default() -> Self {
        Self {
            threshold: 0.80,
            keep_last: 20,
        }
    }
}

impl AutoCompact {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if compaction is needed BEFORE building the LLM request.
    /// Uses actual token counts from provider API when available; falls back to char/4 heuristic.
    pub fn needs_compaction(&self, used_tokens: u32, context_limit: usize) -> bool {
        if context_limit == 0 {
            return false;
        }
        (used_tokens as f64 / context_limit as f64) >= self.threshold
    }

    /// Estimate token count from message content (fallback when no API usage data yet).
    pub(crate) fn estimate_tokens(messages: &[Message]) -> u32 {
        messages
            .iter()
            .map(|m| {
                match &m.content {
                    MessageContent::Text(t) => (t.len() / 4) as u32,
                    MessageContent::Parts(parts) => {
                        parts
                            .iter()
                            .map(|p| match p {
                                ContentPart::Text { text } => (text.len() / 4) as u32,
                                _ => 50u32, // rough estimate for tool blocks
                            })
                            .sum()
                    }
                }
            })
            .sum()
    }

    /// Compact: keep system prompt + last N messages verbatim + rolling LLM summary of older messages.
    /// Summary generated via provider.complete_simple() — 1 LLM call (D-10).
    /// If messages.len() <= keep_last: no-op (not enough to compact).
    pub async fn compact(
        &self,
        session_id: &str,
        messages: &[Message],
        provider: &dyn Provider,
        session: &SessionManager,
    ) -> anyhow::Result<Vec<Message>> {
        if messages.len() <= self.keep_last {
            return Ok(messages.to_vec());
        }

        let split_at = messages.len() - self.keep_last;
        let older = &messages[..split_at];
        let recent = &messages[split_at..];

        // Build summarization prompt from older messages
        let history_text: String = older
            .iter()
            .map(|m| {
                let role_str = m.role.to_string();
                let content_str = match &m.content {
                    MessageContent::Text(t) => t.clone(),
                    MessageContent::Parts(_) => "[structured content]".to_owned(),
                };
                format!("[{}]: {}", role_str, content_str)
            })
            .collect::<Vec<_>>()
            .join("\n");

        let summary_prompt = format!(
            "Summarize the following conversation history concisely, preserving key decisions, facts, and context needed for continuity:\n\n{}",
            history_text
        );

        let summary = provider
            .complete_simple(&summary_prompt)
            .await
            .map_err(|e| anyhow::anyhow!("AutoCompact summary failed: {}", e))?;

        tracing::info!(
            event = "autocompact_fired",
            older_count = older.len(),
            recent_count = recent.len()
        );

        // Replace session history with summary sentinel + recent messages
        session
            .replace_with_summary(session_id, summary.clone(), recent)
            .await?;

        // Return new in-memory history for the current turn
        let mut compacted = vec![Message {
            role: Role::System,
            content: MessageContent::Text(format!("[CONTEXT SUMMARY]: {}", summary)),
        }];
        compacted.extend_from_slice(recent);
        Ok(compacted)
    }
}
