//! Terminal-agent provider — runs Claude Code / opencode headless as the turn EXECUTOR.
//!
//! NOT a real model: no token-level structured guarantee, and the CLI runs its own
//! tool-loop, so Bastion's egress gate / approval do NOT wrap its tool-use. Opt-in,
//! per-deployment (cloud personal use with unlimited CC). NOT the OSS default.
//! ponytail: justified by the unlimited-CC constraint; see decisions/structured-output-strategy.md.
//!
//! **DEPRECATED (A-09, `docs/ARCHITECTURE.md`):** superseded by `AgentRuntime`
//! (`bastion-agent-runtime`'s `CodexAppServerRuntime`/`AcpxAgentRuntime`, A-03/A-04) — a
//! proven substitute with structured sessions/events, real tool-call surfacing, and no
//! egress/approval/budget bypass. This module now only compiles behind the
//! `legacy-terminal-agent` Cargo feature (OFF by default) — see the feature doc comment in
//! `Cargo.toml`. Kept for one deprecation window (A-09 gate: feature flag first, removal
//! only after A-08 + this feature verified green and a tested rollback path), never deleted
//! outright.

use super::Provider;
use crate::types::{CallConfig, LlmResponse, Message, MessageContent, Role};

pub struct TerminalAgentProvider {
    bin: String,   // "claude" | "opencode"
    model: String, // label, e.g. "claude_code"
}

impl TerminalAgentProvider {
    pub fn new(bin: &str, model: &str) -> Self {
        Self {
            bin: bin.to_owned(),
            model: model.to_owned(),
        }
    }

    async fn run(&self, prompt: &str) -> anyhow::Result<String> {
        let mut args = vec![
            "-p".to_owned(),
            prompt.to_owned(),
            "--output-format".to_owned(),
            "text".to_owned(),
        ];
        // Claude Code: pin the runtime model (default Haiku 4.5; override via env).
        // Skipped for opencode — different --model syntax; lets it use its own default.
        if self.bin == "claude" {
            let model = std::env::var("BASTION_TERMINAL_AGENT_MODEL")
                .unwrap_or_else(|_| "claude-haiku-4-5-20251001".to_owned());
            args.push("--model".to_owned());
            args.push(model);
            // PROV-09 tool inversion: this provider returns tool_calls: None by design —
            // a terminal agent runs its OWN tool-loop, so Bastion-side function-calling
            // (MCP tools offered to the model) never fires. The documented mitigation is
            // to point the CC itself at the same MCP servers: pass a Claude Code MCP
            // config file here and memory/skills become CC-native tools.
            if let Ok(mcp_cfg) = std::env::var("BASTION_TERMINAL_AGENT_MCP_CONFIG") {
                if !mcp_cfg.is_empty() {
                    args.push("--mcp-config".to_owned());
                    args.push(mcp_cfg);
                }
            }
            // Headless `-p` runs cannot answer permission prompts — MCP tools must be
            // pre-allowed (e.g. "mcp__memupalace mcp__skill-writer") or CC declines them.
            if let Ok(allowed) = std::env::var("BASTION_TERMINAL_AGENT_ALLOWED_TOOLS") {
                if !allowed.is_empty() {
                    args.push("--allowedTools".to_owned());
                    args.push(allowed);
                }
            }
        }
        let out = tokio::process::Command::new(&self.bin)
            .args(&args)
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("{} spawn failed: {e}", self.bin))?;
        if !out.status.success() {
            anyhow::bail!(
                "{} exited {}: {}",
                self.bin,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
}

/// Flatten system + conversation into one prompt for a headless agent CLI.
fn render_prompt(system: &str, messages: &[Message]) -> String {
    let mut s = String::new();
    if !system.is_empty() {
        s.push_str(system);
        s.push_str("\n\n");
    }
    for m in messages {
        let who = match m.role {
            Role::User => "User",
            Role::Assistant => "Assistant",
            _ => "System",
        };
        if let MessageContent::Text(t) = &m.content {
            s.push_str(who);
            s.push_str(": ");
            s.push_str(t);
            s.push('\n');
        }
    }
    s
}

/// Schema-in-prompt — the intent-compiler trick. A strong model (CC = Claude) obeys
/// "emit ONLY this JSON"; the router's existing 3x serde-parse-retry is the safety net.
/// (We can't constrain at the token level on an opaque CLI — this is governance, not constraint.)
fn structured_prompt(system: &str, user: &str, schema: &serde_json::Value) -> String {
    format!(
        "{system}\n\n{user}\n\nRespond with ONLY a JSON object matching this JSON Schema. \
         No prose, no markdown fences:\n{}",
        serde_json::to_string_pretty(schema).unwrap_or_default()
    )
}

/// Build the prompt for `complete()`'s `response_format` branch — extracted so it's
/// unit-testable without spawning a subprocess (Task 3). Renders the multi-turn
/// `messages` list as the "user" half of `structured_prompt` (system passed
/// separately, so it isn't duplicated inside `render_prompt`'s own system slot),
/// producing the identical prompt shape `complete_structured` already relies on.
fn build_structured_invocation(
    system_prompt: &str,
    messages: &[Message],
    schema: &serde_json::Value,
) -> String {
    structured_prompt(system_prompt, &render_prompt("", messages), schema)
}

/// Extract the first balanced JSON object from a possibly-messy reply (strips ```json
/// fences and surrounding prose). Brace-counting is string-aware so `}` inside a string
/// value doesn't end it early. The fragile bit → covered by the self-check below.
fn extract_json(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    for (i, c) in raw[start..].char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' if in_str => esc = true,
            '"' => in_str = !in_str,
            '{' if !in_str => depth += 1,
            '}' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return Some(&raw[start..=start + i]);
                }
            }
            _ => {}
        }
    }
    None
}

#[async_trait::async_trait]
impl Provider for TerminalAgentProvider {
    async fn complete(
        &self,
        messages: &[Message],
        config: &CallConfig,
    ) -> anyhow::Result<LlmResponse> {
        // D-01 unification: fold `complete_structured`'s prompt-injection behavior
        // (below, untouched — removed later, Plan 08-09) into complete()'s
        // response_format branch, verbatim, reusing the same structured_prompt/
        // extract_json helpers.
        if let Some(schema) = &config.response_format {
            let raw = self
                .run(&build_structured_invocation(
                    &config.system_prompt,
                    messages,
                    schema,
                ))
                .await?;
            return Ok(LlmResponse {
                text: extract_json(&raw).unwrap_or(&raw).to_owned(),
                tool_calls: None,
                usage: Default::default(),
            });
        }

        let text = self
            .run(&render_prompt(&config.system_prompt, messages))
            .await?;
        Ok(LlmResponse {
            text,
            tool_calls: None,
            usage: Default::default(),
        })
    }

    async fn complete_simple(&self, prompt: &str) -> anyhow::Result<String> {
        self.run(prompt).await
    }

    /// D-09: terminal_agent has NO API-level schema/tool_choice control at all — it's
    /// a subprocess CLI, not a real model endpoint. Callers (Plan 08-07) MUST NOT
    /// route it through `complete_structured_via_forced_tool_call` (which requires
    /// `tool_choice` support this provider lacks); its `complete()` above already
    /// handles `response_format` entirely via its own prompt-injection strategy.
    fn supports_json_schema(&self) -> bool {
        false
    }

    fn context_limit(&self) -> usize {
        200_000
    }
    fn model_name(&self) -> &str {
        &self.model
    }
    fn name(&self) -> &'static str {
        "claude_code"
    } // ponytail: egress bypassed anyway; opencode shares the tag
}

#[cfg(test)]
mod tests {
    use super::{build_structured_invocation, extract_json};
    use crate::types::{Message, MessageContent, Role};

    #[test]
    fn extract_json_handles_bare_fenced_prose_and_braces_in_strings() {
        assert_eq!(extract_json(r#"{"a":1}"#), Some(r#"{"a":1}"#));
        assert_eq!(extract_json("```json\n{\"a\":1}\n```"), Some(r#"{"a":1}"#));
        assert_eq!(
            extract_json(r#"Sure! {"a":{"b":2}} done"#),
            Some(r#"{"a":{"b":2}}"#)
        );
        assert_eq!(
            extract_json(r#"{"s":"has } brace"}"#),
            Some(r#"{"s":"has } brace"}"#)
        );
        assert_eq!(extract_json("no json here"), None);
    }

    #[test]
    fn build_structured_invocation_matches_structured_prompt_shape() {
        let schema = serde_json::json!({"type": "object", "properties": {"a": {}}});
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Text("hi".into()),
        }];

        let out = build_structured_invocation("be helpful", &messages, &schema);

        assert!(out.starts_with("be helpful\n\n"));
        assert!(out.contains("User: hi"));
        assert!(out.contains("Respond with ONLY a JSON object matching this JSON Schema."));
        assert!(out.contains(&serde_json::to_string_pretty(&schema).unwrap()));
    }
}
