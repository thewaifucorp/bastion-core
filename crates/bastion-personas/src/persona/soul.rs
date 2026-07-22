// SOUL.md parser — front-matter (serde_norway) + body (persona system prompt).
// Pitfall 5: SOUL.md is `---\nYAML\n---\nMarkdown`, not pure YAML.
// parse_soul splits the front-matter and parses ONLY that with serde_norway;
// the body becomes the persona system prompt.

use serde::Deserialize;

/// The `bastion:` block inside a SOUL.md front-matter.
#[derive(Debug, Clone, Deserialize)]
pub struct BastionBlock {
    pub privacy_tier: crate::memory::PrivacyTier,
    pub weight: f32,
}

/// Parsed front-matter of a persona SOUL.md file.
///
/// Persona contract v2 adds `objectives`/`goals`/`tools`/`scope`. All four are
/// `#[serde(default)]` — a v1 SOUL.md (no v2 fields at all) still parses
/// cleanly, matching the loader's skip-with-warn contract in `mod.rs`
/// (making any of these serde-`required` would turn a merely-incomplete
/// contract into a hard parse error that silently drops the whole persona).
/// [`PersonaFront::validate`] is the LOUD path for incompleteness instead —
/// it returns every problem found rather than failing the parse.
#[derive(Debug, Clone, Deserialize)]
pub struct PersonaFront {
    pub name: String,
    pub description: Option<String>,
    pub bastion: BastionBlock,
    #[serde(default)]
    pub skills: Vec<String>,
    /// Contract v2: what this persona is FOR — free-form, human-readable.
    #[serde(default)]
    pub objectives: Vec<String>,
    /// Contract v2: this persona's declared goals (distinct from the
    /// persisted, GOAL-01-tracked `bastion_types::Goal` row).
    #[serde(default)]
    pub goals: Vec<String>,
    /// Contract v2: the capability allowlist. `None`/absent (the pre-v2
    /// default) means unrestricted — every existing SOUL.md keeps working
    /// exactly as before. `Some(list)` restricts this persona's tool
    /// dispatch to exactly the names in `list` (enforced by
    /// `CapabilityRegistry::invoke`'s Policy 0).
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Contract v2: free-form declared operating scope.
    #[serde(default)]
    pub scope: Option<String>,
}

impl PersonaFront {
    /// Validate persona contract v2 completeness. Returns every problem found
    /// (never stops at the first) so an operator sees the FULL picture in one
    /// pass — never a hard error (see the module doc comment on why these
    /// fields stay `#[serde(default)]`, not serde-required).
    ///
    /// Callers:
    /// - The registry loader (`mod.rs`) calls this AFTER a successful parse
    ///   and `tracing::warn!`s each problem, but keeps its existing
    ///   skip-with-warn behavior — this does NOT turn a validation problem
    ///   into a load failure.
    /// - An agent-side "propose a persona" apply path is expected to call
    ///   this and fail LOUD (reject the proposal) instead of silently
    ///   accepting an incomplete contract.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();

        if self.objectives.is_empty() {
            problems.push(
                "persona contract v2: `objectives` is empty — declare at least one".to_string(),
            );
        }
        if self.goals.is_empty() {
            problems
                .push("persona contract v2: `goals` is empty — declare at least one".to_string());
        }
        let scope_missing = match &self.scope {
            None => true,
            Some(s) => s.is_empty(),
        };
        if scope_missing {
            problems.push(
                "persona contract v2: `scope` is missing or empty — declare this persona's operating scope".to_string(),
            );
        }
        // `tools: None` is a VALID, legacy/unrestricted contract — not a
        // problem. `tools: Some([])` is suspicious: an author who wrote an
        // explicit (but empty) allowlist most likely meant to restrict this
        // persona to *something* and forgot to list it, which — once the
        // tools gate (Policy 0) is wired — would silently deny EVERY tool
        // call. Flagged so the operator notices before that surprises them,
        // but kept in the same warn-level bucket as the others (the loader
        // never hard-fails on `validate()`; only an apply-path caller does).
        if matches!(&self.tools, Some(list) if list.is_empty()) {
            problems.push(
                "persona contract v2: `tools` is `Some([])` — an explicit empty allowlist denies EVERY tool call; use `tools: null`/omit the key for unrestricted, or list the allowed capabilities".to_string(),
            );
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

/// Parse a SOUL.md string into `(PersonaFront, system_prompt_body)`.
///
/// The SOUL.md format is:
/// ```text
/// ---
/// name: Aria
/// bastion:
///   privacy_tier: cloud-ok
///   weight: 0.8
/// ---
/// You are Aria, a helpful assistant.
/// ```
///
/// The front-matter is parsed via serde_norway; the body (everything after the
/// closing `---`) is returned trimmed as the persona system prompt.
pub fn parse_soul(md: &str) -> anyhow::Result<(PersonaFront, String)> {
    // Strip the leading `---` sentinel (Pitfall 5: whole file is not pure YAML)
    let body = md
        .strip_prefix("---")
        .ok_or_else(|| anyhow::anyhow!("SOUL.md missing opening '---' front-matter delimiter"))?;

    // Split at the closing `\n---` to separate YAML front-matter from markdown body
    let (front_yaml, prose) = body.split_once("\n---").ok_or_else(|| {
        anyhow::anyhow!("SOUL.md front-matter is unterminated (missing closing '---')")
    })?;

    let front: PersonaFront = serde_norway::from_str(front_yaml)
        .map_err(|e| anyhow::anyhow!("failed to parse SOUL.md front-matter: {e}"))?;

    // prose may start with a newline; trim leading whitespace/newlines
    Ok((front, prose.trim_start().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PrivacyTier;

    const LOCAL_SOUL: &str = r#"---
name: Saúde
description: Health persona
bastion:
  privacy_tier: local-only
  weight: 0.9
skills:
  - nutrition
  - fitness
---
You are Saúde, a privacy-first health advisor.
Only Ollama processes your context.
"#;

    const CLOUD_SOUL: &str = r#"---
name: Aria
bastion:
  privacy_tier: cloud-ok
  weight: 0.7
---
You are Aria, a general-purpose assistant.
"#;

    #[test]
    fn parse_local_only_soul() {
        let (front, body) = parse_soul(LOCAL_SOUL).expect("parse failed");
        assert_eq!(front.name, "Saúde");
        assert_eq!(front.description.as_deref(), Some("Health persona"));
        assert_eq!(front.bastion.privacy_tier, PrivacyTier::LocalOnly);
        assert!((front.bastion.weight - 0.9).abs() < 1e-5);
        assert_eq!(front.skills, vec!["nutrition", "fitness"]);
        assert!(
            body.contains("You are Saúde"),
            "body should contain system prompt prose, got: {body:?}"
        );
        // Body should NOT contain any YAML front-matter lines
        assert!(!body.contains("privacy_tier"), "body must not contain YAML");
    }

    #[test]
    fn parse_cloud_ok_soul() {
        let (front, body) = parse_soul(CLOUD_SOUL).expect("parse failed");
        assert_eq!(front.name, "Aria");
        assert_eq!(front.bastion.privacy_tier, PrivacyTier::CloudOk);
        assert!(body.contains("You are Aria"));
        assert!(front.skills.is_empty());
    }

    // --- Persona contract v2 -------------------------------------------------

    const V1_LEGACY_SOUL: &str = r#"---
name: Legacy
bastion:
  privacy_tier: cloud-ok
  weight: 0.5
---
You are Legacy, a persona defined before contract v2 existed.
"#;

    const V2_FULL_SOUL: &str = r#"---
name: Guardian
description: Full contract v2 persona
bastion:
  privacy_tier: local-only
  weight: 0.8
skills:
  - budgeting
objectives:
  - Keep the household's finances honest
goals:
  - Never let a bill go unpaid
tools:
  - memory_search
  - goal_create
scope: Household finance only — no medical or legal advice.
---
You are Guardian.
"#;

    #[test]
    fn parse_v1_legacy_soul_still_works_with_v2_fields_defaulted() {
        let (front, _body) = parse_soul(V1_LEGACY_SOUL).expect("legacy SOUL must still parse");
        assert!(front.objectives.is_empty());
        assert!(front.goals.is_empty());
        assert!(
            front.tools.is_none(),
            "absent `tools:` must default to None (unrestricted)"
        );
        assert!(front.scope.is_none());
    }

    #[test]
    fn parse_v2_full_soul_populates_all_contract_fields() {
        let (front, body) = parse_soul(V2_FULL_SOUL).expect("v2 SOUL must parse");
        assert_eq!(front.name, "Guardian");
        assert_eq!(
            front.objectives,
            vec!["Keep the household's finances honest"]
        );
        assert_eq!(front.goals, vec!["Never let a bill go unpaid"]);
        assert_eq!(
            front.tools,
            Some(vec!["memory_search".to_string(), "goal_create".to_string()])
        );
        assert_eq!(
            front.scope.as_deref(),
            Some("Household finance only — no medical or legal advice.")
        );
        assert!(body.contains("You are Guardian"));
    }

    #[test]
    fn validate_passes_for_complete_v2_contract() {
        let (front, _) = parse_soul(V2_FULL_SOUL).expect("parse failed");
        assert!(front.validate().is_ok());
    }

    #[test]
    fn validate_reports_every_problem_for_legacy_soul() {
        // A legacy (pre-v2) SOUL.md is a VALID parse (back-compat), but
        // `validate()` should surface every missing contract-v2 field —
        // this is the loud path, never a parse failure.
        let (front, _) = parse_soul(V1_LEGACY_SOUL).expect("parse failed");
        let problems = front
            .validate()
            .expect_err("legacy SOUL should fail validate()");
        assert!(problems.iter().any(|p| p.contains("objectives")));
        assert!(problems.iter().any(|p| p.contains("goals")));
        assert!(problems.iter().any(|p| p.contains("scope")));
        // `tools: None` is valid/unrestricted — must NOT be reported as a problem.
        assert!(!problems.iter().any(|p| p.contains("tools")));
    }

    #[test]
    fn validate_flags_explicit_empty_tools_allowlist_as_suspicious() {
        let soul = r#"---
name: Empty
bastion:
  privacy_tier: cloud-ok
  weight: 0.5
objectives:
  - something
goals:
  - something
tools: []
scope: somewhere
---
Body.
"#;
        let (front, _) = parse_soul(soul).expect("parse failed");
        assert_eq!(front.tools, Some(vec![]));
        let problems = front
            .validate()
            .expect_err("Some([]) tools must be flagged");
        assert!(problems.iter().any(|p| p.contains("tools")));
    }

    #[test]
    fn validate_ok_when_tools_absent_unrestricted() {
        let (front, _) = parse_soul(
            r#"---
name: Unrestricted
bastion:
  privacy_tier: cloud-ok
  weight: 0.5
objectives:
  - something
goals:
  - something
scope: everywhere
---
Body.
"#,
        )
        .expect("parse failed");
        assert!(front.tools.is_none());
        assert!(front.validate().is_ok());
    }

    #[test]
    fn parse_error_on_missing_front_matter() {
        let bad = "This is just prose, no front-matter.";
        assert!(parse_soul(bad).is_err());
    }

    #[test]
    fn parse_error_on_unterminated_front_matter() {
        let bad = "---\nname: Bob\nbastion:\n  privacy_tier: cloud-ok\n  weight: 0.5\n";
        assert!(parse_soul(bad).is_err());
    }
}
