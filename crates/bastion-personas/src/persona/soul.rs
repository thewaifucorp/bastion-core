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
#[derive(Debug, Clone, Deserialize)]
pub struct PersonaFront {
    pub name: String,
    pub description: Option<String>,
    pub bastion: BastionBlock,
    #[serde(default)]
    pub skills: Vec<String>,
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
