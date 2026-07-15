//! Input guardrail — screens malformed or oversized input before routing (HOOK-02).
//!
//! NOTE: This is NOT an injection defense. Injection is blocked at the egress layer
//! (see `egress.rs` and AI-SPEC §6). Content-level injection filtering is unreliable
//! and must not be relied upon for security. This guardrail's job is structural:
//! reject empty, oversized, or control-char-spam input that would poison downstream
//! processing or cause resource exhaustion (T-02-15).

/// Default maximum input length in bytes.
pub const DEFAULT_MAX_LEN: usize = 16_384;

/// Screens input strings before they are routed to a provider (HOOK-02).
///
/// Rejects:
/// - Empty input
/// - Input exceeding `max_len` bytes
/// - Input dominated by non-printable / control characters (spam/binary garbage)
///
/// NOTE: This guardrail does NOT defend against prompt injection — that is handled
/// at the egress layer (fail-closed, independent of content). Input filtering of
/// injection is unreliable and is explicitly out of scope here (AI-SPEC §6).
pub struct InputGuardrail {
    pub max_len: usize,
}

impl Default for InputGuardrail {
    fn default() -> Self {
        Self {
            max_len: DEFAULT_MAX_LEN,
        }
    }
}

impl InputGuardrail {
    pub fn new(max_len: usize) -> Self {
        Self { max_len }
    }

    /// Screen `input` and return `Ok(())` if it passes all structural checks.
    /// Returns `Err(BastionError::InputGuardrailRejected(...))` on rejection (WR-09).
    /// The rejection detail is safe to log but MUST NOT be echoed to channel callers.
    pub fn screen(&self, input: &str) -> anyhow::Result<()> {
        use crate::types::BastionError;
        if input.is_empty() {
            return Err(anyhow::anyhow!(BastionError::InputGuardrailRejected(
                "input is empty".to_owned()
            )));
        }
        if input.len() > self.max_len {
            return Err(anyhow::anyhow!(BastionError::InputGuardrailRejected(
                format!(
                    "input length {} exceeds maximum {} bytes",
                    input.len(),
                    self.max_len
                )
            )));
        }
        // Reject input where >50% of characters are ASCII control chars (excluding
        // common whitespace \t \n \r). This catches binary garbage or control-char spam.
        let control_count = input
            .chars()
            .filter(|&c| c.is_ascii_control() && c != '\t' && c != '\n' && c != '\r')
            .count();
        let total_count = input.chars().count();
        if total_count > 0 && control_count * 2 > total_count {
            return Err(anyhow::anyhow!(BastionError::InputGuardrailRejected(
                format!(
                    "input contains too many control characters ({}/{})",
                    control_count, total_count
                )
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_input() {
        use crate::types::BastionError;
        let g = InputGuardrail::default();
        assert!(g.screen("").is_err());
        let err = g.screen("").unwrap_err();
        // Must be a typed InputGuardrailRejected, not a bare string (WR-09)
        assert!(
            err.downcast_ref::<BastionError>().is_some(),
            "must be BastionError; got: {err}"
        );
        let err_str = err.to_string();
        assert!(err_str.contains("empty"), "got: {err_str}");
    }

    #[test]
    fn rejects_oversized_input() {
        use crate::types::BastionError;
        let g = InputGuardrail::new(10);
        let long_input = "a".repeat(11);
        let result = g.screen(&long_input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.downcast_ref::<BastionError>().is_some(),
            "must be BastionError; got: {err}"
        );
        let err_str = err.to_string();
        assert!(err_str.contains("exceeds maximum"), "got: {err_str}");
    }

    #[test]
    fn allows_normal_input() {
        let g = InputGuardrail::default();
        assert!(g.screen("Hello, what's the weather today?").is_ok());
    }

    #[test]
    fn allows_input_at_exact_max_len() {
        let g = InputGuardrail::new(5);
        assert!(g.screen("hello").is_ok());
    }

    #[test]
    fn rejects_control_char_spam() {
        let g = InputGuardrail::default();
        // 20 control chars + 5 normal chars → >50% control → rejected
        let spam = "\x01".repeat(20) + "hello";
        assert!(g.screen(&spam).is_err());
    }

    #[test]
    fn allows_input_with_normal_whitespace() {
        let g = InputGuardrail::default();
        assert!(g.screen("line one\nline two\ttabbed").is_ok());
    }
}
