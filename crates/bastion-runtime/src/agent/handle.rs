use tokio::sync::{mpsc, oneshot};

/// A single request sent through the AgentHandle.
///
/// `reply` carries a typed `Result` so real errors propagate back to the caller (WR-10).
/// The channel layer (e.g. `webhook::error_status`) can then classify the error correctly
/// instead of receiving a generic "reply dropped" anyhow string.
pub struct AgentRequest {
    pub text: String,
    pub owner: String,
    /// SEC-05 (D-09): true when this request's content originates from an
    /// untrusted source — received email content (always), or a Discord/Slack
    /// message from a public (non-DM) context. Threaded into
    /// `AgentLoop::run_turn_for_with_trust`, which quarantines the turn's
    /// LLM-facing tool dispatch (zero visible capabilities) for its duration.
    /// `false` (the default via `ask()`) preserves every pre-existing
    /// channel's behavior unchanged.
    pub untrusted: bool,
    pub reply: oneshot::Sender<anyhow::Result<String>>,
}

/// A clonable handle that serializes all inbound messages into ONE AgentLoop task.
///
/// Multiple channels (Telegram, webhook, proactive queue) each hold a clone of this handle.
/// All sends funnel into a single `mpsc::Receiver<AgentRequest>` drained by the AgentLoop,
/// preserving the Phase-1 single-turn invariant.
#[derive(Clone)]
pub struct AgentHandle {
    tx: mpsc::Sender<AgentRequest>,
}

/// Construct a (handle, receiver) pair.  The receiver is given to the AgentLoop task.
pub fn channel() -> (AgentHandle, mpsc::Receiver<AgentRequest>) {
    let (tx, rx) = mpsc::channel(32);
    (AgentHandle { tx }, rx)
}

impl AgentHandle {
    /// Send `text` from `owner` to the serialized AgentLoop and await its reply.
    ///
    /// Returns the typed result from the AgentLoop — callers receive real `BastionError`
    /// variants (e.g. PrivacyEgressBlocked, InputGuardrailRejected) so the channel layer
    /// can map them to correct HTTP/transport status codes (WR-10).
    ///
    /// Byte-identical to today's behavior — a thin wrapper over
    /// `ask_with_trust(text, owner, false)` (SEC-05).
    pub async fn ask(&self, text: String, owner: String) -> anyhow::Result<String> {
        self.ask_with_trust(text, owner, false).await
    }

    /// Like `ask()`, but explicitly marks the request's trust classification
    /// (SEC-05/D-09). `untrusted: true` is threaded through to
    /// `AgentLoop::run_turn_for_with_trust`, which quarantines the turn's
    /// LLM-facing tool dispatch for its whole duration. Every pre-existing
    /// call site keeps calling `ask()` (which always passes `false`) and is
    /// completely unaffected.
    pub async fn ask_with_trust(
        &self,
        text: String,
        owner: String,
        untrusted: bool,
    ) -> anyhow::Result<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(AgentRequest {
                text,
                owner,
                untrusted,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("AgentLoop receiver dropped"))?;
        // Unwrap the outer oneshot (channel dropped = agent crashed) then the inner Result.
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("AgentLoop reply dropped"))?
    }
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::task;

    /// Spawn a stub consumer that drains the receiver sequentially, echoing each message.
    /// Returns a vec that accumulates the received (text, owner) pairs in order.
    fn spawn_stub_consumer(
        mut rx: mpsc::Receiver<AgentRequest>,
    ) -> Arc<Mutex<Vec<(String, String)>>> {
        let log: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = log.clone();
        task::spawn(async move {
            while let Some(req) = rx.recv().await {
                log_clone
                    .lock()
                    .unwrap()
                    .push((req.text.clone(), req.owner.clone()));
                let _ = req.reply.send(Ok(format!("echo:{}", req.text)));
            }
        });
        log
    }

    // --- Plan 11-08 (SEC-05): AgentRequest.untrusted + ask_with_trust --------

    /// Test 1/2: `ask()` (existing method) produces an `AgentRequest` with
    /// `untrusted: false` — byte-identical to today's behavior, internally a
    /// thin wrapper over `ask_with_trust(..., false)`.
    #[tokio::test]
    async fn ask_produces_agent_request_with_untrusted_false() {
        let (handle, mut rx) = channel();
        let h = handle.clone();
        task::spawn(async move {
            let _ = h.ask("hi".into(), "alice".into()).await;
        });
        let req = rx.recv().await.expect("request must arrive");
        assert!(
            !req.untrusted,
            "ask() must default untrusted to false, unchanged from today"
        );
        let _ = req.reply.send(Ok("ok".into()));
    }

    /// Test 2: `ask_with_trust(text, owner, true)` results in an
    /// `AgentRequest` with `untrusted: true` reaching the consumer.
    #[tokio::test]
    async fn ask_with_trust_true_produces_agent_request_with_untrusted_true() {
        let (handle, mut rx) = channel();
        let h = handle.clone();
        task::spawn(async move {
            let _ = h.ask_with_trust("hi".into(), "alice".into(), true).await;
        });
        let req = rx.recv().await.expect("request must arrive");
        assert!(
            req.untrusted,
            "ask_with_trust(..., true) must set untrusted: true"
        );
        let _ = req.reply.send(Ok("ok".into()));
    }

    #[tokio::test]
    async fn two_concurrent_clones_both_get_replies() {
        let (handle, rx) = channel();
        let log = spawn_stub_consumer(rx);

        let h1 = handle.clone();
        let h2 = handle.clone();

        // Fire both tasks concurrently.
        let (r1, r2) = tokio::join!(
            async move { h1.ask("hello".into(), "alice".into()).await.unwrap() },
            async move { h2.ask("world".into(), "bob".into()).await.unwrap() },
        );

        assert!(r1.starts_with("echo:"), "r1={r1}");
        assert!(r2.starts_with("echo:"), "r2={r2}");

        // Consumer processed both one-at-a-time (log has exactly 2 entries).
        let entries = log.lock().unwrap();
        assert_eq!(
            entries.len(),
            2,
            "expected 2 processed entries, got {entries:?}"
        );
    }
}
