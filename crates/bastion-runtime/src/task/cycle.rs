//! The adaptive cycle engine (US-103): `Choose → Act → Observe → Verify →
//! Adapt`, driven from persisted [`TaskCase`] state with no plan graph.
//!
//! After every observation the engine recomputes the next step from current
//! state — it never walks a fixed plan. A text plan may exist as an artifact
//! the [`Chooser`] consults, but it is never the authoritative source of what
//! happens next.
//!
//! Termination is always typed. The loop resolves, in priority order:
//! `complete → approval/park → budget → (chooser: retry / alternative) →
//! escalate / impossible`. Every external effect is executed through the
//! [`TaskExecutor`] port, which is where capability/approval/egress apply —
//! the engine assumes that boundary and never calls out directly.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::hooks::Observer;

use super::ports::{ActionOutcome, ChosenStep, Chooser, CycleHistory, TaskExecutor, Verifier};
use super::store::TaskStore;
use super::{
    Attempt, AttemptId, BudgetKind, StopReason, TaskCase, TaskCaseId, TaskLifecycleEvent,
    TaskStatus, VerificationStatus,
};

/// Absolute ceiling on attempts when a task declares no `max_steps`, so a
/// task can never run forever (US-208). A task that wants more must say so via
/// [`super::Bounds::max_steps`].
const DEFAULT_STEP_CEILING: u32 = 100;

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

/// Drives one [`TaskCase`] through its adaptive lifecycle over the three host
/// ports, persisting progress to a [`TaskStore`] and emitting neutral
/// lifecycle events.
#[derive(Clone)]
pub struct AdaptiveCycle {
    store: Arc<dyn TaskStore>,
    chooser: Arc<dyn Chooser>,
    executor: Arc<dyn TaskExecutor>,
    verifier: Arc<dyn Verifier>,
    observer: Arc<dyn Observer>,
    counter: Arc<AtomicU64>,
}

impl AdaptiveCycle {
    pub fn new(
        store: Arc<dyn TaskStore>,
        chooser: Arc<dyn Chooser>,
        executor: Arc<dyn TaskExecutor>,
        verifier: Arc<dyn Verifier>,
        observer: Arc<dyn Observer>,
    ) -> Self {
        Self {
            store,
            chooser,
            executor,
            verifier,
            observer,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn gen_id(&self, prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            now_nanos(),
            self.counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    async fn emit(&self, event: TaskLifecycleEvent) {
        self.observer.record(event.event_name(), event.metadata()).await;
    }

    /// Run the case to a terminal or parked (`AwaitingApproval`/`Paused`)
    /// status, returning the status reached. `cancel`, if provided, is polled
    /// between steps: setting it cooperatively cancels the task (the executor
    /// is asked to cancel in-flight work, so nothing is orphaned).
    pub async fn run(
        &self,
        owner: &str,
        case_id: &TaskCaseId,
        cancel: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<TaskStatus> {
        let start = Instant::now();

        loop {
            let mut case = self
                .store
                .load_case(owner, case_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("adaptive cycle: case {case_id} not found for owner"))?;
            let mut rev = case.revision;

            // Externally-driven terminal/parked states end the drive.
            if case.status.is_terminal() {
                return Ok(case.status);
            }
            if matches!(case.status, TaskStatus::Paused | TaskStatus::AwaitingApproval) {
                return Ok(case.status);
            }

            // Cooperative cancellation between steps.
            if cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                let _ = self.executor.cancel(&case).await;
                self.store
                    .transition_status(owner, case_id, TaskStatus::Cancelled, Some(StopReason::Cancelled), rev)
                    .await?;
                self.emit(TaskLifecycleEvent::Terminal {
                    owner: owner.to_string(),
                    task: case_id.clone(),
                    status: TaskStatus::Cancelled,
                    stop_reason: StopReason::Cancelled,
                })
                .await;
                return Ok(TaskStatus::Cancelled);
            }

            // Budget: wall clock, then step count (with a hard default ceiling).
            let attempt_count = case.attempts.len() as u32;
            let wall_ms = start.elapsed().as_millis() as u64;
            if let Some(kind) = over_budget(&case, attempt_count, wall_ms) {
                return self
                    .finish(owner, case_id, TaskStatus::Failed, StopReason::BudgetExceeded(kind), rev)
                    .await;
            }

            // Ensure the case is marked Running before the first step.
            if case.status == TaskStatus::Pending {
                rev = self
                    .store
                    .transition_status(owner, case_id, TaskStatus::Running, None, rev)
                    .await?;
                self.emit(TaskLifecycleEvent::StatusChanged {
                    owner: owner.to_string(),
                    task: case_id.clone(),
                    status: TaskStatus::Running,
                })
                .await;
                case.status = TaskStatus::Running;
            }

            let last_verdict = self.last_verdict(owner, &case).await?;
            let history = CycleHistory {
                last_verdict: last_verdict.as_ref(),
                attempt_count,
                usage: &case.usage,
            };

            match self.chooser.choose(&case, &history).await? {
                ChosenStep::Complete => {
                    // No "done" without proof: require a succeeding verdict.
                    match last_verdict.as_ref().map(|v| v.status) {
                        Some(VerificationStatus::Succeeded) => {
                            return self
                                .finish(owner, case_id, TaskStatus::Completed, StopReason::Completed, rev)
                                .await;
                        }
                        _ => {
                            let reason = "completion claimed without a succeeding verdict".to_string();
                            return self
                                .finish(owner, case_id, TaskStatus::Escalated, StopReason::Escalated(reason), rev)
                                .await;
                        }
                    }
                }
                ChosenStep::Escalate(reason) => {
                    return self
                        .finish(owner, case_id, TaskStatus::Escalated, StopReason::Escalated(reason), rev)
                        .await;
                }
                ChosenStep::Impossible(reason) => {
                    return self
                        .finish(owner, case_id, TaskStatus::Failed, StopReason::Impossible(reason), rev)
                        .await;
                }
                ChosenStep::Act(action) => {
                    let attempt_id = AttemptId(self.gen_id("attempt"));
                    self.emit(TaskLifecycleEvent::AttemptStarted {
                        owner: owner.to_string(),
                        task: case_id.clone(),
                        attempt: attempt_id.clone(),
                    })
                    .await;
                    self.emit(TaskLifecycleEvent::ActionChosen {
                        owner: owner.to_string(),
                        task: case_id.clone(),
                        attempt: attempt_id.clone(),
                        action: action.id.clone(),
                    })
                    .await;

                    let outcome = match self.executor.execute(&action, &case).await {
                        Ok(o) => o,
                        Err(e) => {
                            let reason = format!("executor error: {e}");
                            return self
                                .finish(owner, case_id, TaskStatus::Failed, StopReason::Impossible(reason), rev)
                                .await;
                        }
                    };
                    let ActionOutcome {
                        mut evidence,
                        usage: step_usage,
                        pending_approval,
                    } = outcome;

                    // The engine owns identity: stamp each piece of evidence
                    // with the attempt/action it belongs to, so the executor
                    // need not know the ids the cycle just minted.
                    for ev in evidence.iter_mut() {
                        ev.attempt = attempt_id.clone();
                        if ev.action.is_none() {
                            ev.action = Some(action.id.clone());
                        }
                    }

                    self.emit(TaskLifecycleEvent::ActionObserved {
                        owner: owner.to_string(),
                        task: case_id.clone(),
                        attempt: attempt_id.clone(),
                        action: action.id.clone(),
                    })
                    .await;

                    // Fold usage and record the attempt id on the case.
                    case.usage.merge_from(&step_usage);
                    case.usage.steps = case.usage.steps.saturating_add(1);
                    case.attempts.push(attempt_id.clone());

                    if let Some(approval) = pending_approval {
                        // Parked before a verdict: persist the in-flight attempt
                        // (verdict-less) once, then its evidence, then park.
                        let attempt = Attempt {
                            id: attempt_id.clone(),
                            task: case_id.clone(),
                            started_at: now_nanos(),
                            ended_at: None,
                            actions: vec![action.id.clone()],
                            belief_refs: action.belief_refs.clone(),
                            usage: step_usage,
                            verdict: None,
                        };
                        self.store.append_attempt(&attempt).await?;
                        for ev in &evidence {
                            self.store.record_evidence(owner, ev).await?;
                        }
                        case.pending_approvals.push(approval.clone());
                        rev = self.store.update_case(&case, rev).await?;
                        self.store
                            .transition_status(owner, case_id, TaskStatus::AwaitingApproval, None, rev)
                            .await?;
                        self.emit(TaskLifecycleEvent::ApprovalPending {
                            owner: owner.to_string(),
                            task: case_id.clone(),
                            approval,
                        })
                        .await;
                        self.emit(TaskLifecycleEvent::StatusChanged {
                            owner: owner.to_string(),
                            task: case_id.clone(),
                            status: TaskStatus::AwaitingApproval,
                        })
                        .await;
                        return Ok(TaskStatus::AwaitingApproval);
                    }

                    // Verify the evidence, then persist the completed attempt
                    // ONCE (with its verdict) so evidence can resolve to it.
                    let verdict = self.verifier.verify(&case, &attempt_id, &evidence).await?;
                    let status = verdict.status;
                    let attempt = Attempt {
                        id: attempt_id.clone(),
                        task: case_id.clone(),
                        started_at: now_nanos(),
                        ended_at: Some(now_nanos()),
                        actions: vec![action.id.clone()],
                        belief_refs: action.belief_refs.clone(),
                        usage: step_usage,
                        verdict: Some(verdict),
                    };
                    self.store.append_attempt(&attempt).await?;
                    for ev in &evidence {
                        self.store.record_evidence(owner, ev).await?;
                    }
                    self.emit(TaskLifecycleEvent::Verified {
                        owner: owner.to_string(),
                        task: case_id.clone(),
                        attempt: attempt_id.clone(),
                        status,
                    })
                    .await;

                    self.store.update_case(&case, rev).await?;
                    self.emit(TaskLifecycleEvent::Adapted {
                        owner: owner.to_string(),
                        task: case_id.clone(),
                        attempt: attempt_id,
                    })
                    .await;
                    // Loop: the chooser adapts on the next iteration using the
                    // verdict just recorded.
                }
            }
        }
    }

    /// Fetch the most recent attempt's verdict for this case (attempts are
    /// listed oldest-first).
    async fn last_verdict(&self, owner: &str, case: &TaskCase) -> anyhow::Result<Option<super::Verdict>> {
        let attempts = self.store.list_attempts_for_case(owner, &case.id).await?;
        Ok(attempts.into_iter().rev().find_map(|a| a.verdict))
    }

    /// Apply a terminal transition and emit the single terminal event.
    async fn finish(
        &self,
        owner: &str,
        case_id: &TaskCaseId,
        status: TaskStatus,
        stop_reason: StopReason,
        rev: u64,
    ) -> anyhow::Result<TaskStatus> {
        self.store
            .transition_status(owner, case_id, status, Some(stop_reason.clone()), rev)
            .await?;
        self.emit(TaskLifecycleEvent::Terminal {
            owner: owner.to_string(),
            task: case_id.clone(),
            status,
            stop_reason,
        })
        .await;
        Ok(status)
    }
}

/// Which budget dimension (if any) the case has exceeded. Wall clock is
/// checked first, then the step count against `max_steps` or the default
/// ceiling. Token/money limits are checked against accrued usage.
fn over_budget(case: &TaskCase, attempt_count: u32, wall_ms: u64) -> Option<BudgetKind> {
    let b = &case.bounds;
    if let Some(max) = b.max_wall_clock_ms {
        if wall_ms >= max {
            return Some(BudgetKind::WallClock);
        }
    }
    let step_ceiling = b.max_steps.unwrap_or(DEFAULT_STEP_CEILING);
    if attempt_count >= step_ceiling {
        return Some(BudgetKind::Steps);
    }
    if let Some(max) = b.max_tokens {
        let total = case.usage.input_tokens.saturating_add(case.usage.output_tokens);
        if total >= max {
            return Some(BudgetKind::Tokens);
        }
    }
    if let (Some(max), Some(spent)) = (b.max_cost_usd, case.usage.cost_usd) {
        if spent >= max {
            return Some(BudgetKind::Money);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::Observer;
    use crate::task::*;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicU32;
    use tempfile::NamedTempFile;

    struct NullObs;
    #[async_trait]
    impl Observer for NullObs {
        async fn record(&self, _event: &str, _metadata: serde_json::Value) {}
    }

    /// Acts `acts` times, then reports `Complete`.
    struct StepChooser {
        acts: u32,
        calls: AtomicU32,
    }
    #[async_trait]
    impl Chooser for StepChooser {
        async fn choose(
            &self,
            _case: &TaskCase,
            _history: &CycleHistory<'_>,
        ) -> anyhow::Result<ChosenStep> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed);
            if n < self.acts {
                Ok(ChosenStep::Act(act(&format!("act-{n}"))))
            } else {
                Ok(ChosenStep::Complete)
            }
        }
    }

    /// Never completes — used to exercise the step ceiling.
    struct AlwaysAct;
    #[async_trait]
    impl Chooser for AlwaysAct {
        async fn choose(
            &self,
            _case: &TaskCase,
            _history: &CycleHistory<'_>,
        ) -> anyhow::Result<ChosenStep> {
            Ok(ChosenStep::Act(act("a")))
        }
    }

    struct Escalator;
    #[async_trait]
    impl Chooser for Escalator {
        async fn choose(
            &self,
            _case: &TaskCase,
            _history: &CycleHistory<'_>,
        ) -> anyhow::Result<ChosenStep> {
            Ok(ChosenStep::Escalate("nope".into()))
        }
    }

    /// Produces one piece of evidence and no approval.
    struct OkExecutor;
    #[async_trait]
    impl TaskExecutor for OkExecutor {
        async fn execute(
            &self,
            _action: &CandidateAction,
            _case: &TaskCase,
        ) -> anyhow::Result<ActionOutcome> {
            Ok(ActionOutcome {
                evidence: vec![Evidence {
                    id: EvidenceId(String::new()),
                    // stamped by the cycle:
                    attempt: AttemptId(String::new()),
                    action: None,
                    kind: EvidenceKind::Observation,
                    source_ref: ArtifactRef("art".into()),
                    trusted: true,
                    max_tier: None,
                    captured_at: 0,
                }],
                usage: UsageAccum::default(),
                pending_approval: None,
            })
        }
    }

    struct FixedVerifier(VerificationStatus);
    #[async_trait]
    impl Verifier for FixedVerifier {
        async fn verify(
            &self,
            _case: &TaskCase,
            attempt: &AttemptId,
            _evidence: &[Evidence],
        ) -> anyhow::Result<Verdict> {
            Ok(Verdict {
                attempt: attempt.clone(),
                status: self.0,
                provenance: VerdictProvenance::Deterministic,
                evidence: vec![],
                detail: None,
            })
        }
    }

    fn act(id: &str) -> CandidateAction {
        CandidateAction {
            id: ActionId(id.to_string()),
            kind: ActionKind::Respond,
            rationale: String::new(),
            belief_refs: vec![],
        }
    }

    async fn seed(bounds: Bounds) -> (NamedTempFile, Arc<SqliteTaskStore>, TaskCaseId) {
        let f = NamedTempFile::new().expect("tempfile");
        let store = SqliteTaskStore::new(f.path().to_str().unwrap());
        store.init_schema().await.expect("init");
        let id = TaskCaseId("t1".into());
        let case = TaskCase {
            id: id.clone(),
            owner: "alice".into(),
            mode: ExecutionMode::Pursue,
            intent: Intent {
                owner: "alice".into(),
                mode: ExecutionMode::Pursue,
                summary: "do".into(),
                origin: IntentOrigin::Message,
            },
            frame: Frame {
                objective: "obj".into(),
                acceptance: vec![],
                context_refs: vec![],
            },
            bounds,
            status: TaskStatus::Pending,
            stop_reason: None,
            attempts: vec![],
            pending_approvals: vec![],
            next_decision: None,
            usage: UsageAccum::default(),
            parent: None,
            correlation: CorrelationIds::default(),
            business_state: OpaqueState::default(),
            created_at: 0,
            updated_at: 0,
            revision: 1,
        };
        store.create_case(&case, "key").await.expect("create");
        (f, Arc::new(store), id)
    }

    #[tokio::test]
    async fn completes_after_a_succeeding_verdict() {
        let (_f, store, id) = seed(Bounds::default()).await;
        let cycle = AdaptiveCycle::new(
            store.clone(),
            Arc::new(StepChooser {
                acts: 1,
                calls: AtomicU32::new(0),
            }),
            Arc::new(OkExecutor),
            Arc::new(FixedVerifier(VerificationStatus::Succeeded)),
            Arc::new(NullObs),
        );
        let status = cycle.run("alice", &id, None).await.expect("run");
        assert_eq!(status, TaskStatus::Completed);

        let case = store.load_case("alice", &id).await.unwrap().unwrap();
        assert_eq!(case.status, TaskStatus::Completed);
        assert_eq!(case.attempts.len(), 1);
        assert!(matches!(case.stop_reason, Some(StopReason::Completed)));
    }

    #[tokio::test]
    async fn stops_on_step_ceiling() {
        let bounds = Bounds {
            max_steps: Some(2),
            ..Bounds::default()
        };
        let (_f, store, id) = seed(bounds).await;
        let cycle = AdaptiveCycle::new(
            store.clone(),
            Arc::new(AlwaysAct),
            Arc::new(OkExecutor),
            Arc::new(FixedVerifier(VerificationStatus::Unverified)),
            Arc::new(NullObs),
        );
        let status = cycle.run("alice", &id, None).await.expect("run");
        assert_eq!(status, TaskStatus::Failed);

        let case = store.load_case("alice", &id).await.unwrap().unwrap();
        assert!(matches!(
            case.stop_reason,
            Some(StopReason::BudgetExceeded(BudgetKind::Steps))
        ));
        assert_eq!(case.attempts.len(), 2);
    }

    #[tokio::test]
    async fn escalates_when_chooser_escalates() {
        let (_f, store, id) = seed(Bounds::default()).await;
        let cycle = AdaptiveCycle::new(
            store.clone(),
            Arc::new(Escalator),
            Arc::new(OkExecutor),
            Arc::new(FixedVerifier(VerificationStatus::Unverified)),
            Arc::new(NullObs),
        );
        let status = cycle.run("alice", &id, None).await.expect("run");
        assert_eq!(status, TaskStatus::Escalated);

        let case = store.load_case("alice", &id).await.unwrap().unwrap();
        assert!(matches!(case.stop_reason, Some(StopReason::Escalated(_))));
    }
}
