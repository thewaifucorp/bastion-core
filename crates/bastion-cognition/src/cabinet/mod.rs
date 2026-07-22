//! Cabinet deliberation orchestrator (CAB-01, CAB-03, CAB-05, PRIV-04, GOAL-04).
//!
//! The Cabinet is the bounded multi-persona deliberation engine. It:
//! - Runs D-06 bounded rounds (DEFAULT=2, MAX=3): R1 positions, R2 replies, R3 forced synthesis.
//! - Applies PRIV-04 mixed-tier downgrade via `policy::table_tier` before any provider call.
//! - Tags every transcript turn by the persona's returned `PersonaId` (CF-3 / Pitfall 4).
//! - Invokes `hooks::egress::check_egress` before each provider call (fail-closed, CF-1).
//! - Includes the guardian persona when `RouterDecision.convene_reason == GoalImpact` (GOAL-04).

pub mod orchestrator;
pub mod policy;
pub mod synth;

use crate::memory::PrivacyTier;
use crate::types::{ConveneReason, Persona, PersonaId, RouterDecision};

/// The set of personas convened for a single Cabinet deliberation, plus
/// the resolved tier for this deliberation (may be downgraded by policy::table_tier).
#[derive(Debug, Clone)]
pub struct CabinetTable {
    pub personas: Vec<Persona>,
    /// Effective tier for THIS deliberation (D-02: not persisted to registry).
    pub tier: PrivacyTier,
}

/// A single turn in the Cabinet deliberation transcript.
#[derive(Debug, Clone)]
pub struct Turn {
    /// The persona that produced this turn — tagged by RETURNED PersonaId (CF-3 / Pitfall 4).
    pub persona: PersonaId,
    pub kind: TurnKind,
    pub text: String,
}

/// Whether this turn is a first-round position or a second-round reply.
#[derive(Debug, Clone, PartialEq)]
pub enum TurnKind {
    Position,
    Reply,
}

/// Build a `CabinetTable` from a `RouterDecision`, applying:
/// 1. GOAL-04: add the guardian persona when `convene_reason == GoalImpact`.
/// 2. PRIV-04: resolve effective tier via `policy::table_tier` (D-01, D-02).
///
/// `lookup` resolves a persona name to its (cloned) `Persona` data — M2 step 6:
/// this used to take `&PersonaRegistry` directly, but `PersonaRegistry` is a
/// behavior-bearing type (`load_dir`'s filesystem scan) owned by
/// `bastion-personas`, and `bastion-personas` depends on `bastion-cognition`
/// (which owns this Cabinet code) for `PersonaResponder`'s deliberation calls —
/// a direct `&PersonaRegistry` param here would create a crate cycle. Inverting
/// to a plain `Fn(&str) -> Option<Persona>` closure lets the one production
/// caller (`persona::responder::PersonaResponder`, which already owns the
/// registry) resolve names itself and hand this function only the pure
/// `Persona` data it actually needs — identical behavior, no registry type
/// crossing the crate boundary.
///
/// Returns an error if any requested persona is missing (`lookup` returns `None`).
pub fn build_table<F>(
    lookup: F,
    decision: &RouterDecision,
    guardian_name: Option<&str>,
) -> anyhow::Result<CabinetTable>
where
    F: Fn(&str) -> Option<Persona>,
{
    let mut names: Vec<String> = decision.personas.clone();

    // GOAL-04: include the guardian persona when convene_reason is GoalImpact.
    if decision.convene_reason == Some(ConveneReason::GoalImpact) {
        if let Some(guardian) = guardian_name {
            if !names.contains(&guardian.to_string()) {
                names.push(guardian.to_string());
            }
        }
    }

    let mut personas: Vec<Persona> = Vec::with_capacity(names.len());
    for name in &names {
        let p = lookup(name)
            .ok_or_else(|| anyhow::anyhow!("persona '{}' not found in registry", name))?;
        personas.push(p);
    }

    let tiers: Vec<PrivacyTier> = personas.iter().map(|p| p.tier).collect();
    let tier = policy::table_tier(&tiers);

    Ok(CabinetTable { personas, tier })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PrivacyTier;
    use crate::types::{ConveneReason, ResponseMode, RouterDecision};
    use std::collections::HashMap;

    fn make_persona(name: &str, tier: PrivacyTier) -> Persona {
        Persona {
            name: name.to_string(),
            description: None,
            system_prompt: format!("You are {name}."),
            tier,
            weight: 0.5,
            skills: vec![],
            ..Default::default()
        }
    }

    /// M2 step 6: a plain `HashMap` fixture stands in for `PersonaRegistry` —
    /// `build_table` only needs a `Fn(&str) -> Option<Persona>` lookup now
    /// (see `build_table`'s doc comment), so these tests no longer need
    /// `bastion-personas`'s registry type at all.
    fn make_registry(personas: Vec<Persona>) -> HashMap<String, Persona> {
        let mut map = HashMap::new();
        for p in personas {
            map.insert(p.name.clone(), p);
        }
        map
    }

    fn cabinet_decision_with_reason(
        personas: &[&str],
        reason: Option<ConveneReason>,
    ) -> RouterDecision {
        RouterDecision {
            personas: personas.iter().map(|s| s.to_string()).collect(),
            owner: "user1".to_string(),
            mode: ResponseMode::Cabinet,
            convene_reason: reason,
        }
    }

    #[test]
    fn build_table_all_cloud_ok() {
        let registry = make_registry(vec![
            make_persona("Aria", PrivacyTier::CloudOk),
            make_persona("Finance", PrivacyTier::CloudOk),
        ]);
        let decision = cabinet_decision_with_reason(&["Aria", "Finance"], None);
        let table = build_table(|name| registry.get(name).cloned(), &decision, None).unwrap();
        assert_eq!(table.tier, PrivacyTier::CloudOk);
        assert_eq!(table.personas.len(), 2);
    }

    #[test]
    fn build_table_mixed_tier_downgrades_to_local_only() {
        let registry = make_registry(vec![
            make_persona("Aria", PrivacyTier::CloudOk),
            make_persona("Saude", PrivacyTier::LocalOnly),
        ]);
        let decision = cabinet_decision_with_reason(&["Aria", "Saude"], None);
        let table = build_table(|name| registry.get(name).cloned(), &decision, None).unwrap();
        // PRIV-04: any LocalOnly → whole table LocalOnly
        assert_eq!(table.tier, PrivacyTier::LocalOnly);
    }

    #[test]
    fn build_table_goal_impact_adds_guardian() {
        let registry = make_registry(vec![
            make_persona("Aria", PrivacyTier::CloudOk),
            make_persona("Guardian", PrivacyTier::CloudOk),
        ]);
        let decision = cabinet_decision_with_reason(&["Aria"], Some(ConveneReason::GoalImpact));
        let table = build_table(
            |name| registry.get(name).cloned(),
            &decision,
            Some("Guardian"),
        )
        .unwrap();
        // GOAL-04: guardian must be included
        assert!(table.personas.iter().any(|p| p.name == "Guardian"));
        assert_eq!(table.personas.len(), 2);
    }

    #[test]
    fn build_table_goal_impact_no_duplicate_guardian() {
        let registry = make_registry(vec![
            make_persona("Aria", PrivacyTier::CloudOk),
            make_persona("Guardian", PrivacyTier::CloudOk),
        ]);
        // Guardian already in decision
        let decision =
            cabinet_decision_with_reason(&["Aria", "Guardian"], Some(ConveneReason::GoalImpact));
        let table = build_table(
            |name| registry.get(name).cloned(),
            &decision,
            Some("Guardian"),
        )
        .unwrap();
        // Must not be duplicated
        assert_eq!(
            table
                .personas
                .iter()
                .filter(|p| p.name == "Guardian")
                .count(),
            1
        );
    }

    #[test]
    fn build_table_unknown_persona_errors() {
        let registry = make_registry(vec![make_persona("Aria", PrivacyTier::CloudOk)]);
        let decision = cabinet_decision_with_reason(&["Aria", "Unknown"], None);
        assert!(build_table(|name| registry.get(name).cloned(), &decision, None).is_err());
    }
}
