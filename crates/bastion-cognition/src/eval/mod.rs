//! Promoted eval harness (EVAL-01/EVAL-02): the SAME assertion logic `cargo test --test evals`
//! runs is callable in-process so the Reflector's merge gate exercises identical checks.
pub mod capture;
pub mod failure_sink;
pub mod verifier;
