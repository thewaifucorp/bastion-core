//! `bastion-extension-wasm` — the `Wasm` mechanism's sandbox
//! (`docs/ARCHITECTURE.md` §2, M4-08).
//!
//! Deliberately ZERO bastion-* dependencies: this crate knows nothing about
//! `ExtensionManifest`/`PermissionSet`/`Capability` — it only knows how to
//! run a `wasm32-unknown-unknown` module with a fuel budget and NO imports
//! (no WASI, no host functions of any kind) and report a typed result.
//! `src/extension/wasm.rs` (the app, `bastion-agent`) wraps this into an
//! `ExtensionInstance`/`Capability`, the same way `src/extension/subprocess.rs`
//! wraps a child process.
//!
//! "No imports" is the security property this module exists to guarantee: a
//! [`Linker`] with nothing registered on it means the guest module has
//! nothing to call outside itself — not merely policy-denied the way
//! egress/memory/network_bind are for the `Subprocess` mechanism, but
//! STRUCTURALLY absent. There is no host-request protocol here (unlike
//! `subprocess.rs`'s NDJSON exchange) — the reference `Wasm` extension is
//! pure computation by design; a future WASI-backed variant that DOES need
//! host-mediated syscalls is a follow-up, not silently smuggled in here.

#![forbid(unsafe_code)]

use wasmi::core::TrapCode;
use wasmi::{Config, Engine, Linker, Module, Store};

/// Typed failures of a wasm sandbox call. `#[non_exhaustive]` like
/// `bastion_types::BastionError`.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("failed to compile wasm module: {0}")]
    Compile(String),
    #[error("failed to instantiate wasm module: {0}")]
    Instantiate(String),
    #[error("exported function '{0}' not found or has an unexpected signature (expected fn(i64, i64) -> i64)")]
    BadExport(String),
    #[error("execution trapped: {0}")]
    Trap(String),
    #[error("fuel exhausted before completion (budget: {0})")]
    OutOfFuel(u64),
}

/// A reusable `wasmi` `Engine` (cheap to share — `wasmi` is an interpreter,
/// there is no JIT cache to warm). Each `call_i64_i64_to_i64` still gets a
/// FRESH `Store`+`Linker`+instance — no state survives between calls, and no
/// two calls ever share a store.
pub struct WasmSandbox {
    engine: Engine,
}

impl WasmSandbox {
    pub fn new() -> Result<Self, WasmError> {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        Ok(Self { engine })
    }

    /// Compiles `wasm_bytes`, instantiates it against an EMPTY linker (no
    /// imports satisfied — a module that declares any import fails to
    /// instantiate rather than silently getting one), and calls
    /// `func_name(a, b) -> i64` under a `fuel`-bounded budget.
    ///
    /// This is the ONLY calling convention this sandbox understands — no
    /// string/JSON marshalling across the wasm boundary this cycle (keeps the
    /// guest ABI trivial and auditable). A module that needs richer I/O is
    /// out of scope for the reference extension.
    pub fn call_i64_i64_to_i64(
        &self,
        wasm_bytes: &[u8],
        func_name: &str,
        a: i64,
        b: i64,
        fuel: u64,
    ) -> Result<i64, WasmError> {
        let module =
            Module::new(&self.engine, wasm_bytes).map_err(|e| WasmError::Compile(e.to_string()))?;

        // Empty linker — deliberately registers ZERO host functions. A guest
        // module that imports anything fails `instantiate` below; nothing
        // here ever grants ambient authority to fill an import.
        let linker: Linker<()> = Linker::new(&self.engine);
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(fuel)
            .map_err(|e| WasmError::Instantiate(e.to_string()))?;

        let instance_pre = linker
            .instantiate(&mut store, &module)
            .map_err(|e| WasmError::Instantiate(e.to_string()))?;
        let instance = instance_pre
            .start(&mut store)
            .map_err(|e| WasmError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<(i64, i64), i64>(&store, func_name)
            .map_err(|_| WasmError::BadExport(func_name.to_string()))?;

        match func.call(&mut store, (a, b)) {
            Ok(result) => Ok(result),
            Err(e) => {
                if e.as_trap_code() == Some(TrapCode::OutOfFuel) {
                    Err(WasmError::OutOfFuel(fuel))
                } else {
                    Err(WasmError::Trap(e.to_string()))
                }
            }
        }
    }
}

impl Default for WasmSandbox {
    fn default() -> Self {
        Self::new().expect("wasmi engine construction with a valid Config must not fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (func (export "add") (param i64 i64) (result i64)
                    local.get 0 local.get 1 i64.add)
                (func (export "busy_loop") (param i64 i64) (result i64)
                    (loop $forever br $forever)
                    i64.const 0))"#,
        )
        .expect("valid test module")
    }

    #[test]
    fn add_export_computes_correctly() {
        let sandbox = WasmSandbox::new().unwrap();
        let result = sandbox
            .call_i64_i64_to_i64(&reference_wasm(), "add", 2, 3, 1_000_000)
            .expect("add should succeed");
        assert_eq!(result, 5);
    }

    #[test]
    fn unknown_export_is_a_typed_bad_export_error() {
        let sandbox = WasmSandbox::new().unwrap();
        let result =
            sandbox.call_i64_i64_to_i64(&reference_wasm(), "does_not_exist", 1, 1, 1_000_000);
        assert!(matches!(result, Err(WasmError::BadExport(_))));
    }

    #[test]
    fn busy_loop_exhausts_fuel_instead_of_hanging() {
        let sandbox = WasmSandbox::new().unwrap();
        let result = sandbox.call_i64_i64_to_i64(&reference_wasm(), "busy_loop", 0, 0, 10_000);
        assert!(matches!(result, Err(WasmError::OutOfFuel(10_000))));
    }

    #[test]
    fn malformed_bytes_are_a_typed_compile_error() {
        let sandbox = WasmSandbox::new().unwrap();
        let result = sandbox.call_i64_i64_to_i64(b"not a wasm module", "add", 1, 1, 1_000);
        assert!(matches!(result, Err(WasmError::Compile(_))));
    }
}
