//! dlc-verify compiled to WebAssembly, for the web page in `web/` and any other JavaScript.
//!
//! Every function takes and returns JSON text, so the module needs no bindings beyond strings.
//! The functions and their requests are documented in [`api`] and in `docs/wasm.md`. Nothing
//! leaves the page: there is no network access and no storage.
//!
//! On `wasm32` a Rust panic aborts the module instead of unwinding, so a bug that panics traps
//! the call (a `RuntimeError` in JavaScript) instead of answering with an error. Instantiate the
//! module again after one.

pub mod api;

use wasm_bindgen::prelude::wasm_bindgen;

/// Verifies messages. See [`api::verify`].
#[wasm_bindgen]
pub fn verify(request: &str) -> String {
    api::verify(request)
}

/// Prints what the messages say. See [`api::inspect`].
#[wasm_bindgen]
pub fn inspect(request: &str) -> String {
    api::inspect(request)
}

/// Completes the CET for an oracle attestation. See [`api::settle`].
#[wasm_bindgen]
pub fn settle(request: &str) -> String {
    api::settle(request)
}

/// Completes the refund. See [`api::refund`].
#[wasm_bindgen]
pub fn refund(request: &str) -> String {
    api::refund(request)
}

/// The policy a profile builds. See [`api::profile_policy`].
#[wasm_bindgen(js_name = profilePolicy)]
pub fn profile_policy(request: &str) -> String {
    api::profile_policy(request)
}

/// The profiles. See [`api::profiles`].
#[wasm_bindgen]
pub fn profiles() -> String {
    api::profiles()
}

/// The oracle registry. See [`api::oracles`].
#[wasm_bindgen]
pub fn oracles() -> String {
    api::oracles()
}

/// The dlc-verify version.
#[wasm_bindgen]
pub fn version() -> String {
    api::version()
}
