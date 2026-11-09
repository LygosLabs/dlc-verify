//! Verify DLC offer, accept and sign messages.
//!
//! The verifier decodes the messages, rebuilds the contract transactions with DDK and checks every
//! signature against them. It performs no I/O and reads no clock: the caller passes the current
//! time in.

pub mod decode;
pub mod input;
pub mod inspect;
pub mod network;
pub mod report;
pub mod summary;
pub mod text;
pub mod time;
pub mod verify;

pub use decode::{DecodeFailure, Messages, decode};
pub use input::{Input, InputError, MessageKind};
pub use inspect::{Inspection, inspect};
pub use report::{Payee, Report, render_text, report};
pub use verify::{Check, CheckStatus, Options, Status, Verification, verify};

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
