//! Verify DLC offer, accept and sign messages.
//!
//! The verifier decodes the messages, rebuilds the contract transactions with DDK and checks every
//! signature against them. It performs no I/O and reads no clock: the caller passes the current
//! time in.

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
