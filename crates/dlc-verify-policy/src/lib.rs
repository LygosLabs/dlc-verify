//! Check a verified DLC against the terms you expected to sign.
//!
//! [`dlc_verify_core`] proves that the messages are consistent and that the signatures commit to
//! the transactions they describe. It cannot know whether those are the transactions you agreed
//! to. A [`Policy`] states that agreement: network, collateral, parties, oracles, locktimes, and
//! who each CET and the refund must pay. [`evaluate`] compares a verification with a policy and
//! returns one check per stated term.
//!
//! Policies are TOML or JSON files ([`Policy::parse`]); `docs/policy.md` describes the format.
//! [`profiles`] build policies for known kinds of contract from a few deal terms, using the
//! oracle keys in the [`registry`]; `docs/profiles.md` describes them.

mod evaluate;
pub mod midnight;
pub mod profiles;
pub mod registry;
mod schema;

pub use evaluate::{POLICY_CHECK_IDS, evaluate, report_with_policy};
pub use profiles::{Profile, ProfilePolicy, profile_policy};
pub use registry::{OracleEntry, registry};
pub use schema::{
    CetRule, Destination, LocktimePolicy, OraclePolicy, POLICY_SCHEMA, Party, PartyPolicy, Pay,
    Policy, PolicyError, RefundRule, address_script, destination_script, funding_key, oracle_key,
    script_hex,
};
