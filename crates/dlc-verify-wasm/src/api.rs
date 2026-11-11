//! The module's API as plain Rust: a JSON request in, a JSON response out.
//!
//! Every call that takes a request answers with an envelope: `{"ok": true, ...}` with the result,
//! or `{"ok": false, "error": {"kind", "message"}}`. The error kinds are:
//!
//! | Kind | Meaning |
//! |---|---|
//! | `request` | The request is not JSON, has an unknown field, or combines fields that conflict |
//! | `input` | The messages are malformed or missing |
//! | `policy` | The policy, profile or terms are invalid |
//! | `attestation` | No attestation, a malformed one, or none for this contract |
//! | `incomplete` | Settling needs the offer, accept and sign messages |
//! | `no-cet` | The attested outcome settles no CET (too few oracles, for example) |
//! | `signature` | A signature in the messages does not verify |
//! | `internal` | A bug in dlc-verify |

use dlc_verify_core::{Input, Options};
use dlc_verify_policy::{Policy, Profile};
use dlc_verify_settle::{SettleError, Settlement};
use serde::Deserialize;
use serde_json::{Map, Value};

/// A request. Each call reads the fields it documents and refuses the others.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// A bundle (`{"offer", "accept", "sign"}`, as JSON text or an object) or an offer in hex.
    pub input: Option<Value>,
    /// The offer in hex, instead of `input`.
    pub offer: Option<String>,
    /// The accept in hex, with `offer`.
    pub accept: Option<String>,
    /// The sign in hex, with `offer`.
    pub sign: Option<String>,
    /// The current time as a Unix timestamp, for the maturity checks and to say whether a
    /// locktime has passed. Without it the maturity checks warn that they could not run.
    pub now: Option<u64>,
    /// A policy file's text (TOML or JSON).
    pub policy: Option<String>,
    /// A profile name: `lygos-loan` or `lygos-midnight`.
    pub profile: Option<String>,
    /// The profile's terms (TOML or JSON).
    pub terms: Option<String>,
    /// Oracle attestations: TLV hex, or JSON as `dlc-verify settle --attestation` reads it,
    /// as a string, an object or a list.
    pub attestations: Option<Value>,
}

impl Request {
    fn parse(text: &str) -> Result<Self, ApiError> {
        serde_json::from_str(text)
            .map_err(|error| ApiError::new("request", format!("the request is invalid: {error}")))
    }

    /// Refuses `fields` that are set, which the calling function does not read.
    fn refuse(&self, call: &str, fields: &[&str]) -> Result<(), ApiError> {
        for field in fields {
            let set = match *field {
                "now" => self.now.is_some(),
                "policy" => self.policy.is_some(),
                "profile" => self.profile.is_some(),
                "terms" => self.terms.is_some(),
                "attestations" => self.attestations.is_some(),
                _ => false,
            };
            if set {
                return Err(ApiError::new(
                    "request",
                    format!("{call} does not take `{field}`"),
                ));
            }
        }
        Ok(())
    }

    /// The messages, and the bundle's text when they came as one.
    fn input(&self) -> Result<(Input, Option<String>), ApiError> {
        let separate = self.offer.is_some() || self.accept.is_some() || self.sign.is_some();
        let input_error = |error: dlc_verify_core::InputError| ApiError::new("input", error);
        match (&self.input, separate) {
            (Some(_), true) => Err(ApiError::new(
                "request",
                "give either `input` or `offer`/`accept`/`sign`, not both",
            )),
            (None, false) => Err(ApiError::new(
                "input",
                "no input: pass `input` (a bundle, or an offer in hex) or `offer`",
            )),
            (Some(Value::String(text)), false) => {
                let input = Input::from_text(text).map_err(input_error)?;
                let bundle = text.trim_start().starts_with('{').then(|| text.clone());
                Ok((input, bundle))
            }
            (Some(value @ Value::Object(_)), false) => {
                let text = value.to_string();
                let input = Input::from_bundle(&text).map_err(input_error)?;
                Ok((input, Some(text)))
            }
            (Some(_), false) => Err(ApiError::new(
                "request",
                "`input` must be a string or a bundle object",
            )),
            (None, true) => {
                let offer = self
                    .offer
                    .as_deref()
                    .ok_or_else(|| ApiError::new("input", "`accept` and `sign` need `offer`"))?;
                let input = Input::from_hex(offer, self.accept.as_deref(), self.sign.as_deref())
                    .map_err(input_error)?;
                Ok((input, None))
            }
        }
    }

    /// The policy to check, from `policy` or `profile` and `terms`, and what the profile could
    /// not check.
    fn policy(&self) -> Result<Option<(Policy, Vec<String>)>, ApiError> {
        match (&self.policy, &self.profile, &self.terms) {
            (Some(_), Some(_), _) => Err(ApiError::new(
                "request",
                "give either `policy` or `profile`, not both",
            )),
            (Some(_), None, Some(_)) | (None, None, Some(_)) => {
                Err(ApiError::new("request", "`terms` needs `profile`"))
            }
            (Some(text), None, None) => Policy::parse(text)
                .map(|policy| Some((policy, Vec::new())))
                .map_err(|error| ApiError::new("policy", format!("policy: {error}"))),
            (None, Some(name), terms) => {
                let built = profile_policy_of(name, terms.as_deref())?;
                Ok(Some((built.policy, built.notes)))
            }
            (None, None, None) => Ok(None),
        }
    }
}

/// Why a call failed.
#[derive(Debug)]
struct ApiError {
    kind: &'static str,
    message: String,
}

impl ApiError {
    fn new(kind: &'static str, message: impl ToString) -> Self {
        Self {
            kind,
            message: message.to_string(),
        }
    }
}

impl From<SettleError> for ApiError {
    fn from(error: SettleError) -> Self {
        let kind = match &error {
            SettleError::Incomplete(_) => "incomplete",
            SettleError::Attestation(_) => "attestation",
            SettleError::NoCet(_) => "no-cet",
            SettleError::Signature(_) => "signature",
        };
        Self::new(kind, error)
    }
}

/// The fields of a successful response.
type Fields = Vec<(&'static str, Value)>;

/// Wraps a call's result in the response envelope.
fn respond(result: Result<Fields, ApiError>) -> String {
    let mut object = Map::new();
    match result {
        Ok(fields) => {
            object.insert("ok".to_owned(), Value::Bool(true));
            for (key, value) in fields {
                object.insert(key.to_owned(), value);
            }
        }
        Err(error) => {
            object.insert("ok".to_owned(), Value::Bool(false));
            let mut detail = Map::new();
            detail.insert("kind".to_owned(), Value::from(error.kind));
            detail.insert("message".to_owned(), Value::from(error.message));
            object.insert("error".to_owned(), Value::Object(detail));
        }
    }
    Value::Object(object).to_string()
}

fn to_value(value: &impl serde::Serialize) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|error| ApiError::new("internal", error))
}

fn profile_policy_of(
    name: &str,
    terms: Option<&str>,
) -> Result<dlc_verify_policy::ProfilePolicy, ApiError> {
    let profile = Profile::from_name(name).ok_or_else(|| {
        let names: Vec<&str> = Profile::ALL.iter().map(|profile| profile.name()).collect();
        ApiError::new(
            "policy",
            format!(
                "unknown profile {name:?}; expected one of {}",
                names.join(", ")
            ),
        )
    })?;
    dlc_verify_policy::profile_policy(profile, terms).map_err(|error| {
        let source = if terms.is_some() { "terms" } else { "profile" };
        ApiError::new("policy", format!("{source}: {error}"))
    })
}

/// Verifies messages, as `dlc-verify verify` does.
///
/// Reads `input` (or `offer`, `accept`, `sign`), `now`, and optionally `policy`, or `profile`
/// with `terms`. Answers `report` (the JSON report), `text` (the same report as text) and
/// `notes` (what a profile could not check). A report whose status is `fail` is still `ok`: the
/// call worked.
pub fn verify(request: &str) -> String {
    respond(verify_fields(request))
}

fn verify_fields(request: &str) -> Result<Fields, ApiError> {
    let request = Request::parse(request)?;
    request.refuse("verify", &["attestations"])?;
    let policy = request.policy()?;
    let (input, _) = request.input()?;
    let verification = dlc_verify_core::verify(&input, &Options { now: request.now });
    let mut report = dlc_verify_core::report(&verification);
    let mut notes = Vec::new();
    if let Some((policy, profile_notes)) = policy {
        let outcome = dlc_verify_policy::evaluate(&policy, &verification, &report);
        report = report.with_policy(outcome);
        notes = profile_notes;
    }
    Ok(vec![
        ("report", to_value(&report)?),
        ("text", Value::from(dlc_verify_core::render_text(&report))),
        ("notes", Value::from(notes)),
    ])
}

/// Prints what the messages say, without verifying them, as `dlc-verify inspect` does.
///
/// Reads `input` (or `offer`, `accept`, `sign`). Answers `inspection`.
pub fn inspect(request: &str) -> String {
    respond(inspect_fields(request))
}

fn inspect_fields(request: &str) -> Result<Fields, ApiError> {
    let request = Request::parse(request)?;
    request.refuse(
        "inspect",
        &["now", "policy", "profile", "terms", "attestations"],
    )?;
    let (input, _) = request.input()?;
    Ok(vec![(
        "inspection",
        to_value(&dlc_verify_core::inspect(&input))?,
    )])
}

/// Completes the CET for an oracle attestation, as `dlc-verify settle` does.
///
/// Reads `input` (or `offer`, `accept`, `sign`), `now` and `attestations`; without
/// `attestations`, the bundle's own. Answers `settlement` (with the transaction hex under
/// `transaction`) and `text`.
pub fn settle(request: &str) -> String {
    respond(settle_fields(request))
}

fn settle_fields(request: &str) -> Result<Fields, ApiError> {
    let request = Request::parse(request)?;
    request.refuse("settle", &["policy", "profile", "terms"])?;
    let (input, bundle) = request.input()?;
    let attestations = match &request.attestations {
        Some(Value::String(text)) => dlc_verify_settle::parse_attestations(text)?,
        Some(other) => dlc_verify_settle::parse_attestations(&other.to_string())?,
        None => {
            let attestations = match &bundle {
                Some(bundle) => dlc_verify_settle::attestations_from_bundle(bundle)?,
                None => Vec::new(),
            };
            if attestations.is_empty() {
                return Err(ApiError::new(
                    "attestation",
                    "no attestation: pass `attestations`, or a bundle with them",
                ));
            }
            attestations
        }
    };
    let verification = dlc_verify_core::verify(&input, &Options { now: request.now });
    let settlement = dlc_verify_settle::settle(&verification, &attestations, request.now)?;
    settlement_fields(&settlement)
}

/// Completes the refund transaction, as `dlc-verify refund` does.
///
/// Reads `input` (or `offer`, `accept`, `sign`) and `now`. Answers `settlement` and `text`.
pub fn refund(request: &str) -> String {
    respond(refund_fields(request))
}

fn refund_fields(request: &str) -> Result<Fields, ApiError> {
    let request = Request::parse(request)?;
    request.refuse("refund", &["policy", "profile", "terms", "attestations"])?;
    let (input, _) = request.input()?;
    let verification = dlc_verify_core::verify(&input, &Options { now: request.now });
    let settlement = dlc_verify_settle::refund(&verification, request.now)?;
    settlement_fields(&settlement)
}

fn settlement_fields(settlement: &Settlement) -> Result<Fields, ApiError> {
    Ok(vec![
        ("settlement", to_value(settlement)?),
        (
            "text",
            Value::from(dlc_verify_settle::render_text(settlement)),
        ),
    ])
}

/// The policy a profile builds from terms, as `dlc-verify profile` prints it.
///
/// Reads `profile` and `terms`. Answers `policy` and `notes`.
pub fn profile_policy(request: &str) -> String {
    respond(profile_policy_fields(request))
}

fn profile_policy_fields(request: &str) -> Result<Fields, ApiError> {
    let request = Request::parse(request)?;
    request.refuse("profilePolicy", &["now", "policy", "attestations"])?;
    if request.input.is_some()
        || request.offer.is_some()
        || request.accept.is_some()
        || request.sign.is_some()
    {
        return Err(ApiError::new(
            "request",
            "profilePolicy does not take messages",
        ));
    }
    let name = request
        .profile
        .as_deref()
        .ok_or_else(|| ApiError::new("request", "profilePolicy needs `profile`"))?;
    let built = profile_policy_of(name, request.terms.as_deref())?;
    Ok(vec![
        ("policy", to_value(&built.policy)?),
        ("notes", Value::from(built.notes)),
    ])
}

/// The profiles: `profiles`, each with its `name` and one line `about` it.
pub fn profiles() -> String {
    let list: Vec<Value> = Profile::ALL
        .iter()
        .map(|profile| {
            let mut entry = Map::new();
            entry.insert("name".to_owned(), Value::from(profile.name()));
            entry.insert("about".to_owned(), Value::from(profile.about()));
            Value::Object(entry)
        })
        .collect();
    respond(Ok(vec![("profiles", Value::from(list))]))
}

/// The oracle keys dlc-verify knows by name: `oracles`.
pub fn oracles() -> String {
    respond(
        dlc_verify_policy::registry()
            .map_err(|error| ApiError::new("internal", error))
            .and_then(|entries| Ok(vec![("oracles", to_value(&entries)?)])),
    )
}

/// The dlc-verify version.
pub fn version() -> String {
    dlc_verify_core::VERSION.to_owned()
}
