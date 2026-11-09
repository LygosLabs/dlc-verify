//! Reading oracle attestations.
//!
//! An attestation travels as a hex TLV record (type 55400, so the hex starts `fdd868`), the form
//! oracles serve over HTTP. dlc-verify also reads the JSON shapes it writes itself: an object
//! with that hex under `hex`, a list of those, or a bundle with them under `attestations`.

use ddk_messages::TlvRecord;
use ddk_messages::oracle_msgs::OracleAttestation;
use serde_json::Value;

use crate::SettleError;

/// The most attestation text [`parse_attestations`] reads: far more than any real attestation
/// set, small enough to refuse a mistaken file at once.
pub const MAX_ATTESTATION_TEXT: usize = 1 << 20;

/// Reads one attestation from its hex TLV record. Whitespace and a `0x` prefix are allowed.
///
/// # Errors
///
/// Fails when the text is not hex or not an attestation record.
pub fn parse_attestation(text: &str) -> Result<OracleAttestation, SettleError> {
    let digits: String = text.split_whitespace().collect();
    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .unwrap_or(&digits);
    if digits.is_empty() {
        return Err(SettleError::Attestation(
            "the attestation is empty".to_owned(),
        ));
    }
    let bytes = hex::decode(digits).map_err(|error| {
        SettleError::Attestation(format!("the attestation is not valid hex: {error}"))
    })?;
    OracleAttestation::from_tlv_bytes(&bytes).map_err(|error| {
        SettleError::Attestation(format!(
            "not an oracle attestation TLV record (type 55400, hex starting fdd868): {error:?}"
        ))
    })
}

/// Reads attestations from whatever was given: hex, a JSON object with `hex`, a JSON list of
/// hex strings or such objects, or a bundle with them under `attestations` (or
/// `data.attestations`). A bundle without attestations gives an empty list.
///
/// # Errors
///
/// Fails on malformed JSON or hex, or an entry that is not an attestation.
pub fn parse_attestations(text: &str) -> Result<Vec<OracleAttestation>, SettleError> {
    if text.len() > MAX_ATTESTATION_TEXT {
        return Err(SettleError::Attestation(format!(
            "{} bytes of attestation text, more than the {MAX_ATTESTATION_TEXT}-byte limit",
            text.len()
        )));
    }
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return parse_attestation(text).map(|attestation| vec![attestation]);
    }
    let value: Value = serde_json::from_str(text).map_err(|error| {
        SettleError::Attestation(format!("the attestation JSON is malformed: {error}"))
    })?;
    match &value {
        Value::Array(entries) => entries.iter().map(entry).collect(),
        Value::Object(object) if object.contains_key("hex") => entry(&value).map(|one| vec![one]),
        Value::Object(_) => bundle(&value),
        _ => Err(SettleError::Attestation(
            "expected attestation hex, an object or a list".to_owned(),
        )),
    }
}

/// The attestations in a bundle, under `attestations` or `data.attestations`; empty when there
/// are none.
///
/// # Errors
///
/// Fails on malformed JSON or an entry that is not an attestation.
pub fn attestations_from_bundle(json: &str) -> Result<Vec<OracleAttestation>, SettleError> {
    let value: Value = serde_json::from_str(json)
        .map_err(|error| SettleError::Attestation(format!("the bundle is malformed: {error}")))?;
    bundle(&value)
}

fn bundle(value: &Value) -> Result<Vec<OracleAttestation>, SettleError> {
    let list = value
        .get("attestations")
        .or_else(|| value.get("data").and_then(|data| data.get("attestations")));
    match list {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(entries)) => entries.iter().map(entry).collect(),
        Some(_) => Err(SettleError::Attestation(
            "the bundle's attestations must be a list".to_owned(),
        )),
    }
}

fn entry(value: &Value) -> Result<OracleAttestation, SettleError> {
    match value {
        Value::String(text) => parse_attestation(text),
        Value::Object(object) => match object.get("hex") {
            Some(Value::String(text)) => parse_attestation(text),
            _ => Err(SettleError::Attestation(
                "an attestation object needs its TLV record as a hex string under `hex`".to_owned(),
            )),
        },
        _ => Err(SettleError::Attestation(
            "an attestation must be a hex string or an object with `hex`".to_owned(),
        )),
    }
}
