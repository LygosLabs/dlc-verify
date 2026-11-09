//! Message input: hex strings and JSON bundles.
//!
//! The verifier takes the three DLC messages as bytes. This module turns the forms people paste
//! into those bytes: a hex string per message, or one JSON object that carries all three. Reading
//! files and standard input is the caller's job.

use serde_json::Value;

/// The largest message the verifier decodes, in bytes. A contract with many outcomes carries one
/// adaptor signature per CET, so accept messages can run to a few megabytes.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// A DLC message type, named by its role in the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageKind {
    /// `offer_dlc`, sent by the offering party.
    Offer,
    /// `accept_dlc`, sent by the accepting party.
    Accept,
    /// `sign_dlc`, sent by the offering party.
    Sign,
}

impl MessageKind {
    /// The message's wire type, the two bytes every encoded message starts with.
    pub const fn wire_type(self) -> u16 {
        match self {
            Self::Offer => ddk_messages::types::OFFER_TYPE,
            Self::Accept => ddk_messages::types::ACCEPT_TYPE,
            Self::Sign => ddk_messages::types::SIGN_TYPE,
        }
    }

    /// The name with its indefinite article: "an offer", "an accept", "a sign".
    pub const fn with_article(self) -> &'static str {
        match self {
            Self::Offer => "an offer",
            Self::Accept => "an accept",
            Self::Sign => "a sign",
        }
    }

    /// The lowercase name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Accept => "accept",
            Self::Sign => "sign",
        }
    }
}

impl std::fmt::Display for MessageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The encoded messages of one contract. Only the offer is required: an offer alone can be
/// inspected, an offer and accept checked up to the accepter's signatures, and all three checked
/// in full.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Input {
    /// The encoded `offer_dlc`.
    pub offer: Vec<u8>,
    /// The encoded `accept_dlc`, if given.
    pub accept: Option<Vec<u8>>,
    /// The encoded `sign_dlc`, if given.
    pub sign: Option<Vec<u8>>,
}

/// Why input could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    /// A message's hex is malformed.
    Hex {
        /// Which message.
        kind: MessageKind,
        /// What is wrong with it.
        detail: String,
    },
    /// A message is larger than [`MAX_MESSAGE_BYTES`].
    TooLarge {
        /// Which message.
        kind: MessageKind,
        /// Its size in bytes.
        bytes: usize,
    },
    /// The JSON bundle is malformed or has no offer.
    Bundle(String),
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hex { kind, detail } => write!(f, "{kind} is not valid hex: {detail}"),
            Self::TooLarge { kind, bytes } => write!(
                f,
                "{kind} is {bytes} bytes, more than the {MAX_MESSAGE_BYTES}-byte limit"
            ),
            Self::Bundle(detail) => write!(f, "bundle: {detail}"),
        }
    }
}

impl std::error::Error for InputError {}

/// The bundle keys that may carry each message. The first is the canonical one; the others are
/// the shapes Lygos APIs return.
const BUNDLE_KEYS: [(MessageKind, [&str; 3]); 3] = [
    (MessageKind::Offer, ["offer", "offerHex", "offer_hex"]),
    (MessageKind::Accept, ["accept", "acceptHex", "accept_hex"]),
    (MessageKind::Sign, ["sign", "signHex", "sign_hex"]),
];

impl Input {
    /// Reads each message from hex. Empty strings count as absent.
    ///
    /// # Errors
    ///
    /// Fails when a message is malformed hex or too large, or when the offer is missing.
    pub fn from_hex(
        offer: &str,
        accept: Option<&str>,
        sign: Option<&str>,
    ) -> Result<Self, InputError> {
        let offer = decode_hex(MessageKind::Offer, offer)?.ok_or(InputError::Hex {
            kind: MessageKind::Offer,
            detail: "the offer is empty".to_owned(),
        })?;
        let accept = match accept {
            Some(text) => decode_hex(MessageKind::Accept, text)?,
            None => None,
        };
        let sign = match sign {
            Some(text) => decode_hex(MessageKind::Sign, text)?,
            None => None,
        };
        Ok(Self {
            offer,
            accept,
            sign,
        })
    }

    /// Reads a JSON bundle: an object with the messages as hex strings under `offer`, `accept`
    /// and `sign` (or `offerHex`… or `offer_hex`…). The bundle may also be wrapped in a `data`
    /// object, as API responses are. Other keys are ignored.
    ///
    /// # Errors
    ///
    /// Fails when the JSON is malformed, a key appears in two spellings, a message is not a hex
    /// string, or there is no offer.
    pub fn from_bundle(json: &str) -> Result<Self, InputError> {
        let value: Value = serde_json::from_str(json)
            .map_err(|error| InputError::Bundle(format!("not valid JSON: {error}")))?;
        let object = bundle_object(&value)?;
        let mut messages: [Option<Vec<u8>>; 3] = [None, None, None];
        for (slot, (kind, keys)) in messages.iter_mut().zip(BUNDLE_KEYS) {
            let present: Vec<(&str, &Value)> = keys
                .iter()
                .filter_map(|key| object.get(*key).map(|value| (*key, value)))
                .filter(|(_, value)| !value.is_null())
                .collect();
            if present.len() > 1 {
                let names: Vec<&str> = present.iter().map(|(key, _)| *key).collect();
                return Err(InputError::Bundle(format!(
                    "{kind} appears under more than one key: {}",
                    names.join(", ")
                )));
            }
            if let Some((key, value)) = present.first() {
                let Value::String(text) = value else {
                    return Err(InputError::Bundle(format!("{key} must be a hex string")));
                };
                *slot = decode_hex(kind, text)?;
            }
        }
        let [offer, accept, sign] = messages;
        let offer = offer.ok_or_else(|| InputError::Bundle("no offer in the bundle".to_owned()))?;
        Ok(Self {
            offer,
            accept,
            sign,
        })
    }

    /// Reads whatever was pasted: a JSON bundle if the text starts with `{`, otherwise the offer
    /// alone as hex.
    ///
    /// # Errors
    ///
    /// As [`Input::from_bundle`] or [`Input::from_hex`].
    pub fn from_text(text: &str) -> Result<Self, InputError> {
        if text.trim_start().starts_with('{') {
            Self::from_bundle(text)
        } else {
            Self::from_hex(text, None, None)
        }
    }

    /// The encoded message of `kind`, if present.
    pub fn message(&self, kind: MessageKind) -> Option<&[u8]> {
        match kind {
            MessageKind::Offer => Some(&self.offer),
            MessageKind::Accept => self.accept.as_deref(),
            MessageKind::Sign => self.sign.as_deref(),
        }
    }
}

fn bundle_object(value: &Value) -> Result<&serde_json::Map<String, Value>, InputError> {
    let Value::Object(object) = value else {
        return Err(InputError::Bundle("expected a JSON object".to_owned()));
    };
    let has_message = BUNDLE_KEYS
        .iter()
        .flat_map(|(_, keys)| keys)
        .any(|key| object.contains_key(*key));
    if !has_message && let Some(Value::Object(inner)) = object.get("data") {
        return Ok(inner);
    }
    Ok(object)
}

/// Decodes one message's hex. Surrounding whitespace, whitespace inside, and a `0x` prefix are
/// allowed. Returns `None` for an empty string.
///
/// # Errors
///
/// Fails on an odd number of digits, a non-hex character, or a message over
/// [`MAX_MESSAGE_BYTES`].
pub fn decode_hex(kind: MessageKind, text: &str) -> Result<Option<Vec<u8>>, InputError> {
    let trimmed = text.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let digits: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() {
        return Ok(None);
    }
    if digits.len() / 2 > MAX_MESSAGE_BYTES {
        return Err(InputError::TooLarge {
            kind,
            bytes: digits.len() / 2,
        });
    }
    let hex_error = |detail: String| InputError::Hex { kind, detail };
    if let Some(position) = digits.find(|c: char| !c.is_ascii_hexdigit()) {
        return Err(hex_error(format!(
            "non-hex character at position {position}"
        )));
    }
    if !digits.len().is_multiple_of(2) {
        return Err(hex_error(format!(
            "odd number of hex digits ({})",
            digits.len()
        )));
    }
    hex::decode(&digits)
        .map(Some)
        .map_err(|error| hex_error(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_allows_prefix_and_whitespace() {
        let bytes = decode_hex(MessageKind::Offer, "  0xA7 1a\n00 ");
        assert_eq!(bytes, Ok(Some(vec![0xa7, 0x1a, 0x00])));
    }

    #[test]
    fn hex_rejects_odd_length_and_bad_characters() {
        assert!(matches!(
            decode_hex(MessageKind::Accept, "abc"),
            Err(InputError::Hex {
                kind: MessageKind::Accept,
                ..
            })
        ));
        assert!(matches!(
            decode_hex(MessageKind::Sign, "zz"),
            Err(InputError::Hex {
                kind: MessageKind::Sign,
                ..
            })
        ));
    }

    #[test]
    fn empty_hex_is_absent() {
        assert_eq!(decode_hex(MessageKind::Sign, " \n"), Ok(None));
        let input = Input::from_hex("aa", Some(""), None);
        assert_eq!(
            input,
            Ok(Input {
                offer: vec![0xaa],
                accept: None,
                sign: None
            })
        );
    }

    #[test]
    fn missing_offer_is_an_error() {
        assert!(Input::from_hex("", Some("aa"), None).is_err());
        assert!(Input::from_bundle(r#"{"accept":"aa"}"#).is_err());
    }

    #[test]
    fn bundle_shapes() {
        let expected = Input {
            offer: vec![0x01],
            accept: Some(vec![0x02]),
            sign: Some(vec![0x03]),
        };
        for json in [
            r#"{"offer":"01","accept":"02","sign":"03","oraclePubkey":"ff"}"#,
            r#"{"offerHex":"01","acceptHex":"02","signHex":"03"}"#,
            r#"{"offer_hex":"01","accept_hex":"02","sign_hex":"03"}"#,
            r#"{"data":{"offerHex":"01","acceptHex":"02","signHex":"03"}}"#,
        ] {
            assert_eq!(Input::from_bundle(json).as_ref(), Ok(&expected), "{json}");
        }
    }

    #[test]
    fn bundle_rejects_two_spellings_and_non_strings() {
        assert!(Input::from_bundle(r#"{"offer":"01","offerHex":"01"}"#).is_err());
        assert!(Input::from_bundle(r#"{"offer":1}"#).is_err());
        assert!(Input::from_bundle("[]").is_err());
    }

    #[test]
    fn text_detects_bundles() {
        assert_eq!(
            Input::from_text(" {\"offer\":\"01\"}").map(|input| input.offer),
            Ok(vec![0x01])
        );
        assert_eq!(
            Input::from_text("01").map(|input| input.offer),
            Ok(vec![0x01])
        );
    }
}
