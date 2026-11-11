//! Strict decoding of DLC messages.
//!
//! A message decodes only if it is exactly the encoding DDK writes for the value it decodes to:
//! the right type prefix, every field well formed, and nothing the round trip would change. DDK
//! reads everything after an offer's fixed fields as TLV records, so trailing bytes are either a
//! decode error or records that [`tlv_records`] lists.

use ddk_messages::{AcceptDlc, OfferDlc, SignDlc, TlvStream};
use lightning::io::Cursor;
use lightning::util::ser::{Readable, Writeable};

use crate::input::{Input, MessageKind};

/// The decoded messages of one contract.
#[derive(Clone, Debug, PartialEq)]
pub struct Messages {
    /// The offer.
    pub offer: OfferDlc,
    /// The accept, if given.
    pub accept: Option<AcceptDlc>,
    /// The sign, if given.
    pub sign: Option<SignDlc>,
}

/// Why a message did not decode.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DecodeFailure {
    /// The message.
    pub message: MessageKind,
    /// What went wrong.
    pub error: String,
}

impl std::fmt::Display for DecodeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} does not decode: {}", self.message, self.error)
    }
}

impl std::error::Error for DecodeFailure {}

/// Each message's decode result: the offer's, and the accept's and sign's when given.
pub type DecodeResults = (
    Result<OfferDlc, DecodeFailure>,
    Option<Result<AcceptDlc, DecodeFailure>>,
    Option<Result<SignDlc, DecodeFailure>>,
);

/// Decodes every message in `input`, stopping at nothing: each message's result is reported.
pub fn decode_all(input: &Input) -> DecodeResults {
    (
        decode_message(MessageKind::Offer, &input.offer),
        input
            .accept
            .as_deref()
            .map(|bytes| decode_message(MessageKind::Accept, bytes)),
        input
            .sign
            .as_deref()
            .map(|bytes| decode_message(MessageKind::Sign, bytes)),
    )
}

/// Decodes every message in `input`.
///
/// # Errors
///
/// Fails on the first message that does not decode.
pub fn decode(input: &Input) -> Result<Messages, DecodeFailure> {
    let (offer, accept, sign) = decode_all(input);
    Ok(Messages {
        offer: offer?,
        accept: accept.transpose()?,
        sign: sign.transpose()?,
    })
}

/// Decodes one message of `kind` strictly. See the [module documentation](self).
///
/// # Errors
///
/// Fails when the bytes are not a message of `kind`, do not decode, or are not the canonical
/// encoding of what they decode to.
pub fn decode_message<T: Readable + Writeable>(
    kind: MessageKind,
    bytes: &[u8],
) -> Result<T, DecodeFailure> {
    let fail = |error: String| DecodeFailure {
        message: kind,
        error,
    };
    let Some(prefix) = bytes.get(..2) else {
        return Err(fail(format!("only {} bytes", bytes.len())));
    };
    let wire_type = u16::from_be_bytes([prefix[0], prefix[1]]);
    if wire_type != kind.wire_type() {
        let other = [MessageKind::Offer, MessageKind::Accept, MessageKind::Sign]
            .into_iter()
            .find(|other| other.wire_type() == wire_type);
        return Err(fail(match other {
            Some(other) => format!(
                "this is {} message, not {}",
                other.with_article(),
                kind.with_article()
            ),
            None => format!(
                "starts with type {wire_type:#06x}; {} starts with {:#06x}",
                kind.with_article(),
                kind.wire_type()
            ),
        }));
    }
    let mut cursor = Cursor::new(bytes);
    let message = T::read(&mut cursor).map_err(|error| fail(format!("{error:?}")))?;
    let consumed = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    if consumed != bytes.len() {
        return Err(fail(format!(
            "{} trailing bytes after the message",
            bytes.len().saturating_sub(consumed)
        )));
    }
    let encoded = message.encode();
    if encoded != bytes {
        let offset = encoded
            .iter()
            .zip(bytes)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| encoded.len().min(bytes.len()));
        return Err(fail(format!(
            "not the canonical encoding: re-encoding it differs at byte {offset} \
             ({} bytes in, {} bytes out); messages from before protocol version 1 \
             are not supported",
            bytes.len(),
            encoded.len()
        )));
    }
    Ok(message)
}

/// A TLV record found after a message's fixed fields.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TlvRecordInfo {
    /// The record type.
    pub tlv_type: u64,
    /// The body length in bytes.
    pub length: usize,
    /// The record's name if this verifier knows it.
    pub known: Option<&'static str>,
    /// Whether the type is even. A peer must reject a message carrying an even type it does not
    /// know ("it's OK to be odd").
    pub required: bool,
}

/// The TLV types this verifier understands on each message.
pub fn known_tlv(kind: MessageKind, tlv_type: u64) -> Option<&'static str> {
    match (kind, tlv_type) {
        (MessageKind::Offer, t)
            if t == u64::from(ddk_messages::payout_overrides::PAYOUT_SCRIPT_OVERRIDES_TYPE) =>
        {
            Some("payout-script-overrides")
        }
        _ => None,
    }
}

/// The TLV records on a message, in wire order.
pub fn tlv_records(kind: MessageKind, tlvs: &TlvStream) -> Vec<TlvRecordInfo> {
    tlvs.raw()
        .map(|record| TlvRecordInfo {
            tlv_type: record.tlv_type,
            length: record.body.len(),
            known: known_tlv(kind, record.tlv_type),
            required: record.tlv_type % 2 == 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_mistyped_messages() {
        let short = decode_message::<OfferDlc>(MessageKind::Offer, &[0xa7]);
        assert!(short.is_err());
        let accept_as_offer = decode_message::<OfferDlc>(MessageKind::Offer, &[0xa7, 0x1c, 0, 0]);
        assert_eq!(
            accept_as_offer.map_err(|failure| failure.error),
            Err("this is an accept message, not an offer".to_owned())
        );
        let unknown = decode_message::<SignDlc>(MessageKind::Sign, &[0x00, 0x01]);
        assert!(unknown.is_err());
    }

    #[test]
    fn truncated_offer_fails() {
        let truncated = decode_message::<OfferDlc>(MessageKind::Offer, &[0xa7, 0x1a, 0, 0, 0, 1]);
        assert!(truncated.is_err());
    }
}
