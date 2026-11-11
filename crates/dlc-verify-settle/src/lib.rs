//! Complete a DLC's CET or refund from its messages, without any private key.
//!
//! The messages carry every signature a DLC needs to close. The accept holds the accepter's
//! adaptor signature on every CET and its refund signature; the sign holds the offerer's. An
//! oracle attestation reveals the secret that decrypts both adaptor signatures of the CET for
//! the attested outcome. So anyone holding the three messages and the attestation can build the
//! fully signed CET, and anyone holding the messages can build the signed refund, which is only
//! valid after its locktime.
//!
//! [`settle`] and [`refund`] take a [`Verification`] (the messages, decoded and rebuilt by
//! [`dlc_verify_core::verify`]), check every signature they use against the transaction they
//! complete, and return the transaction ready to broadcast. Nothing here holds a key or touches
//! the network.

mod attestation;
mod text;

use std::panic::{AssertUnwindSafe, catch_unwind};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, Transaction};
use ddk_dlc::secp256k1_zkp::ecdsa::Signature;
use ddk_dlc::secp256k1_zkp::schnorr::Signature as SchnorrSignature;
use ddk_dlc::secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Scalar, Secp256k1, SecretKey};
use ddk_manager::contract::contract_info::ContractInfo as ExecutionInfo;
use ddk_messages::oracle_msgs::OracleAttestation;
use ddk_messages::{AcceptDlc, OfferDlc, SignDlc};
use dlc_verify_core::report::PayoutOutput;
use dlc_verify_core::summary::LocktimeSummary;
use dlc_verify_core::time::{LocktimeKind, format_unix};
use dlc_verify_core::verify::RebuiltContract;
use dlc_verify_core::{CetOutcome, Status, Verification};
use serde::Serialize;

pub use attestation::{
    MAX_ATTESTATION_TEXT, attestations_from_bundle, parse_attestation, parse_attestations,
};
pub use text::render_text;

/// The schema id every [`Settlement`] carries.
pub const SETTLEMENT_SCHEMA: &str = "dlc-verify/settlement/v1";

/// Why a transaction could not be completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettleError {
    /// The messages are not enough: one is missing, or the contract could not be rebuilt.
    Incomplete(String),
    /// An attestation is malformed, invalid, or not for this contract.
    Attestation(String),
    /// The attested outcomes match no CET of the contract.
    NoCet(String),
    /// A signature in the messages does not complete the transaction.
    Signature(String),
}

impl std::fmt::Display for SettleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete(detail)
            | Self::Attestation(detail)
            | Self::NoCet(detail)
            | Self::Signature(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for SettleError {}

/// Which transaction a [`Settlement`] completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// The CET for an attested outcome.
    Cet,
    /// The refund.
    Refund,
}

/// A completed, fully signed transaction and what it does.
#[derive(Clone, Debug, Serialize)]
pub struct Settlement {
    /// Always [`SETTLEMENT_SCHEMA`].
    pub schema: &'static str,
    /// CET or refund.
    pub kind: Kind,
    /// The contract id, hex.
    pub contract_id: String,
    /// How verification of the messages ended. Check a contract that did not pass before
    /// broadcasting anything.
    pub verification: Status,
    /// The signed transaction's id.
    pub txid: String,
    /// The signed transaction, consensus-encoded hex, ready to broadcast.
    pub transaction: String,
    /// Its virtual size.
    pub vsize: u64,
    /// The fee it pays: the funding output's value less its outputs.
    pub fee_sat: u64,
    /// The funding output it spends.
    pub spends: Spends,
    /// Its locktime.
    pub locktime: LocktimeSummary,
    /// When it can be broadcast.
    pub broadcast: Broadcast,
    /// For a CET: the outcome it settles and the attestations it was completed with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cet: Option<SettledCet>,
    /// Its outputs and who each one pays.
    pub outputs: Vec<PayoutOutput>,
}

/// The funding output a settlement spends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Spends {
    /// The funding transaction id.
    pub txid: String,
    /// The funding output's index.
    pub vout: usize,
    /// The funding output's value.
    pub value_sat: u64,
}

/// When a transaction can be broadcast. The funding transaction must confirm first in every
/// case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "when", rename_all = "kebab-case")]
pub enum Broadcast {
    /// No locktime: as soon as the funding transaction confirms.
    Now,
    /// A time lock: once the chain's median time past passes `unix`, about an hour after that
    /// wall-clock time.
    AfterTime {
        /// The locktime, Unix seconds.
        unix: u64,
        /// The locktime as RFC 3339.
        utc: String,
        /// Whether the given current time is past the locktime; `None` without a clock.
        #[serde(skip_serializing_if = "Option::is_none")]
        reached: Option<bool>,
    },
    /// A height lock: from the block after `height`.
    AfterHeight {
        /// The locktime, a block height.
        height: u32,
    },
}

/// The CET a settlement completes.
#[derive(Clone, Debug, Serialize)]
pub struct SettledCet {
    /// The CET's position among all CETs.
    pub index: usize,
    /// The contract info it belongs to.
    pub contract_info: usize,
    /// The outcome it settles as text.
    pub outcome: String,
    /// The outcome it settles.
    pub settles: CetOutcome,
    /// The attestations bound to the contract info, by oracle.
    pub attestations: Vec<BoundAttestation>,
}

/// An attestation matched to one of the contract's oracle announcements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BoundAttestation {
    /// The announcement's position in the contract info's oracle list.
    pub oracle_index: usize,
    /// The oracle's key, x-only hex.
    pub oracle_public_key: String,
    /// The event id.
    pub event_id: String,
    /// The attested outcome: the enum outcome, or the numeric digits.
    pub outcomes: Vec<String>,
}

/// Completes the CET for the attested outcome.
///
/// Each attestation is matched to the contract's announcement with the same oracle key and
/// event id, and must verify against it. Attestations for other contracts are ignored, but at
/// least one must be for this one. The CET's adaptor signatures from both parties are decrypted
/// with the attestation and checked against the CET before it is returned.
///
/// `now` (Unix seconds) only sets [`Broadcast::AfterTime::reached`].
///
/// # Errors
///
/// Fails when the messages are incomplete, an attestation is invalid or for another contract,
/// the attested outcome has no CET, or a signature does not complete the CET.
pub fn settle(
    verification: &Verification,
    attestations: &[OracleAttestation],
    now: Option<u64>,
) -> Result<Settlement, SettleError> {
    let parts = Parts::of(verification)?;
    if attestations.is_empty() {
        return Err(SettleError::Attestation(
            "no attestation given; a CET can only be completed with the oracle's attestation"
                .to_owned(),
        ));
    }
    let secp = Secp256k1::new();
    let contract = parts.contract;
    let total = parts.offer.get_total_collateral();
    let accept_signatures: Vec<EcdsaAdaptorSignature> =
        (&parts.accept.cet_adaptor_signatures).into();
    let offer_signatures: Vec<EcdsaAdaptorSignature> = (&parts.sign.cet_adaptor_signatures).into();

    let mut adaptor_start = 0;
    let mut bound_any = false;
    for (info_index, (info, range)) in contract
        .execution_infos
        .iter()
        .zip(&contract.cet_ranges)
        .enumerate()
    {
        let cets = contract
            .transactions
            .cets
            .get(range.clone())
            .ok_or_else(|| {
                SettleError::Incomplete(format!(
                    "contract info {info_index}: CET range out of bounds"
                ))
            })?;
        let (adaptor_info, next) = guarded(|| {
            info.verify_and_get_adaptor_info(
                &secp,
                total,
                &parts.accept.funding_pubkey,
                &contract.transactions.funding_witness_script,
                contract.fund_output_value,
                cets,
                &accept_signatures,
                adaptor_start,
            )
            .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            SettleError::Signature(format!(
                "contract info {info_index}: the accepter's adaptor signatures do not verify: \
                 {error}"
            ))
        })?;
        let start = adaptor_start;
        adaptor_start = next;

        let bound = bind(info, attestations);
        if bound.is_empty() {
            continue;
        }
        bound_any = true;
        for (oracle_index, attestation) in &bound {
            let announcement = info
                .oracle_announcements
                .get(*oracle_index)
                .ok_or_else(|| {
                    SettleError::Attestation(format!("oracle {oracle_index} has no announcement"))
                })?;
            attestation.validate(&secp, announcement).map_err(|error| {
                SettleError::Attestation(format!(
                    "the attestation from oracle {} for event {:?} does not verify against its \
                     announcement: {error}",
                    attestation.oracle_public_key, attestation.event_id
                ))
            })?;
        }
        let found = guarded(|| {
            info.get_range_info_and_oracle_signatures(&adaptor_info, &bound, start)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            SettleError::Attestation(format!("contract info {info_index}: {error}"))
        })?;
        let Some((range_info, oracle_signatures)) = found else {
            continue;
        };

        let cet_index = range.start + range_info.cet_index;
        let mut cet = contract
            .transactions
            .cets
            .get(cet_index)
            .cloned()
            .ok_or_else(|| SettleError::Incomplete(format!("CET {cet_index} out of bounds")))?;
        let secret = adaptor_secret(&oracle_signatures).map_err(SettleError::Attestation)?;
        let accept_signature = decrypt(
            accept_signatures.get(range_info.adaptor_index),
            &secret,
            "accepter",
        )?;
        let offer_signature = decrypt(
            offer_signatures.get(range_info.adaptor_index),
            &secret,
            "offerer",
        )?;
        complete(
            &secp,
            &mut cet,
            contract,
            (parts.offer.funding_pubkey, offer_signature),
            (parts.accept.funding_pubkey, accept_signature),
        )?;

        let report = dlc_verify_core::report(verification);
        let payouts = report
            .payouts
            .as_ref()
            .and_then(|payouts| payouts.cets.get(cet_index));
        let settled = SettledCet {
            index: cet_index,
            contract_info: info_index,
            outcome: payouts
                .map(|payouts| payouts.outcome.clone())
                .unwrap_or_else(|| format!("CET {cet_index}")),
            settles: payouts.map_or(CetOutcome::Unknown, |payouts| payouts.settles.clone()),
            attestations: bound
                .iter()
                .map(|(oracle_index, attestation)| BoundAttestation {
                    oracle_index: *oracle_index,
                    oracle_public_key: attestation.oracle_public_key.to_string(),
                    event_id: attestation.event_id.clone(),
                    outcomes: attestation.outcomes.clone(),
                })
                .collect(),
        };
        let outputs = payouts
            .map(|payouts| payouts.outputs.clone())
            .unwrap_or_default();
        return Ok(settlement(
            verification,
            contract,
            Kind::Cet,
            &cet,
            Some(settled),
            outputs,
            now,
        ));
    }
    if bound_any {
        Err(SettleError::NoCet(
            "the attested outcome matches no CET of this contract".to_owned(),
        ))
    } else {
        Err(SettleError::Attestation(
            "no attestation is for this contract: none matches an announcement's oracle key and \
             event id"
                .to_owned(),
        ))
    }
}

/// Completes the refund. It is only valid once its locktime has passed.
///
/// `now` (Unix seconds) only sets [`Broadcast::AfterTime::reached`].
///
/// # Errors
///
/// Fails when the messages are incomplete or a refund signature does not verify.
pub fn refund(verification: &Verification, now: Option<u64>) -> Result<Settlement, SettleError> {
    let parts = Parts::of(verification)?;
    let secp = Secp256k1::new();
    let mut transaction = parts.contract.transactions.refund.clone();
    complete(
        &secp,
        &mut transaction,
        parts.contract,
        (parts.offer.funding_pubkey, parts.sign.refund_signature),
        (parts.accept.funding_pubkey, parts.accept.refund_signature),
    )?;
    let report = dlc_verify_core::report(verification);
    let outputs = report
        .payouts
        .map(|payouts| payouts.refund.outputs)
        .unwrap_or_default();
    Ok(settlement(
        verification,
        parts.contract,
        Kind::Refund,
        &transaction,
        None,
        outputs,
        now,
    ))
}

/// What settling needs from a verification.
struct Parts<'a> {
    offer: &'a OfferDlc,
    accept: &'a AcceptDlc,
    sign: &'a SignDlc,
    contract: &'a RebuiltContract,
}

impl<'a> Parts<'a> {
    fn of(verification: &'a Verification) -> Result<Self, SettleError> {
        let messages = verification.messages.as_ref().ok_or_else(|| {
            SettleError::Incomplete("the offer does not decode; run verify to see why".to_owned())
        })?;
        let accept = messages.accept.as_ref().ok_or_else(|| {
            SettleError::Incomplete(
                "no accept message: it carries the accepter's signatures".to_owned(),
            )
        })?;
        let sign = messages.sign.as_ref().ok_or_else(|| {
            SettleError::Incomplete(
                "no sign message: it carries the offerer's signatures".to_owned(),
            )
        })?;
        let contract = verification.contract.as_ref().ok_or_else(|| {
            SettleError::Incomplete(
                "the contract could not be rebuilt from the messages; run verify to see why"
                    .to_owned(),
            )
        })?;
        if sign.contract_id != contract.contract_id {
            return Err(SettleError::Signature(format!(
                "the sign message names contract {}, but the messages rebuild contract {}",
                hex::encode(sign.contract_id),
                hex::encode(contract.contract_id)
            )));
        }
        Ok(Self {
            offer: &messages.offer,
            accept,
            sign,
            contract,
        })
    }
}

/// The attestations whose oracle key and event id match one of `info`'s announcements, with that
/// announcement's index. Exact duplicates are dropped.
fn bind(
    info: &ExecutionInfo,
    attestations: &[OracleAttestation],
) -> Vec<(usize, OracleAttestation)> {
    let mut bound: Vec<(usize, OracleAttestation)> = Vec::new();
    for attestation in attestations {
        let Some(index) = info.oracle_announcements.iter().position(|announcement| {
            announcement.oracle_public_key == attestation.oracle_public_key
                && announcement.oracle_event.event_id == attestation.event_id
        }) else {
            continue;
        };
        if !bound
            .iter()
            .any(|(other, seen)| *other == index && seen == attestation)
        {
            bound.push((index, attestation.clone()));
        }
    }
    bound
}

/// The adaptor secret: the sum of the `s` values of the oracle signatures, as DDK computes it.
fn adaptor_secret(signatures: &[Vec<SchnorrSignature>]) -> Result<SecretKey, String> {
    let mut secret: Option<SecretKey> = None;
    for signature in signatures.iter().flatten() {
        let (_, s) = ddk_dlc::secp_utils::schnorrsig_decompose(signature)
            .map_err(|error| format!("an oracle signature is malformed: {error}"))?;
        let s = SecretKey::from_slice(s)
            .map_err(|error| format!("an oracle signature's s value is invalid: {error}"))?;
        secret = Some(match secret {
            None => s,
            Some(sum) => sum.add_tweak(&Scalar::from(s)).map_err(|error| {
                format!("the oracle signatures do not sum to a secret: {error}")
            })?,
        });
    }
    secret.ok_or_else(|| "the attestation carries no signatures".to_owned())
}

fn decrypt(
    signature: Option<&EcdsaAdaptorSignature>,
    secret: &SecretKey,
    party: &str,
) -> Result<Signature, SettleError> {
    let signature = signature.ok_or_else(|| {
        SettleError::Signature(format!("the {party} has no adaptor signature for this CET"))
    })?;
    let mut decrypted = signature.decrypt(secret).map_err(|error| {
        SettleError::Signature(format!(
            "the {party}'s adaptor signature does not decrypt with the attestation: {error}"
        ))
    })?;
    decrypted.normalize_s();
    Ok(decrypted)
}

/// Checks both signatures against `transaction`'s funding input and puts them in its witness.
fn complete(
    secp: &Secp256k1<All>,
    transaction: &mut Transaction,
    contract: &RebuiltContract,
    offerer: (PublicKey, Signature),
    accepter: (PublicKey, Signature),
) -> Result<(), SettleError> {
    for ((pubkey, signature), party) in [(&offerer, "offerer"), (&accepter, "accepter")] {
        ddk_dlc::verify_tx_input_sig(
            secp,
            signature,
            transaction,
            0,
            &contract.transactions.funding_witness_script,
            contract.fund_output_value,
            pubkey,
        )
        .map_err(|error| {
            SettleError::Signature(format!("the {party}'s signature does not verify: {error}"))
        })?;
    }
    let input = transaction.input.first_mut().ok_or_else(|| {
        SettleError::Incomplete("the rebuilt transaction has no input".to_owned())
    })?;
    input.witness = ddk_dlc::util::multisig_witness(
        &contract.transactions.funding_witness_script,
        offerer,
        accepter,
    );
    Ok(())
}

fn settlement(
    verification: &Verification,
    contract: &RebuiltContract,
    kind: Kind,
    transaction: &Transaction,
    cet: Option<SettledCet>,
    outputs: Vec<PayoutOutput>,
    now: Option<u64>,
) -> Settlement {
    let paid: Amount = transaction.output.iter().map(|output| output.value).sum();
    let locktime = transaction.lock_time.to_consensus_u32();
    Settlement {
        schema: SETTLEMENT_SCHEMA,
        kind,
        contract_id: hex::encode(contract.contract_id),
        verification: verification.status,
        txid: transaction.compute_txid().to_string(),
        transaction: serialize_hex(transaction),
        vsize: u64::try_from(transaction.vsize()).unwrap_or(u64::MAX),
        fee_sat: contract
            .fund_output_value
            .checked_sub(paid)
            .map_or(0, Amount::to_sat),
        spends: Spends {
            txid: contract.transactions.fund.compute_txid().to_string(),
            vout: contract.fund_output_index,
            value_sat: contract.fund_output_value.to_sat(),
        },
        locktime: LocktimeSummary::new(locktime),
        broadcast: broadcast(locktime, now),
        cet,
        outputs,
    }
}

fn broadcast(locktime: u32, now: Option<u64>) -> Broadcast {
    match dlc_verify_core::time::locktime_kind(locktime) {
        LocktimeKind::None => Broadcast::Now,
        LocktimeKind::Height => Broadcast::AfterHeight { height: locktime },
        LocktimeKind::Time => {
            let unix = u64::from(locktime);
            Broadcast::AfterTime {
                unix,
                utc: format_unix(unix),
                reached: now.map(|now| now > unix),
            }
        }
    }
}

/// Runs `f`, turning a panic inside DDK into an error, as the verifier does.
fn guarded<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            Err(format!("DDK panicked: {message}"))
        }
    }
}
