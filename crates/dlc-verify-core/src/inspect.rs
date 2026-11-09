//! A readable dump of what DLC messages say, without verifying anything.

use bitcoin::Network;
use ddk_messages::contract_msgs::{
    ContractDescriptor, ContractInfo, ContractInfoInner, PayoutCurvePiece,
};
use ddk_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement, OracleInfo};
use ddk_messages::{AcceptDlc, OfferDlc, OverrideOutcome, PayoutScriptOverrides, SignDlc};
use serde::Serialize;

use crate::decode::{DecodeFailure, TlvRecordInfo, decode_all, tlv_records};
use crate::input::{Input, MessageKind};
use crate::network::{network_from_chain_hash, network_name};
use crate::summary::{FundingInputSummary, LocktimeSummary, ScriptSummary, TimeSummary};

/// The schema name of [`Inspection`] in JSON.
pub const INSPECT_SCHEMA: &str = "dlc-verify.inspect.v1";

/// What the messages say. Messages that do not decode are listed in `errors`.
#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    /// [`INSPECT_SCHEMA`].
    pub schema: &'static str,
    /// The offer, if it decodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<OfferSummary>,
    /// The accept, if given and it decodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<AcceptSummary>,
    /// The sign, if given and it decodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign: Option<SignSummary>,
    /// The messages that did not decode.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<DecodeFailure>,
}

/// An offer's contents.
#[derive(Clone, Debug, Serialize)]
pub struct OfferSummary {
    /// Protocol version.
    pub protocol_version: u32,
    /// Contract flags byte.
    pub contract_flags: u8,
    /// Names of the flags set.
    pub contract_flag_names: Vec<String>,
    /// Chain hash in hex, as written.
    pub chain_hash: String,
    /// The network the chain hash names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<&'static str>,
    /// Set when the chain hash is written in display byte order.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub chain_hash_reversed: bool,
    /// Temporary contract id.
    pub temporary_contract_id: String,
    /// Total collateral of both parties.
    pub total_collateral_sat: u64,
    /// The offering party's collateral.
    pub offer_collateral_sat: u64,
    /// The accepting party's collateral, total minus offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_collateral_sat: Option<u64>,
    /// The offering party's funding key.
    pub funding_pubkey: String,
    /// The offering party's payout script.
    pub payout: ScriptSummary,
    /// Payout serial id.
    pub payout_serial_id: u64,
    /// The offering party's change script.
    pub change: ScriptSummary,
    /// Change serial id.
    pub change_serial_id: u64,
    /// Funding output serial id.
    pub fund_output_serial_id: u64,
    /// Fee rate, sat/vB.
    pub fee_rate_per_vb: u64,
    /// CET locktime.
    pub cet_locktime: LocktimeSummary,
    /// Refund locktime.
    pub refund_locktime: LocktimeSummary,
    /// The offering party's funding inputs.
    pub funding_inputs: Vec<FundingInputSummary>,
    /// The contract.
    pub contract: ContractSummary,
    /// TLV records after the fixed fields.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tlvs: Vec<TlvRecordInfo>,
    /// The decoded payout-script-override record, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payout_overrides: Option<Vec<OverrideSummary>>,
    /// Set when the override record is present but does not decode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payout_overrides_error: Option<String>,
}

/// The contract info of an offer.
#[derive(Clone, Debug, Serialize)]
pub struct ContractSummary {
    /// `single` or `disjoint`.
    pub kind: &'static str,
    /// Each contract info, in offer order.
    pub infos: Vec<ContractInfoSummary>,
}

/// One contract info: payouts and the oracles that decide them.
#[derive(Clone, Debug, Serialize)]
pub struct ContractInfoSummary {
    /// The payouts.
    pub descriptor: DescriptorSummary,
    /// The oracles.
    pub oracle: OracleSummary,
}

/// A contract descriptor.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DescriptorSummary {
    /// One payout per outcome.
    Enum {
        /// Outcomes in descriptor order.
        outcomes: Vec<EnumOutcomeSummary>,
    },
    /// A payout curve over a numeric outcome.
    Numeric {
        /// Digits of the outcome.
        num_digits: u16,
        /// Curve pieces in order.
        pieces: Vec<PieceSummary>,
        /// Rounding intervals.
        rounding_intervals: Vec<RoundingSummary>,
    },
}

/// One enum outcome's payouts.
#[derive(Clone, Debug, Serialize)]
pub struct EnumOutcomeSummary {
    /// Outcome string.
    pub outcome: String,
    /// What the offering party receives.
    pub offer_payout_sat: u64,
    /// What the accepting party's output receives, total minus offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_payout_sat: Option<u64>,
}

/// A piece of a numeric payout curve.
#[derive(Clone, Debug, Serialize)]
pub struct PieceSummary {
    /// `polynomial` or `hyperbola`.
    pub kind: &'static str,
    /// The piece's left end: outcome and offer payout.
    pub from: PointSummary,
    /// The piece's right end.
    pub to: PointSummary,
}

/// A point on a payout curve.
#[derive(Clone, Debug, Serialize)]
pub struct PointSummary {
    /// The outcome value.
    pub outcome: u64,
    /// The offering party's payout there.
    pub offer_payout_sat: u64,
}

/// A rounding interval.
#[derive(Clone, Debug, Serialize)]
pub struct RoundingSummary {
    /// First outcome the interval applies to.
    pub begin: u64,
    /// Payouts are rounded to a multiple of this.
    pub rounding_mod: u64,
}

/// The oracles of a contract info.
#[derive(Clone, Debug, Serialize)]
pub struct OracleSummary {
    /// How many oracles must attest.
    pub threshold: u16,
    /// Announcements in offer order.
    pub announcements: Vec<AnnouncementSummary>,
    /// Multi-oracle numeric tolerance parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<OracleParamsSummary>,
}

/// Multi-oracle numeric tolerance parameters.
#[derive(Clone, Debug, Serialize)]
pub struct OracleParamsSummary {
    /// Largest allowed difference, as a power of two.
    pub max_error_exp: u16,
    /// Smallest guaranteed-to-fail difference, as a power of two.
    pub min_fail_exp: u16,
    /// Whether to maximize coverage.
    pub maximize_coverage: bool,
}

/// An oracle announcement.
#[derive(Clone, Debug, Serialize)]
pub struct AnnouncementSummary {
    /// The oracle's x-only public key.
    pub oracle_public_key: String,
    /// Event id.
    pub event_id: String,
    /// When the event matures.
    pub maturity: TimeSummary,
    /// Number of nonces.
    pub nonces: usize,
    /// What the oracle attests.
    pub event: EventSummary,
}

/// What an oracle attests.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EventSummary {
    /// One of a set of strings.
    Enum {
        /// The outcomes.
        outcomes: Vec<String>,
    },
    /// A number, digit by digit.
    Digits {
        /// Base.
        base: u16,
        /// Whether a sign digit precedes the number.
        is_signed: bool,
        /// Unit.
        unit: String,
        /// Power of ten applied to the value.
        precision: i32,
        /// Number of digits.
        nb_digits: u16,
    },
}

/// One payout-script override.
#[derive(Clone, Debug, Serialize)]
pub struct OverrideSummary {
    /// The enum outcome it covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// The numeric range it covers, both ends included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<[u64; 2]>,
    /// The script paid in place of the accepting party's.
    pub script: ScriptSummary,
}

/// An accept's contents.
#[derive(Clone, Debug, Serialize)]
pub struct AcceptSummary {
    /// Protocol version.
    pub protocol_version: u32,
    /// Temporary contract id.
    pub temporary_contract_id: String,
    /// The accepting party's collateral.
    pub accept_collateral_sat: u64,
    /// The accepting party's funding key.
    pub funding_pubkey: String,
    /// The accepting party's payout script.
    pub payout: ScriptSummary,
    /// Payout serial id.
    pub payout_serial_id: u64,
    /// The accepting party's change script.
    pub change: ScriptSummary,
    /// Change serial id.
    pub change_serial_id: u64,
    /// The accepting party's funding inputs.
    pub funding_inputs: Vec<FundingInputSummary>,
    /// Number of CET adaptor signatures.
    pub cet_adaptor_signatures: usize,
    /// Whether negotiation fields are present.
    pub negotiation_fields: bool,
    /// TLV records after the fixed fields.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tlvs: Vec<TlvRecordInfo>,
}

/// A sign's contents.
#[derive(Clone, Debug, Serialize)]
pub struct SignSummary {
    /// Protocol version.
    pub protocol_version: u32,
    /// Contract id.
    pub contract_id: String,
    /// Number of CET adaptor signatures.
    pub cet_adaptor_signatures: usize,
    /// Witness element count of each funding signature.
    pub funding_witness_elements: Vec<usize>,
    /// TLV records after the fixed fields.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tlvs: Vec<TlvRecordInfo>,
}

/// Decodes and summarizes every message in `input`.
pub fn inspect(input: &Input) -> Inspection {
    let (offer, accept, sign) = decode_all(input);
    let mut errors = Vec::new();
    let offer = offer.map_err(|error| errors.push(error)).ok();
    let accept = accept.and_then(|result| result.map_err(|error| errors.push(error)).ok());
    let sign = sign.and_then(|result| result.map_err(|error| errors.push(error)).ok());
    let network = offer
        .as_ref()
        .and_then(|offer| network_from_chain_hash(&offer.chain_hash))
        .map(|matched| matched.network);
    Inspection {
        schema: INSPECT_SCHEMA,
        offer: offer.as_ref().map(summarize_offer),
        accept: accept
            .as_ref()
            .map(|accept| summarize_accept(accept, network)),
        sign: sign.as_ref().map(summarize_sign),
        errors,
    }
}

/// Names of the contract flags set in `flags`.
pub fn contract_flag_names(flags: u8) -> Vec<String> {
    (0..8)
        .filter(|bit| flags & (1 << bit) != 0)
        .map(|bit| match 1u8 << bit {
            0x01 => "refund-to-accepter".to_owned(),
            other => format!("unknown-{other:#04x}"),
        })
        .collect()
}

/// Summarizes an offer.
pub fn summarize_offer(offer: &OfferDlc) -> OfferSummary {
    let matched = network_from_chain_hash(&offer.chain_hash);
    let network = matched.map(|matched| matched.network);
    let total = offer.get_total_collateral();
    let (payout_overrides, payout_overrides_error) = match offer.tlvs.get::<PayoutScriptOverrides>()
    {
        Ok(Some(record)) => (Some(summarize_overrides(&record, network)), None),
        Ok(None) => (None, None),
        Err(error) => (None, Some(format!("{error:?}"))),
    };
    OfferSummary {
        protocol_version: offer.protocol_version,
        contract_flags: offer.contract_flags,
        contract_flag_names: contract_flag_names(offer.contract_flags),
        chain_hash: hex::encode(offer.chain_hash),
        network: network.map(network_name),
        chain_hash_reversed: matched.is_some_and(|matched| matched.reversed),
        temporary_contract_id: hex::encode(offer.temporary_contract_id),
        total_collateral_sat: total.to_sat(),
        offer_collateral_sat: offer.offer_collateral.to_sat(),
        accept_collateral_sat: total
            .checked_sub(offer.offer_collateral)
            .map(|amount| amount.to_sat()),
        funding_pubkey: offer.funding_pubkey.to_string(),
        payout: ScriptSummary::new(&offer.payout_spk, network),
        payout_serial_id: offer.payout_serial_id,
        change: ScriptSummary::new(&offer.change_spk, network),
        change_serial_id: offer.change_serial_id,
        fund_output_serial_id: offer.fund_output_serial_id,
        fee_rate_per_vb: offer.fee_rate_per_vb,
        cet_locktime: LocktimeSummary::new(offer.cet_locktime),
        refund_locktime: LocktimeSummary::new(offer.refund_locktime),
        funding_inputs: offer
            .funding_inputs
            .iter()
            .map(|input| FundingInputSummary::new(input, network))
            .collect(),
        contract: summarize_contract(&offer.contract_info),
        tlvs: tlv_records(MessageKind::Offer, &offer.tlvs),
        payout_overrides,
        payout_overrides_error,
    }
}

fn summarize_overrides(
    record: &PayoutScriptOverrides,
    network: Option<Network>,
) -> Vec<OverrideSummary> {
    record
        .overrides
        .iter()
        .map(|item| {
            let (outcome, range) = match &item.outcome {
                OverrideOutcome::Enum { outcome } => (Some(outcome.clone()), None),
                OverrideOutcome::Numeric { start, end } => (None, Some([*start, *end])),
            };
            OverrideSummary {
                outcome,
                range,
                script: ScriptSummary::new(&item.script_pubkey, network),
            }
        })
        .collect()
}

fn summarize_contract(contract: &ContractInfo) -> ContractSummary {
    match contract {
        ContractInfo::SingleContractInfo(single) => ContractSummary {
            kind: "single",
            infos: vec![summarize_info(
                &single.contract_info,
                single.total_collateral.to_sat(),
            )],
        },
        ContractInfo::DisjointContractInfo(disjoint) => ContractSummary {
            kind: "disjoint",
            infos: disjoint
                .contract_infos
                .iter()
                .map(|info| summarize_info(info, disjoint.total_collateral.to_sat()))
                .collect(),
        },
    }
}

fn summarize_info(info: &ContractInfoInner, total: u64) -> ContractInfoSummary {
    let descriptor = match &info.contract_descriptor {
        ContractDescriptor::EnumeratedContractDescriptor(descriptor) => DescriptorSummary::Enum {
            outcomes: descriptor
                .payouts
                .iter()
                .map(|payout| EnumOutcomeSummary {
                    outcome: payout.outcome.clone(),
                    offer_payout_sat: payout.offer_payout.to_sat(),
                    accept_payout_sat: total.checked_sub(payout.offer_payout.to_sat()),
                })
                .collect(),
        },
        ContractDescriptor::NumericOutcomeContractDescriptor(descriptor) => {
            let function = &descriptor.payout_function;
            let pieces = function
                .payout_function_pieces
                .iter()
                .enumerate()
                .map(|(index, piece)| {
                    let next = function
                        .payout_function_pieces
                        .get(index + 1)
                        .map_or(&function.last_endpoint, |next| &next.end_point);
                    PieceSummary {
                        kind: match piece.payout_curve_piece {
                            PayoutCurvePiece::PolynomialPayoutCurvePiece(_) => "polynomial",
                            PayoutCurvePiece::HyperbolaPayoutCurvePiece(_) => "hyperbola",
                        },
                        from: PointSummary {
                            outcome: piece.end_point.event_outcome,
                            offer_payout_sat: piece.end_point.outcome_payout.to_sat(),
                        },
                        to: PointSummary {
                            outcome: next.event_outcome,
                            offer_payout_sat: next.outcome_payout.to_sat(),
                        },
                    }
                })
                .collect();
            DescriptorSummary::Numeric {
                num_digits: descriptor.num_digits,
                pieces,
                rounding_intervals: descriptor
                    .rounding_intervals
                    .intervals
                    .iter()
                    .map(|interval| RoundingSummary {
                        begin: interval.begin_interval,
                        rounding_mod: interval.rounding_mod,
                    })
                    .collect(),
            }
        }
    };
    ContractInfoSummary {
        descriptor,
        oracle: summarize_oracle(&info.oracle_info),
    }
}

fn summarize_oracle(info: &OracleInfo) -> OracleSummary {
    match info {
        OracleInfo::Single(single) => OracleSummary {
            threshold: 1,
            announcements: vec![summarize_announcement(&single.oracle_announcement)],
            params: None,
        },
        OracleInfo::Multi(multi) => OracleSummary {
            threshold: multi.threshold,
            announcements: multi
                .oracle_announcements
                .iter()
                .map(summarize_announcement)
                .collect(),
            params: multi
                .oracle_params
                .as_ref()
                .map(|params| OracleParamsSummary {
                    max_error_exp: params.max_error_exp,
                    min_fail_exp: params.min_fail_exp,
                    maximize_coverage: params.maximize_coverage,
                }),
        },
    }
}

/// Summarizes an oracle announcement.
pub fn summarize_announcement(announcement: &OracleAnnouncement) -> AnnouncementSummary {
    let event = &announcement.oracle_event;
    AnnouncementSummary {
        oracle_public_key: announcement.oracle_public_key.to_string(),
        event_id: event.event_id.clone(),
        maturity: TimeSummary::new(u64::from(event.event_maturity_epoch)),
        nonces: event.oracle_nonces.len(),
        event: match &event.event_descriptor {
            EventDescriptor::EnumEvent(descriptor) => EventSummary::Enum {
                outcomes: descriptor.outcomes.clone(),
            },
            EventDescriptor::DigitDecompositionEvent(descriptor) => EventSummary::Digits {
                base: descriptor.base,
                is_signed: descriptor.is_signed,
                unit: descriptor.unit.clone(),
                precision: descriptor.precision,
                nb_digits: descriptor.nb_digits,
            },
        },
    }
}

/// Summarizes an accept.
pub fn summarize_accept(accept: &AcceptDlc, network: Option<Network>) -> AcceptSummary {
    AcceptSummary {
        protocol_version: accept.protocol_version,
        temporary_contract_id: hex::encode(accept.temporary_contract_id),
        accept_collateral_sat: accept.accept_collateral.to_sat(),
        funding_pubkey: accept.funding_pubkey.to_string(),
        payout: ScriptSummary::new(&accept.payout_spk, network),
        payout_serial_id: accept.payout_serial_id,
        change: ScriptSummary::new(&accept.change_spk, network),
        change_serial_id: accept.change_serial_id,
        funding_inputs: accept
            .funding_inputs
            .iter()
            .map(|input| FundingInputSummary::new(input, network))
            .collect(),
        cet_adaptor_signatures: accept.cet_adaptor_signatures.ecdsa_adaptor_signatures.len(),
        negotiation_fields: accept.negotiation_fields.is_some(),
        tlvs: tlv_records(MessageKind::Accept, &accept.tlvs),
    }
}

/// Summarizes a sign.
pub fn summarize_sign(sign: &SignDlc) -> SignSummary {
    SignSummary {
        protocol_version: sign.protocol_version,
        contract_id: hex::encode(sign.contract_id),
        cet_adaptor_signatures: sign.cet_adaptor_signatures.ecdsa_adaptor_signatures.len(),
        funding_witness_elements: sign
            .funding_signatures
            .funding_signatures
            .iter()
            .map(|signature| signature.witness_elements.len())
            .collect(),
        tlvs: tlv_records(MessageKind::Sign, &sign.tlvs),
    }
}
