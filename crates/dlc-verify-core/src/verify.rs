//! The verifier: every check in the catalogue, from decoding to signatures.
//!
//! [`verify`] decodes the messages, checks their structure, the oracle announcements and the
//! locktimes, rebuilds the funding transaction, CETs and refund with DDK, and verifies every
//! signature the messages carry against the rebuilt transactions. Each check has a stable id
//! ([`CHECK_IDS`]) and ends as pass, warn, fail or skip. A check whose inputs are missing or
//! failed is skipped and says why.
//!
//! Nothing here reads the clock: the current time, for the maturity check, comes in
//! [`Options::now`].

use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Witness};
use ddk_dlc::dlc_input::{DlcInputInfo, verify_dlc_funding_input_signature};
use ddk_dlc::secp256k1_zkp::{All, EcdsaAdaptorSignature, PublicKey, Secp256k1};
use ddk_dlc::{DlcTransactions, FeeRule, PartyParams, TxInputInfo};
use ddk_manager::contract::cet_records::validate_cet_records;
use ddk_manager::contract::contract_info::ContractInfo as ExecutionInfo;
use ddk_manager::contract::execution_contract_infos;
use ddk_manager::contract::transactions::{
    ContractTerms, ContractTransactions, build_contract_transactions,
};
use ddk_messages::contract_msgs::{
    ContractDescriptor, ContractInfo, ContractInfoInner, PayoutCurvePiece, PayoutPoint,
};
use ddk_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement, OracleInfo};
use ddk_messages::{
    AcceptDlc, CetAdaptorSignatures, FundingInput, FundingSignature, OfferDlc,
    PayoutScriptOverrides, SignDlc,
};
use serde::Serialize;

use crate::decode::{DecodeFailure, Messages, decode_all, tlv_records};
use crate::input::{Input, MessageKind};
use crate::inspect::contract_flag_names;
use crate::summary::spent_output;
use crate::time::{LocktimeKind, format_duration, format_unix, locktime_kind};

/// The protocol version this verifier supports.
pub const PROTOCOL_VERSION: u32 = 1;

/// The highest fee rate DDK accepts, in sat/vB.
pub const MAX_FEE_RATE_PER_VB: u64 = 6250;

/// The contract flags this verifier understands: DDK's refund-to-accepter flag.
pub const KNOWN_CONTRACT_FLAGS: u8 = ddk_dlc::REFUND_TO_ACCEPTER_FLAG;

/// The most contract infos a disjoint contract may have.
pub const MAX_CONTRACT_INFOS: usize = 32;

/// The most oracle announcements one contract info may have.
pub const MAX_ORACLES: usize = 32;

/// The most outcomes an enum contract info or enum event may have.
pub const MAX_ENUM_OUTCOMES: usize = 4096;

/// The most adaptor signatures an enum contract info may need (outcomes times oracle
/// combinations).
pub const MAX_ENUM_ADAPTOR_SIGNATURES: u128 = 100_000;

/// The most funding inputs one party may have.
pub const MAX_FUNDING_INPUTS: usize = 512;

/// Every check, in report order.
pub const CHECK_IDS: [&str; 27] = [
    "decode.offer",
    "decode.accept",
    "decode.sign",
    "decode.unknown-tlvs",
    "structure.protocol-version",
    "structure.temp-id",
    "structure.contract-flags",
    "structure.collateral",
    "structure.serial-ids",
    "structure.funding-inputs",
    "structure.fee-rate",
    "structure.limits",
    "oracle.announcement-signature",
    "oracle.outcome-coverage",
    "oracle.maturity",
    "locktime.cet",
    "locktime.refund",
    "locktime.units",
    "tx.build",
    "tx.funding-output",
    "tx.contract-id",
    "sig.accept.cet-adaptors",
    "sig.accept.refund",
    "sig.offer.cet-adaptors",
    "sig.offer.refund",
    "sig.offer.funding",
    "sig.contract-id",
];

/// What the verifier needs besides the messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// The current Unix time, for the maturity check. Without it, maturity is not compared with
    /// the present.
    pub now: Option<u64>,
}

/// How one check ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// The check passed.
    Pass,
    /// The check passed with something worth a look.
    Warn,
    /// The check failed: the contract is not what it should be.
    Fail,
    /// The check could not run; the detail says why.
    Skip,
}

/// The overall result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Every check passed (some perhaps with warnings).
    Pass,
    /// At least one check failed.
    Fail,
    /// Nothing failed, but some checks could not run: a message is missing or a funding witness
    /// could not be checked.
    Incomplete,
}

impl Status {
    /// The lowercase name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Incomplete => "incomplete",
        }
    }
}

impl CheckStatus {
    /// The lowercase name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

/// One check's result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    /// The check id, one of [`CHECK_IDS`].
    pub id: &'static str,
    /// How it ended.
    pub status: CheckStatus,
    /// What was found, in a sentence.
    pub detail: String,
}

/// The contract as DDK rebuilds it from the messages.
#[derive(Clone)]
pub struct RebuiltContract {
    /// The CET fee rule the messages were built with.
    pub fee_rule: FeeRule,
    /// The contract id: the funding txid and output index mixed into the temporary id.
    pub contract_id: [u8; 32],
    /// The funding output's index in the funding transaction.
    pub fund_output_index: usize,
    /// The funding output's value.
    pub fund_output_value: Amount,
    /// The unsigned funding transaction, every CET and the refund.
    pub transactions: DlcTransactions,
    /// Each execution info's CETs within `transactions.cets`.
    pub cet_ranges: Vec<Range<usize>>,
    /// The contract infos in DDK's execution form, one per offered contract info.
    pub execution_infos: Vec<ExecutionInfo>,
}

impl std::fmt::Debug for RebuiltContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RebuiltContract")
            .field("fee_rule", &self.fee_rule)
            .field("contract_id", &hex::encode(self.contract_id))
            .field("fund_txid", &self.transactions.fund.compute_txid())
            .field("fund_output_index", &self.fund_output_index)
            .field("fund_output_value", &self.fund_output_value)
            .field("cets", &self.transactions.cets.len())
            .field("cet_ranges", &self.cet_ranges)
            .finish_non_exhaustive()
    }
}

/// The name of a fee rule as reports show it.
pub const fn fee_rule_name(rule: FeeRule) -> &'static str {
    match rule {
        FeeRule::CounterpartyPayout => "counterparty-payout",
        FeeRule::OwnPayoutOnly => "own-payout-only",
    }
}

/// Everything [`verify`] found.
#[derive(Clone, Debug)]
pub struct Verification {
    /// The overall result.
    pub status: Status,
    /// Every check in [`CHECK_IDS`] order.
    pub checks: Vec<Check>,
    /// The decoded messages; `None` when the offer does not decode. A message that does not
    /// decode is `None` inside.
    pub messages: Option<Messages>,
    /// The rebuilt contract, when the rebuild succeeded.
    pub contract: Option<RebuiltContract>,
}

impl Verification {
    /// The result of check `id`.
    pub fn check(&self, id: &str) -> Option<&Check> {
        self.checks.iter().find(|check| check.id == id)
    }
}

/// Runs every check on `input`.
pub fn verify(input: &Input, options: &Options) -> Verification {
    let secp = Secp256k1::new();
    let mut checks = Checks::default();

    let (offer, accept, sign) = decode_all(input);
    let offer = match offer {
        Ok(offer) => offer,
        Err(failure) => {
            checks.set("decode.offer", CheckStatus::Fail, failure.error);
            return finish(checks, "not run: decode.offer failed", None, None);
        }
    };
    checks.set(
        "decode.offer",
        CheckStatus::Pass,
        canonical(input.offer.len()),
    );
    let accept = decoded(
        &mut checks,
        "decode.accept",
        input,
        MessageKind::Accept,
        accept,
    );
    let sign = decoded(&mut checks, "decode.sign", input, MessageKind::Sign, sign);
    checks.record(
        "decode.unknown-tlvs",
        unknown_tlvs(&offer, accept.as_ref(), sign.as_ref()),
    );

    let shape = Shape::new(&offer);
    structure_checks(&mut checks, &offer, accept.as_ref(), sign.as_ref(), &shape);

    checks.record(
        "oracle.announcement-signature",
        announcement_signatures(&secp, &shape),
    );
    let mut execution_infos = None;
    if checks.open(
        "oracle.outcome-coverage",
        &["structure.limits", "structure.collateral"],
    ) {
        match outcome_coverage(&offer, &shape) {
            Ok((outcome, infos)) => {
                checks.record("oracle.outcome-coverage", Ok(outcome));
                execution_infos = Some(infos);
            }
            Err(error) => {
                checks.record("oracle.outcome-coverage", Err(error));
            }
        }
    }
    checks.record("oracle.maturity", maturity(&shape, options.now));
    checks.record("locktime.cet", cet_locktime(&offer, &shape));
    checks.record("locktime.refund", refund_locktime(&offer, &shape));
    checks.record("locktime.units", locktime_units(&offer));

    let contract = rebuild_checks(
        &mut checks,
        &secp,
        &offer,
        accept.as_ref(),
        sign.as_ref(),
        execution_infos,
    );
    if let (Some(contract), Some(accept)) = (contract.as_ref(), accept.as_ref()) {
        signature_checks(
            &mut checks,
            &secp,
            &offer,
            accept,
            sign.as_ref(),
            contract,
            shape.total,
        );
    }

    let messages = Messages {
        offer,
        accept,
        sign,
    };
    finish(checks, "not run", Some(messages), contract)
}

fn finish(
    checks: Checks,
    missing: &str,
    messages: Option<Messages>,
    contract: Option<RebuiltContract>,
) -> Verification {
    let checks = checks.finish(missing);
    let status = if checks.iter().any(|check| check.status == CheckStatus::Fail) {
        Status::Fail
    } else if checks.iter().any(|check| check.status == CheckStatus::Skip) {
        Status::Incomplete
    } else {
        Status::Pass
    };
    Verification {
        status,
        checks,
        messages,
        contract,
    }
}

/// A check's outcome other than failure.
enum Outcome {
    Pass(String),
    Warn(String),
    Skip(String),
}

type CheckResult = Result<Outcome, String>;

#[derive(Default)]
struct Checks(Vec<Check>);

impl Checks {
    fn set(&mut self, id: &'static str, status: CheckStatus, detail: impl Into<String>) {
        self.0.retain(|check| check.id != id);
        self.0.push(Check {
            id,
            status,
            detail: detail.into(),
        });
    }

    /// Records a result; returns whether the check passed (with or without a warning).
    fn record(&mut self, id: &'static str, result: CheckResult) -> bool {
        let (status, detail) = match result {
            Ok(Outcome::Pass(detail)) => (CheckStatus::Pass, detail),
            Ok(Outcome::Warn(detail)) => (CheckStatus::Warn, detail),
            Ok(Outcome::Skip(detail)) => (CheckStatus::Skip, detail),
            Err(detail) => (CheckStatus::Fail, detail),
        };
        self.set(id, status, detail);
        matches!(status, CheckStatus::Pass | CheckStatus::Warn)
    }

    fn get(&self, id: &str) -> Option<&Check> {
        self.0.iter().find(|check| check.id == id)
    }

    /// Why a check that needs `deps` cannot run, if it cannot.
    fn blocked(&self, deps: &[&'static str]) -> Option<String> {
        deps.iter().find_map(|dep| match self.get(dep) {
            Some(check) => match check.status {
                CheckStatus::Pass | CheckStatus::Warn => None,
                CheckStatus::Fail => Some(format!("not run: {dep} failed")),
                CheckStatus::Skip => Some(check.detail.clone()),
            },
            None => Some(format!("not run: {dep} did not run")),
        })
    }

    /// Whether check `id` can run; if not, records it as skipped.
    fn open(&mut self, id: &'static str, deps: &[&'static str]) -> bool {
        match self.blocked(deps) {
            Some(reason) => {
                self.set(id, CheckStatus::Skip, reason);
                false
            }
            None => true,
        }
    }

    /// Runs `check` if `deps` passed, otherwise records `id` as skipped.
    fn gated(
        &mut self,
        id: &'static str,
        deps: &[&'static str],
        check: impl FnOnce() -> CheckResult,
    ) {
        if self.open(id, deps) {
            self.record(id, check());
        }
    }

    fn finish(self, missing: &str) -> Vec<Check> {
        CHECK_IDS
            .iter()
            .map(|id| {
                self.get(id).cloned().unwrap_or_else(|| Check {
                    id,
                    status: CheckStatus::Skip,
                    detail: missing.to_owned(),
                })
            })
            .collect()
    }
}

/// Runs `f`, turning a panic inside DDK into an error. DDK's builders assume validated input and
/// panic on some malformed contracts; the checks before each call reject those, and this is the
/// second line of defence. (In WebAssembly a panic aborts instead.)
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

fn canonical(bytes: usize) -> String {
    format!("{bytes} bytes, canonical encoding")
}

fn decoded<T>(
    checks: &mut Checks,
    id: &'static str,
    input: &Input,
    kind: MessageKind,
    result: Option<Result<T, DecodeFailure>>,
) -> Option<T> {
    match result {
        None => {
            checks.set(id, CheckStatus::Skip, format!("no {kind} message given"));
            None
        }
        Some(Err(failure)) => {
            checks.set(id, CheckStatus::Fail, failure.error);
            None
        }
        Some(Ok(message)) => {
            let bytes = input.message(kind).map_or(0, <[u8]>::len);
            checks.set(id, CheckStatus::Pass, canonical(bytes));
            Some(message)
        }
    }
}

fn unknown_tlvs(
    offer: &OfferDlc,
    accept: Option<&AcceptDlc>,
    sign: Option<&SignDlc>,
) -> CheckResult {
    let mut records = vec![(
        MessageKind::Offer,
        tlv_records(MessageKind::Offer, &offer.tlvs),
    )];
    if let Some(accept) = accept {
        records.push((
            MessageKind::Accept,
            tlv_records(MessageKind::Accept, &accept.tlvs),
        ));
    }
    if let Some(sign) = sign {
        records.push((
            MessageKind::Sign,
            tlv_records(MessageKind::Sign, &sign.tlvs),
        ));
    }
    let mut known = Vec::new();
    let mut ignored = Vec::new();
    for (kind, list) in &records {
        for record in list {
            match record.known {
                Some(name) => known.push(format!("{kind}: {name} ({})", record.tlv_type)),
                None if record.required => {
                    return Err(format!(
                        "the {kind} carries TLV type {}, which is even (required) and unknown to \
                         this verifier",
                        record.tlv_type
                    ));
                }
                None => ignored.push(format!(
                    "{kind}: unknown TLV type {} ({} bytes)",
                    record.tlv_type, record.length
                )),
            }
        }
    }
    offer.tlvs.get::<PayoutScriptOverrides>().map_err(|error| {
        format!("the offer's payout-script-overrides record is malformed: {error:?}")
    })?;
    if !ignored.is_empty() {
        let mut all = known;
        all.extend(ignored.iter().cloned());
        return Ok(Outcome::Warn(format!(
            "{}; unknown odd records are ignored and do not change the transactions",
            all.join(", ")
        )));
    }
    if known.is_empty() {
        Ok(Outcome::Pass("no TLV records".to_owned()))
    } else {
        Ok(Outcome::Pass(known.join(", ")))
    }
}

/// The offer's contract infos, flattened.
struct Shape<'a> {
    total: Amount,
    disjoint: bool,
    infos: Vec<&'a ContractInfoInner>,
}

impl<'a> Shape<'a> {
    fn new(offer: &'a OfferDlc) -> Self {
        match &offer.contract_info {
            ContractInfo::SingleContractInfo(single) => Self {
                total: single.total_collateral,
                disjoint: false,
                infos: vec![&single.contract_info],
            },
            ContractInfo::DisjointContractInfo(disjoint) => Self {
                total: disjoint.total_collateral,
                disjoint: true,
                infos: disjoint.contract_infos.iter().collect(),
            },
        }
    }

    fn announcements(&self) -> impl Iterator<Item = &'a OracleAnnouncement> + '_ {
        self.infos
            .iter()
            .flat_map(|info| announcements(&info.oracle_info))
    }

    /// The earliest and latest oracle maturity, if there are announcements.
    fn maturities(&self) -> Option<(u32, u32)> {
        let epochs = || {
            self.announcements()
                .map(|announcement| announcement.oracle_event.event_maturity_epoch)
        };
        Some((epochs().min()?, epochs().max()?))
    }
}

fn announcements(info: &OracleInfo) -> Vec<&OracleAnnouncement> {
    match info {
        OracleInfo::Single(single) => vec![&single.oracle_announcement],
        OracleInfo::Multi(multi) => multi.oracle_announcements.iter().collect(),
    }
}

fn threshold(info: &OracleInfo) -> u16 {
    match info {
        OracleInfo::Single(_) => 1,
        OracleInfo::Multi(multi) => multi.threshold,
    }
}

fn structure_checks(
    checks: &mut Checks,
    offer: &OfferDlc,
    accept: Option<&AcceptDlc>,
    sign: Option<&SignDlc>,
    shape: &Shape<'_>,
) {
    checks.record(
        "structure.protocol-version",
        protocol_version(offer, accept, sign),
    );
    checks.gated("structure.temp-id", &["decode.accept"], || {
        temp_id(offer, accept)
    });
    checks.record(
        "structure.contract-flags",
        contract_flags(offer.contract_flags),
    );
    checks.record("structure.collateral", collateral(offer, accept, shape));
    checks.record("structure.serial-ids", serial_ids(offer, accept));
    checks.record("structure.funding-inputs", funding_inputs(offer, accept));
    checks.record("structure.fee-rate", fee_rate(offer.fee_rate_per_vb));
    checks.record("structure.limits", limits(shape));
}

fn protocol_version(
    offer: &OfferDlc,
    accept: Option<&AcceptDlc>,
    sign: Option<&SignDlc>,
) -> CheckResult {
    let mut versions = vec![(MessageKind::Offer, offer.protocol_version)];
    if let Some(accept) = accept {
        versions.push((MessageKind::Accept, accept.protocol_version));
    }
    if let Some(sign) = sign {
        versions.push((MessageKind::Sign, sign.protocol_version));
    }
    if let Some((kind, version)) = versions
        .iter()
        .find(|(_, version)| *version != PROTOCOL_VERSION)
    {
        return Err(format!(
            "the {kind} has protocol version {version}; only version {PROTOCOL_VERSION} is \
             supported"
        ));
    }
    if accept.is_some_and(|accept| accept.negotiation_fields.is_some()) {
        return Err("the accept carries negotiation fields, which DDK does not support".to_owned());
    }
    let names: Vec<&str> = versions.iter().map(|(kind, _)| kind.name()).collect();
    Ok(Outcome::Pass(format!(
        "version {PROTOCOL_VERSION} ({})",
        names.join(", ")
    )))
}

fn temp_id(offer: &OfferDlc, accept: Option<&AcceptDlc>) -> CheckResult {
    let accept = accept.ok_or("no accept message")?;
    if accept.temporary_contract_id != offer.temporary_contract_id {
        return Err(format!(
            "the accept answers temporary contract id {}, but the offer's is {}",
            hex::encode(accept.temporary_contract_id),
            hex::encode(offer.temporary_contract_id)
        ));
    }
    Ok(Outcome::Pass(format!(
        "{} on both messages",
        hex::encode(offer.temporary_contract_id)
    )))
}

fn contract_flags(flags: u8) -> CheckResult {
    let unknown = flags & !KNOWN_CONTRACT_FLAGS;
    if unknown != 0 {
        return Err(format!(
            "unknown contract flag bits {unknown:#04x}; DDK would build different transactions"
        ));
    }
    let names = contract_flag_names(flags);
    Ok(Outcome::Pass(if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }))
}

fn collateral(offer: &OfferDlc, accept: Option<&AcceptDlc>, shape: &Shape<'_>) -> CheckResult {
    let total = shape.total;
    if total == Amount::ZERO {
        return Err("the total collateral is zero".to_owned());
    }
    if total > Amount::MAX_MONEY {
        return Err(format!("the total collateral {total} is more than 21M BTC"));
    }
    let Some(accept_share) = total.checked_sub(offer.offer_collateral) else {
        return Err(format!(
            "the offerer puts in {}, more than the {} total",
            offer.offer_collateral, total
        ));
    };
    if let Some(accept) = accept
        && accept.accept_collateral != accept_share
    {
        return Err(format!(
            "the accepter puts in {}, but the total {} less the offerer's {} is {}",
            accept.accept_collateral, total, offer.offer_collateral, accept_share
        ));
    }
    for (index, info) in shape.infos.iter().enumerate() {
        match &info.contract_descriptor {
            ContractDescriptor::EnumeratedContractDescriptor(descriptor) => {
                for payout in &descriptor.payouts {
                    if payout.offer_payout > total {
                        return Err(format!(
                            "contract info {index}: outcome {:?} pays the offerer {}, more than \
                             the {total} total",
                            payout.outcome, payout.offer_payout
                        ));
                    }
                }
            }
            ContractDescriptor::NumericOutcomeContractDescriptor(descriptor) => {
                let function = &descriptor.payout_function;
                let points = function
                    .payout_function_pieces
                    .iter()
                    .flat_map(|piece| {
                        let inner: &[PayoutPoint] = match &piece.payout_curve_piece {
                            PayoutCurvePiece::PolynomialPayoutCurvePiece(polynomial) => {
                                &polynomial.payout_points
                            }
                            PayoutCurvePiece::HyperbolaPayoutCurvePiece(_) => &[],
                        };
                        std::iter::once(&piece.end_point).chain(inner)
                    })
                    .chain(std::iter::once(&function.last_endpoint));
                for point in points {
                    if point.outcome_payout > total {
                        return Err(format!(
                            "contract info {index}: the payout at outcome {} is {}, more than the \
                             {total} total",
                            point.event_outcome, point.outcome_payout
                        ));
                    }
                }
            }
        }
    }
    Ok(Outcome::Pass(format!(
        "{} sat total: offerer {} sat, accepter {} sat",
        total.to_sat(),
        offer.offer_collateral.to_sat(),
        accept_share.to_sat()
    )))
}

fn serial_ids(offer: &OfferDlc, accept: Option<&AcceptDlc>) -> CheckResult {
    let mut inputs: Vec<u64> = offer
        .funding_inputs
        .iter()
        .chain(accept.map_or(&[][..], |accept| &accept.funding_inputs))
        .map(|input| input.input_serial_id)
        .collect();
    inputs.sort_unstable();
    if let Some(pair) = inputs.windows(2).find(|pair| pair.first() == pair.get(1)) {
        return Err(format!(
            "funding input serial id {} is used twice",
            pair.first().copied().unwrap_or_default()
        ));
    }
    let mut outputs = vec![
        ("the funding output", offer.fund_output_serial_id),
        ("the offerer's change output", offer.change_serial_id),
    ];
    if let Some(accept) = accept {
        outputs.push(("the accepter's change output", accept.change_serial_id));
    }
    for (index, (name, id)) in outputs.iter().enumerate() {
        if let Some((other, _)) = outputs
            .iter()
            .skip(index + 1)
            .find(|(_, other_id)| other_id == id)
        {
            return Err(format!("{name} and {other} share serial id {id}"));
        }
    }
    let mut payouts = 1;
    if let Some(accept) = accept {
        payouts += 1;
        if accept.payout_serial_id == offer.payout_serial_id {
            return Err(format!(
                "both parties' CET payout outputs have serial id {}",
                offer.payout_serial_id
            ));
        }
    }
    Ok(Outcome::Pass(format!(
        "{} funding input, {} funding transaction output and {payouts} payout serial ids, all \
         distinct",
        inputs.len(),
        outputs.len()
    )))
}

/// One party's funding inputs, checked: the outputs they spend and their total.
struct PartyFunding {
    count: usize,
    total: Amount,
    outpoints: Vec<bitcoin::OutPoint>,
}

fn party_funding(party: &str, inputs: &[FundingInput]) -> Result<PartyFunding, String> {
    if inputs.len() > MAX_FUNDING_INPUTS {
        return Err(format!(
            "the {party} has {} funding inputs, more than {MAX_FUNDING_INPUTS}",
            inputs.len()
        ));
    }
    let mut total = Amount::ZERO;
    let mut outpoints = Vec::with_capacity(inputs.len());
    for input in inputs {
        let spent = spent_output(input).map_err(|error| {
            format!(
                "the {party}'s funding input serial id {}: {error}",
                input.input_serial_id
            )
        })?;
        if spent.txout.value > Amount::MAX_MONEY {
            return Err(format!(
                "the {party}'s funding input serial id {} spends {}, more than 21M BTC",
                input.input_serial_id, spent.txout.value
            ));
        }
        total = total
            .checked_add(spent.txout.value)
            .filter(|total| *total <= Amount::MAX_MONEY)
            .ok_or_else(|| format!("the {party}'s funding inputs add up to more than 21M BTC"))?;
        outpoints.push(spent.outpoint);
    }
    Ok(PartyFunding {
        count: inputs.len(),
        total,
        outpoints,
    })
}

fn funding_inputs(offer: &OfferDlc, accept: Option<&AcceptDlc>) -> CheckResult {
    let offerer = party_funding("offerer", &offer.funding_inputs)?;
    if offerer.total < offer.offer_collateral {
        return Err(format!(
            "the offerer's inputs total {}, less than its {} collateral",
            offerer.total, offer.offer_collateral
        ));
    }
    validate_dlc_inputs(&offer.funding_inputs)?;
    let mut detail = format!(
        "offerer: {} input(s), {} sat",
        offerer.count,
        offerer.total.to_sat()
    );
    let mut outpoints = offerer.outpoints;
    if let Some(accept) = accept {
        let accepter = party_funding("accepter", &accept.funding_inputs)?;
        if accepter.total < accept.accept_collateral {
            return Err(format!(
                "the accepter's inputs total {}, less than its {} collateral",
                accepter.total, accept.accept_collateral
            ));
        }
        if let Some(input) = accept
            .funding_inputs
            .iter()
            .find(|input| input.dlc_input.is_some())
        {
            return Err(format!(
                "the accepter's funding input serial id {} spends an earlier DLC; only the \
                 offerer may splice",
                input.input_serial_id
            ));
        }
        detail.push_str(&format!(
            "; accepter: {} input(s), {} sat",
            accepter.count,
            accepter.total.to_sat()
        ));
        outpoints.extend(accepter.outpoints);
    }
    outpoints.sort_unstable();
    if let Some(pair) = outpoints
        .windows(2)
        .find(|pair| pair.first() == pair.get(1))
        && let Some(outpoint) = pair.first()
    {
        return Err(format!(
            "two funding inputs spend the same output {outpoint}"
        ));
    }
    Ok(Outcome::Pass(detail))
}

/// DDK's rules for funding inputs that spend an earlier DLC's funding output.
fn validate_dlc_inputs(inputs: &[FundingInput]) -> Result<(), String> {
    for input in inputs {
        let Some(dlc_input) = &input.dlc_input else {
            continue;
        };
        let id = input.input_serial_id;
        if input.max_witness_len <= 108 {
            return Err(format!(
                "DLC funding input serial id {id}: max_witness_len {} is too small for a 2-of-2 \
                 witness (must be over 108)",
                input.max_witness_len
            ));
        }
        if !input.redeem_script.is_empty() {
            return Err(format!(
                "DLC funding input serial id {id} carries a redeem script"
            ));
        }
        let spent = spent_output(input).map_err(|error| format!("serial id {id}: {error}"))?;
        let expected = ddk_dlc::make_funding_redeemscript(
            &dlc_input.local_fund_pubkey,
            &dlc_input.remote_fund_pubkey,
        )
        .to_p2wsh();
        if spent.txout.script_pubkey != expected {
            return Err(format!(
                "DLC funding input serial id {id} does not spend the 2-of-2 funding output of \
                 its funding keys"
            ));
        }
    }
    Ok(())
}

fn fee_rate(rate: u64) -> CheckResult {
    if rate == 0 {
        Ok(Outcome::Warn(
            "0 sat/vB: the funding transaction pays no fee and will not relay".to_owned(),
        ))
    } else if rate > MAX_FEE_RATE_PER_VB {
        Err(format!(
            "{rate} sat/vB, more than DDK's {MAX_FEE_RATE_PER_VB} sat/vB limit"
        ))
    } else {
        Ok(Outcome::Pass(format!("{rate} sat/vB")))
    }
}

fn limits(shape: &Shape<'_>) -> CheckResult {
    if shape.infos.is_empty() {
        return Err("the contract has no contract infos".to_owned());
    }
    if shape.infos.len() > MAX_CONTRACT_INFOS {
        return Err(format!(
            "{} contract infos, more than {MAX_CONTRACT_INFOS}",
            shape.infos.len()
        ));
    }
    let mut warnings = Vec::new();
    if shape.disjoint && shape.infos.len() == 1 {
        warnings.push("a disjoint contract with one contract info".to_owned());
    }
    let mut oracle_count = 0;
    for (index, info) in shape.infos.iter().enumerate() {
        let at = |message: String| format!("contract info {index}: {message}");
        oracle_count += info_limits(info, &mut warnings).map_err(at)?;
    }
    let summary = format!(
        "{} contract info(s), {oracle_count} oracle announcement(s)",
        shape.infos.len()
    );
    if warnings.is_empty() {
        Ok(Outcome::Pass(summary))
    } else {
        Ok(Outcome::Warn(format!("{summary}; {}", warnings.join("; "))))
    }
}

/// Checks one contract info against the limits DDK assumes. Returns its announcement count.
fn info_limits(info: &ContractInfoInner, warnings: &mut Vec<String>) -> Result<usize, String> {
    let announcements = announcements(&info.oracle_info);
    if announcements.is_empty() {
        return Err("no oracle announcements".to_owned());
    }
    if announcements.len() > MAX_ORACLES {
        return Err(format!(
            "{} oracle announcements, more than {MAX_ORACLES}",
            announcements.len()
        ));
    }
    let threshold = threshold(&info.oracle_info);
    if threshold == 0 || usize::from(threshold) > announcements.len() {
        return Err(format!(
            "threshold {threshold} of {} oracles",
            announcements.len()
        ));
    }
    for (index, announcement) in announcements.iter().enumerate() {
        announcement.oracle_event.validate().map_err(|error| {
            format!(
                "oracle {index} event {:?}: {error}",
                announcement.oracle_event.event_id
            )
        })?;
    }
    match &info.contract_descriptor {
        ContractDescriptor::EnumeratedContractDescriptor(descriptor) => {
            let mut outcomes = 0;
            for announcement in &announcements {
                let EventDescriptor::EnumEvent(event) = &announcement.oracle_event.event_descriptor
                else {
                    return Err("enum payouts with a numeric oracle event".to_owned());
                };
                outcomes = outcomes.max(event.outcomes.len());
            }
            outcomes = outcomes.max(descriptor.payouts.len());
            if descriptor.payouts.is_empty() {
                return Err("no enum payouts".to_owned());
            }
            if outcomes > MAX_ENUM_OUTCOMES {
                return Err(format!(
                    "{outcomes} enum outcomes, more than {MAX_ENUM_OUTCOMES}"
                ));
            }
            let combinations = combinations(announcements.len(), usize::from(threshold));
            let needed = combinations.saturating_mul(outcomes as u128);
            if needed > MAX_ENUM_ADAPTOR_SIGNATURES {
                return Err(format!(
                    "{outcomes} outcomes across {combinations} oracle combinations need {needed} \
                     adaptor signatures, more than {MAX_ENUM_ADAPTOR_SIGNATURES}"
                ));
            }
        }
        ContractDescriptor::NumericOutcomeContractDescriptor(descriptor) => {
            numeric_limits(info, descriptor, &announcements, warnings)?;
        }
    }
    Ok(announcements.len())
}

fn numeric_limits(
    info: &ContractInfoInner,
    descriptor: &ddk_messages::contract_msgs::NumericOutcomeContractDescriptor,
    announcements: &[&OracleAnnouncement],
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    if descriptor.payout_function.payout_function_pieces.is_empty() {
        return Err("the payout function has no pieces".to_owned());
    }
    let intervals = &descriptor.rounding_intervals.intervals;
    match intervals.first() {
        None => return Err("no rounding intervals".to_owned()),
        Some(first) if first.begin_interval != 0 => {
            return Err(format!(
                "the first rounding interval begins at {}, not 0",
                first.begin_interval
            ));
        }
        Some(_) => {}
    }
    if let Some(interval) = intervals.iter().find(|interval| interval.rounding_mod == 0) {
        return Err(format!(
            "the rounding interval at {} has rounding modulus 0",
            interval.begin_interval
        ));
    }
    let mut base = None;
    let mut min_digits = u16::MAX;
    for announcement in announcements {
        let EventDescriptor::DigitDecompositionEvent(event) =
            &announcement.oracle_event.event_descriptor
        else {
            return Err("numeric payouts with an enum oracle event".to_owned());
        };
        if event.base < 2 {
            return Err(format!("oracle event base {}", event.base));
        }
        if *base.get_or_insert(event.base) != event.base {
            return Err("oracle events with different bases".to_owned());
        }
        if event.nb_digits == 0 {
            return Err("an oracle event with no digits".to_owned());
        }
        u64::from(event.base)
            .checked_pow(u32::from(event.nb_digits))
            .ok_or_else(|| {
                format!(
                    "base {} with {} digits overflows 64 bits",
                    event.base, event.nb_digits
                )
            })?;
        min_digits = min_digits.min(event.nb_digits);
    }
    if descriptor.num_digits != min_digits {
        warnings.push(format!(
            "the descriptor says {} digits but the oracle events have {min_digits}",
            descriptor.num_digits
        ));
    }
    if let OracleInfo::Multi(multi) = &info.oracle_info
        && let Some(params) = &multi.oracle_params
        && !(params.min_fail_exp < params.max_error_exp && params.max_error_exp <= min_digits)
    {
        return Err(format!(
            "oracle params min_fail_exp {} and max_error_exp {} do not satisfy min_fail_exp < \
             max_error_exp <= {min_digits} digits",
            params.min_fail_exp, params.max_error_exp
        ));
    }
    Ok(())
}

/// n choose k, saturating.
fn combinations(n: usize, k: usize) -> u128 {
    let k = k.min(n.saturating_sub(k));
    (0..k).fold(1u128, |acc, i| {
        acc.saturating_mul((n - i) as u128) / (i as u128 + 1)
    })
}

fn announcement_signatures(secp: &Secp256k1<All>, shape: &Shape<'_>) -> CheckResult {
    let mut oracles = Vec::new();
    let mut count = 0;
    for (index, info) in shape.infos.iter().enumerate() {
        for announcement in announcements(&info.oracle_info) {
            announcement.validate(secp).map_err(|error| {
                format!(
                    "contract info {index}: the announcement of event {:?} by oracle {}: {error}",
                    announcement.oracle_event.event_id, announcement.oracle_public_key
                )
            })?;
            count += 1;
            if !oracles.contains(&announcement.oracle_public_key) {
                oracles.push(announcement.oracle_public_key);
            }
        }
    }
    if count == 0 {
        return Err("no oracle announcements".to_owned());
    }
    Ok(Outcome::Pass(format!(
        "{count} announcement signature(s) from {} oracle(s) verify",
        oracles.len()
    )))
}

fn outcome_coverage(
    offer: &OfferDlc,
    shape: &Shape<'_>,
) -> Result<(Outcome, Vec<ExecutionInfo>), String> {
    for (index, info) in shape.infos.iter().enumerate() {
        if let ContractDescriptor::EnumeratedContractDescriptor(descriptor) =
            &info.contract_descriptor
        {
            if let Some(outcome) =
                duplicate(descriptor.payouts.iter().map(|payout| &payout.outcome))
            {
                return Err(format!(
                    "contract info {index}: outcome {outcome:?} has two payouts"
                ));
            }
            for announcement in announcements(&info.oracle_info) {
                if let EventDescriptor::EnumEvent(event) =
                    &announcement.oracle_event.event_descriptor
                    && let Some(outcome) = duplicate(event.outcomes.iter())
                {
                    return Err(format!(
                        "contract info {index}: oracle event {:?} lists outcome {outcome:?} twice",
                        announcement.oracle_event.event_id
                    ));
                }
            }
        }
    }
    let infos = guarded(|| {
        execution_contract_infos(&offer.contract_info).map_err(|error| error.to_string())
    })?;
    for (index, info) in infos.iter().enumerate() {
        guarded(|| info.validate().map_err(|error| error.to_string()))
            .map_err(|error| format!("contract info {index}: {error}"))?;
    }
    guarded(|| {
        validate_cet_records(&infos, shape.total, &offer.tlvs).map_err(|error| error.to_string())
    })?;
    let overrides = offer
        .tlvs
        .get::<PayoutScriptOverrides>()
        .ok()
        .flatten()
        .map_or(0, |record| record.overrides.len());
    let mut detail = format!(
        "every outcome the oracles can attest has a payout ({} contract info(s))",
        infos.len()
    );
    if overrides > 0 {
        detail.push_str(&format!(
            "; {overrides} payout script override(s) name real outcomes"
        ));
    }
    Ok((Outcome::Pass(detail), infos))
}

fn duplicate<'a>(items: impl Iterator<Item = &'a String>) -> Option<&'a String> {
    let mut seen = std::collections::BTreeSet::new();
    items.into_iter().find(|item| !seen.insert(*item))
}

fn maturity(shape: &Shape<'_>, now: Option<u64>) -> CheckResult {
    let Some((closest, latest)) = shape.maturities() else {
        return Ok(Outcome::Skip("no oracle announcements".to_owned()));
    };
    let (closest, latest) = (u64::from(closest), u64::from(latest));
    let span = if closest == latest {
        format!("oracle events mature at {}", format_unix(closest))
    } else {
        format!(
            "oracle events mature from {} to {}",
            format_unix(closest),
            format_unix(latest)
        )
    };
    match now {
        None => Ok(Outcome::Warn(format!(
            "{span}; no current time given, so not compared with now"
        ))),
        Some(now) if now >= closest => Ok(Outcome::Warn(format!(
            "{span}; the earliest matured {} before now ({})",
            format_duration(now - closest),
            format_unix(now)
        ))),
        Some(now) => Ok(Outcome::Pass(format!(
            "{span}; the earliest is in {}",
            format_duration(closest - now)
        ))),
    }
}

fn cet_locktime(offer: &OfferDlc, shape: &Shape<'_>) -> CheckResult {
    let cet = offer.cet_locktime;
    let refund = offer.refund_locktime;
    if cet != 0 && locktime_kind(cet) == locktime_kind(refund) && cet >= refund {
        return Err(format!(
            "the CET locktime {cet} is not before the refund locktime {refund}, so the refund \
             could be broadcast before any CET"
        ));
    }
    match locktime_kind(cet) {
        LocktimeKind::None => Ok(Outcome::Pass(
            "0: a CET can be broadcast as soon as the oracle attests".to_owned(),
        )),
        LocktimeKind::Height => Ok(Outcome::Warn(format!(
            "block height {cet}; not comparable with the oracle maturity time"
        ))),
        LocktimeKind::Time => {
            let Some((closest, _)) = shape.maturities() else {
                return Ok(Outcome::Skip(
                    "no oracle announcements to compare with".to_owned(),
                ));
            };
            if cet > closest {
                return Err(format!(
                    "{} is after the earliest oracle maturity {}; DDK rejects this",
                    format_unix(u64::from(cet)),
                    format_unix(u64::from(closest))
                ));
            }
            Ok(Outcome::Pass(format!(
                "{}, at or before the earliest oracle maturity",
                format_unix(u64::from(cet))
            )))
        }
    }
}

fn refund_locktime(offer: &OfferDlc, shape: &Shape<'_>) -> CheckResult {
    let refund = offer.refund_locktime;
    match locktime_kind(refund) {
        LocktimeKind::None => {
            Err("0: the refund could be broadcast at once, before the oracle attests".to_owned())
        }
        LocktimeKind::Height => Ok(Outcome::Warn(format!(
            "block height {refund}; not comparable with the oracle maturity time"
        ))),
        LocktimeKind::Time => {
            let Some((closest, latest)) = shape.maturities() else {
                return Ok(Outcome::Skip(
                    "no oracle announcements to compare with".to_owned(),
                ));
            };
            let at = format_unix(u64::from(refund));
            if refund <= closest {
                return Err(format!(
                    "{at} is not after the earliest oracle maturity {}, so the refund could \
                     beat settlement",
                    format_unix(u64::from(closest))
                ));
            }
            let after = format_duration(u64::from(refund - closest));
            if refund <= latest {
                return Ok(Outcome::Warn(format!(
                    "{at}, {after} after the earliest oracle maturity but before the latest ({})",
                    format_unix(u64::from(latest))
                )));
            }
            Ok(Outcome::Pass(format!(
                "{at}, {after} after the earliest oracle maturity"
            )))
        }
    }
}

fn kind_name(kind: LocktimeKind) -> &'static str {
    match kind {
        LocktimeKind::None => "no lock",
        LocktimeKind::Height => "a block height",
        LocktimeKind::Time => "a time",
    }
}

fn locktime_units(offer: &OfferDlc) -> CheckResult {
    let cet = locktime_kind(offer.cet_locktime);
    let refund = locktime_kind(offer.refund_locktime);
    let detail = format!(
        "CET locktime is {}, refund locktime is {}",
        kind_name(cet),
        kind_name(refund)
    );
    if cet != LocktimeKind::None && refund != LocktimeKind::None && cet != refund {
        return Ok(Outcome::Warn(format!(
            "{detail}; their order cannot be compared"
        )));
    }
    Ok(Outcome::Pass(detail))
}

const BUILD_DEPS: [&str; 7] = [
    "decode.accept",
    "structure.collateral",
    "structure.serial-ids",
    "structure.funding-inputs",
    "structure.fee-rate",
    "structure.limits",
    "oracle.outcome-coverage",
];

fn rebuild_checks(
    checks: &mut Checks,
    secp: &Secp256k1<All>,
    offer: &OfferDlc,
    accept: Option<&AcceptDlc>,
    sign: Option<&SignDlc>,
    execution_infos: Option<Vec<ExecutionInfo>>,
) -> Option<RebuiltContract> {
    let contract = match (
        checks.open("tx.build", &BUILD_DEPS),
        accept,
        execution_infos,
    ) {
        (true, Some(accept), Some(infos)) => match rebuild(secp, offer, accept, sign, infos) {
            Ok(contract) => {
                checks.set(
                    "tx.build",
                    CheckStatus::Pass,
                    format!(
                        "rebuilt the funding transaction, {} CET(s) and the refund (fee rule {})",
                        contract.transactions.cets.len(),
                        fee_rule_name(contract.fee_rule)
                    ),
                );
                Some(contract)
            }
            Err(error) => {
                checks.set("tx.build", CheckStatus::Fail, error);
                None
            }
        },
        (true, _, _) => {
            checks.set("tx.build", CheckStatus::Skip, "not run: missing input");
            None
        }
        (false, _, _) => None,
    };
    if let (Some(contract), Some(accept)) = (contract.as_ref(), accept) {
        checks.record("tx.funding-output", funding_output(offer, accept, contract));
        checks.set(
            "tx.contract-id",
            CheckStatus::Pass,
            hex::encode(contract.contract_id),
        );
    } else {
        checks.open("tx.funding-output", &["tx.build"]);
        checks.open("tx.contract-id", &["tx.build"]);
    }
    contract
}

fn party_params(
    fund_pubkey: PublicKey,
    payout: &ScriptBuf,
    payout_serial_id: u64,
    change: &ScriptBuf,
    change_serial_id: u64,
    collateral: Amount,
    funding_inputs: &[FundingInput],
) -> Result<PartyParams, String> {
    let mut inputs = Vec::with_capacity(funding_inputs.len());
    let mut dlc_inputs = Vec::new();
    let mut input_amount = Amount::ZERO;
    for input in funding_inputs {
        let spent = spent_output(input).map_err(|error| {
            format!("funding input serial id {}: {error}", input.input_serial_id)
        })?;
        input_amount = input_amount
            .checked_add(spent.txout.value)
            .ok_or("funding input values overflow")?;
        inputs.push(TxInputInfo {
            outpoint: spent.outpoint,
            max_witness_len: usize::from(input.max_witness_len),
            redeem_script: input.redeem_script.clone(),
            serial_id: input.input_serial_id,
        });
        if let Some(dlc_input) = &input.dlc_input {
            dlc_inputs.push(dlc_input_info(input, dlc_input, spent.txout.value)?);
        }
    }
    Ok(PartyParams {
        fund_pubkey,
        change_script_pubkey: change.clone(),
        change_serial_id,
        payout_script_pubkey: payout.clone(),
        payout_serial_id,
        inputs,
        dlc_inputs,
        input_amount,
        collateral,
    })
}

/// DDK's `DlcInputInfo` for a splice input, built without the unwraps of its `From` impl.
fn dlc_input_info(
    input: &FundingInput,
    dlc_input: &ddk_messages::DlcInput,
    fund_amount: Amount,
) -> Result<DlcInputInfo, String> {
    let fund_tx: Transaction = bitcoin::consensus::deserialize(&input.prev_tx)
        .map_err(|error| format!("prev_tx is not a transaction: {error}"))?;
    Ok(DlcInputInfo {
        fund_tx,
        fund_vout: input.prev_tx_vout,
        local_fund_pubkey: dlc_input.local_fund_pubkey,
        remote_fund_pubkey: dlc_input.remote_fund_pubkey,
        fund_amount,
        max_witness_len: usize::from(input.max_witness_len),
        input_serial_id: input.input_serial_id,
        contract_id: dlc_input.contract_id,
    })
}

/// Rebuilds the contract. DDK builds under two CET fee rules; the messages say which one the
/// parties used: the sign message's contract id or, without a sign, the accepter's refund
/// signature only verifies against the right one.
fn rebuild(
    secp: &Secp256k1<All>,
    offer: &OfferDlc,
    accept: &AcceptDlc,
    sign: Option<&SignDlc>,
    infos: Vec<ExecutionInfo>,
) -> Result<RebuiltContract, String> {
    let offer_params = party_params(
        offer.funding_pubkey,
        &offer.payout_spk,
        offer.payout_serial_id,
        &offer.change_spk,
        offer.change_serial_id,
        offer.offer_collateral,
        &offer.funding_inputs,
    )
    .map_err(|error| format!("offerer: {error}"))?;
    let accept_params = party_params(
        accept.funding_pubkey,
        &accept.payout_spk,
        accept.payout_serial_id,
        &accept.change_spk,
        accept.change_serial_id,
        accept.accept_collateral,
        &accept.funding_inputs,
    )
    .map_err(|error| format!("accepter: {error}"))?;
    let terms = ContractTerms::from(offer);
    let matches = |contract: &RebuiltContract| match sign {
        Some(sign) => sign.contract_id == contract.contract_id,
        None => refund_signature(
            secp,
            contract,
            &accept.funding_pubkey,
            &accept.refund_signature,
        )
        .is_ok(),
    };

    let mut first: Option<Result<RebuiltContract, String>> = None;
    for rule in [FeeRule::CounterpartyPayout, FeeRule::OwnPayoutOnly] {
        let built = build(&offer_params, &accept_params, &infos, offer, &terms, rule);
        if let Ok(contract) = &built
            && matches(contract)
        {
            return Ok(contract.clone());
        }
        first = match first {
            None => Some(built),
            Some(Err(_)) if built.is_ok() => Some(built),
            other => other,
        };
    }
    first.unwrap_or_else(|| Err("no fee rule to build with".to_owned()))
}

fn build(
    offer_params: &PartyParams,
    accept_params: &PartyParams,
    infos: &[ExecutionInfo],
    offer: &OfferDlc,
    terms: &ContractTerms,
    fee_rule: FeeRule,
) -> Result<RebuiltContract, String> {
    let ContractTransactions {
        transactions,
        cet_ranges,
    } = guarded(|| {
        build_contract_transactions(
            offer_params,
            accept_params,
            infos,
            &offer.tlvs,
            terms,
            fee_rule,
        )
        .map_err(|error| error.to_string())
    })?;
    let funding_script_pubkey = transactions.funding_script_pubkey();
    let (fund_output_index, fund_output_value) =
        ddk_dlc::util::get_output_for_script_pubkey(&transactions.fund, &funding_script_pubkey)
            .map(|(index, output)| (index, output.value))
            .ok_or("the rebuilt funding transaction has no funding output")?;
    let contract_id = contract_id(
        &transactions.fund,
        fund_output_index,
        &offer.temporary_contract_id,
    )?;
    Ok(RebuiltContract {
        fee_rule,
        contract_id,
        fund_output_index,
        fund_output_value,
        transactions,
        cet_ranges,
        execution_infos: infos.to_vec(),
    })
}

/// The contract id: the funding txid, byte-reversed, XOR the temporary id, with the funding
/// output index XORed into the last two bytes.
fn contract_id(
    fund: &Transaction,
    fund_output_index: usize,
    temporary_contract_id: &[u8; 32],
) -> Result<[u8; 32], String> {
    let index = u16::try_from(fund_output_index)
        .map_err(|_| format!("funding output index {fund_output_index} exceeds 16 bits"))?;
    let txid = fund.compute_txid().to_byte_array();
    let mut id = [0u8; 32];
    for ((byte, txid_byte), temp_byte) in id
        .iter_mut()
        .zip(txid.iter().rev())
        .zip(temporary_contract_id)
    {
        *byte = txid_byte ^ temp_byte;
    }
    let [high, low] = index.to_be_bytes();
    id[30] ^= high;
    id[31] ^= low;
    Ok(id)
}

fn funding_output(offer: &OfferDlc, accept: &AcceptDlc, contract: &RebuiltContract) -> CheckResult {
    if offer.funding_pubkey == accept.funding_pubkey {
        return Err(format!(
            "both parties use funding key {}; the 2-of-2 would be one key",
            offer.funding_pubkey
        ));
    }
    let total = offer.offer_collateral + accept.accept_collateral;
    if contract.fund_output_value < total {
        return Err(format!(
            "the funding output holds {}, less than the {total} collateral",
            contract.fund_output_value
        ));
    }
    Ok(Outcome::Pass(format!(
        "output {} of {}: {} sat to the 2-of-2 of both funding keys",
        contract.fund_output_index,
        contract.transactions.fund.compute_txid(),
        contract.fund_output_value.to_sat()
    )))
}

fn signature_checks(
    checks: &mut Checks,
    secp: &Secp256k1<All>,
    offer: &OfferDlc,
    accept: &AcceptDlc,
    sign: Option<&SignDlc>,
    contract: &RebuiltContract,
    total: Amount,
) {
    checks.record(
        "sig.accept.cet-adaptors",
        adaptor_signatures(
            secp,
            contract,
            total,
            &accept.funding_pubkey,
            &accept.cet_adaptor_signatures,
        ),
    );
    checks.record(
        "sig.accept.refund",
        refund_signature(
            secp,
            contract,
            &accept.funding_pubkey,
            &accept.refund_signature,
        )
        .map(|()| Outcome::Pass("the accepter's refund signature verifies".to_owned())),
    );
    let sign_deps = ["decode.sign", "tx.build"];
    let Some(sign) = sign else {
        for id in [
            "sig.offer.cet-adaptors",
            "sig.offer.refund",
            "sig.offer.funding",
            "sig.contract-id",
        ] {
            checks.open(id, &sign_deps);
        }
        return;
    };
    checks.record(
        "sig.offer.cet-adaptors",
        adaptor_signatures(
            secp,
            contract,
            total,
            &offer.funding_pubkey,
            &sign.cet_adaptor_signatures,
        ),
    );
    checks.record(
        "sig.offer.refund",
        refund_signature(
            secp,
            contract,
            &offer.funding_pubkey,
            &sign.refund_signature,
        )
        .map(|()| Outcome::Pass("the offerer's refund signature verifies".to_owned())),
    );
    checks.record(
        "sig.offer.funding",
        offer_funding(secp, offer, accept, sign, contract),
    );
    checks.record(
        "sig.contract-id",
        if sign.contract_id == contract.contract_id {
            Ok(Outcome::Pass(format!(
                "the sign message names the rebuilt contract {}",
                hex::encode(contract.contract_id)
            )))
        } else {
            Err(format!(
                "the sign message names contract {}, but the rebuilt contract is {}",
                hex::encode(sign.contract_id),
                hex::encode(contract.contract_id)
            ))
        },
    );
}

fn adaptor_signatures(
    secp: &Secp256k1<All>,
    contract: &RebuiltContract,
    total: Amount,
    pubkey: &PublicKey,
    signatures: &CetAdaptorSignatures,
) -> CheckResult {
    let signatures: Vec<EcdsaAdaptorSignature> = signatures.into();
    let mut index = 0;
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
            .ok_or("a CET range is out of bounds")?;
        let (_, next) = guarded(|| {
            info.verify_and_get_adaptor_info(
                secp,
                total,
                pubkey,
                &contract.transactions.funding_witness_script,
                contract.fund_output_value,
                cets,
                &signatures,
                index,
            )
            .map_err(|error| error.to_string())
        })
        .map_err(|error| format!("contract info {info_index}: {error}"))?;
        index = next;
    }
    if index != signatures.len() {
        return Err(format!(
            "{} adaptor signatures given, but the contract uses {index}",
            signatures.len()
        ));
    }
    Ok(Outcome::Pass(format!(
        "{} adaptor signature(s) verify against {} CET(s)",
        signatures.len(),
        contract.transactions.cets.len()
    )))
}

fn refund_signature(
    secp: &Secp256k1<All>,
    contract: &RebuiltContract,
    pubkey: &PublicKey,
    signature: &ddk_dlc::secp256k1_zkp::ecdsa::Signature,
) -> Result<(), String> {
    ddk_dlc::verify_tx_input_sig(
        secp,
        signature,
        &contract.transactions.refund,
        0,
        &contract.transactions.funding_witness_script,
        contract.fund_output_value,
        pubkey,
    )
    .map_err(|error| format!("the refund signature does not verify: {error}"))
}

/// The offerer's funding witnesses from the sign message, checked against the outputs they
/// spend. The accepter's witnesses never travel in the messages.
fn offer_funding(
    secp: &Secp256k1<All>,
    offer: &OfferDlc,
    accept: &AcceptDlc,
    sign: &SignDlc,
    contract: &RebuiltContract,
) -> CheckResult {
    let signatures = &sign.funding_signatures.funding_signatures;
    if signatures.len() != offer.funding_inputs.len() {
        return Err(format!(
            "the sign message carries {} funding witnesses for the offer's {} funding inputs",
            signatures.len(),
            offer.funding_inputs.len()
        ));
    }
    if signatures.is_empty() {
        return Ok(Outcome::Pass(
            "the offerer has no funding inputs to sign".to_owned(),
        ));
    }
    let all_inputs: Vec<&FundingInput> = offer
        .funding_inputs
        .iter()
        .chain(&accept.funding_inputs)
        .collect();
    let mut prevouts: Vec<TxOut> = Vec::with_capacity(all_inputs.len());
    for input in &all_inputs {
        prevouts.push(spent_output(input)?.txout);
    }
    let serial_ids: Vec<u64> = all_inputs
        .iter()
        .map(|input| input.input_serial_id)
        .collect();
    let prevouts = ddk_dlc::util::order_by_serial_ids(prevouts, &serial_ids);
    let mut sorted = serial_ids;
    sorted.sort_unstable();

    let fund = &contract.transactions.fund;
    let mut unverifiable = Vec::new();
    for (input, signature) in offer.funding_inputs.iter().zip(signatures) {
        let id = input.input_serial_id;
        let index = sorted
            .iter()
            .position(|serial| *serial == id)
            .ok_or_else(|| format!("funding input serial id {id} is missing"))?;
        let result = match &input.dlc_input {
            Some(dlc_input) => {
                let half = splice_half(id, dlc_input, signature)?;
                let spent = spent_output(input)?;
                let info = dlc_input_info(input, dlc_input, spent.txout.value)?;
                guarded(|| {
                    Ok(verify_dlc_funding_input_signature(
                        secp,
                        fund,
                        index,
                        &info,
                        half.to_vec(),
                        &dlc_input.local_fund_pubkey,
                    ))
                })?
            }
            None => {
                let spent = spent_output(input)?;
                let info = TxInputInfo {
                    outpoint: spent.outpoint,
                    max_witness_len: usize::from(input.max_witness_len),
                    redeem_script: input.redeem_script.clone(),
                    serial_id: id,
                };
                let witness = Witness::from_slice(
                    &signature
                        .witness_elements
                        .iter()
                        .map(|element| element.witness.as_slice())
                        .collect::<Vec<_>>(),
                );
                guarded(|| {
                    Ok(ddk_dlc::verify_funding_witness(
                        secp, fund, index, &info, &prevouts, &witness,
                    ))
                })?
            }
        };
        match result {
            Ok(()) => {}
            Err(ddk_dlc::Error::UnsupportedScriptType) => unverifiable.push(id),
            Err(ddk_dlc::Error::WitnessTooLong {
                witness_len,
                max_witness_len,
            }) => {
                return Err(format!(
                    "the witness for funding input serial id {id} is {witness_len} bytes, more \
                     than its max_witness_len {max_witness_len}"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "the witness for funding input serial id {id} does not verify: {error}"
                ));
            }
        }
    }
    if !unverifiable.is_empty() {
        let ids: Vec<String> = unverifiable.iter().map(u64::to_string).collect();
        return Ok(Outcome::Skip(format!(
            "cannot check the witness script type of funding input serial id(s) {}",
            ids.join(", ")
        )));
    }
    Ok(Outcome::Pass(format!(
        "{} offerer funding witness(es) verify; the accepter's are not in the messages",
        signatures.len()
    )))
}

/// The offerer's half of a splice input's 2-of-2 signature: the half alone, or the half followed
/// by the offerer's earlier funding key.
fn splice_half<'a>(
    id: u64,
    dlc_input: &ddk_messages::DlcInput,
    signature: &'a FundingSignature,
) -> Result<&'a [u8], String> {
    match signature.witness_elements.as_slice() {
        [half] => Ok(&half.witness),
        [half, key] if key.witness == dlc_input.local_fund_pubkey.serialize() => Ok(&half.witness),
        elements => Err(format!(
            "DLC funding input serial id {id}: expected the half signature, optionally followed \
             by the offerer's earlier funding key, got {} witness elements",
            elements.len()
        )),
    }
}
