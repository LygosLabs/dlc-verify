//! The verification report: the checks, the contract terms, and who every CET and the refund
//! pay.
//!
//! Payouts are read off the rebuilt transactions, not the descriptor, so the report shows what
//! the signatures commit to. Every output is labelled with the party whose script it pays:
//! `offerer`, `accepter`, `third-party` (an output a payout-script-override record redirected,
//! with the record), `shared` (both parties named the same script), or `unknown`.

use bitcoin::{Network, Script, Transaction};
use ddk_manager::contract::ContractDescriptor as ExecutionDescriptor;
use ddk_manager::contract::contract_info::ContractInfo as ExecutionInfo;
use ddk_messages::{
    AcceptDlc, OfferDlc, OverrideOutcome, PayoutScriptOverride, PayoutScriptOverrides,
};
use serde::Serialize;

use crate::inspect::contract_flag_names;
use crate::network::{network_from_chain_hash, network_name};
use crate::summary::{LocktimeSummary, ScriptSummary, TimeSummary};
use crate::time::{LocktimeKind, format_unix};
use crate::verify::{Check, CheckStatus, RebuiltContract, Status, Verification, fee_rule_name};

/// The JSON schema name of [`Report`].
pub const REPORT_SCHEMA: &str = "dlc-verify.report.v1";

/// The DDK release the verifier rebuilds contracts with.
pub const DDK_VERSION: &str = "2.0.0-rc.10";

/// The TLV type of DDK's payout-script-override record.
const PAYOUT_SCRIPT_OVERRIDES_TYPE: u64 = 65005;

/// Everything a verification found, ready to print or serialize.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// Always [`REPORT_SCHEMA`].
    pub schema: &'static str,
    /// The verifier that wrote the report.
    pub verifier: Verifier,
    /// The overall result: the checks', combined with the policy's when there is one.
    pub status: Status,
    /// How many checks ended each way.
    pub counts: Counts,
    /// The contract terms; `None` when the offer does not decode.
    pub contract: Option<ContractOverview>,
    /// Every check, in catalogue order.
    pub checks: Vec<Check>,
    /// The result of checking the contract against a policy, when one was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyOutcome>,
    /// Who the refund and every CET pay; `None` when the contract could not be rebuilt.
    pub payouts: Option<Payouts>,
}

impl Report {
    /// Attaches the result of a policy and folds its status into the report's.
    pub fn with_policy(mut self, policy: PolicyOutcome) -> Self {
        self.status = combine(self.status, policy.status);
        self.policy = Some(policy);
        self
    }
}

/// The result of checking a contract against a policy.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyOutcome {
    /// The policy's name, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `fail` if any policy check fails, `incomplete` if one could not run, otherwise `pass`.
    pub status: Status,
    /// The policy's checks, one per expectation the policy states.
    pub checks: Vec<Check>,
}

impl PolicyOutcome {
    /// Collects `checks` under the status they add up to.
    pub fn new(name: Option<String>, checks: Vec<Check>) -> Self {
        let status = if checks.iter().any(|check| check.status == CheckStatus::Fail) {
            Status::Fail
        } else if checks.iter().any(|check| check.status == CheckStatus::Skip) {
            Status::Incomplete
        } else {
            Status::Pass
        };
        Self {
            name,
            status,
            checks,
        }
    }
}

/// The worse of two results: `fail` over `incomplete` over `pass`.
pub const fn combine(left: Status, right: Status) -> Status {
    match (left, right) {
        (Status::Fail, _) | (_, Status::Fail) => Status::Fail,
        (Status::Incomplete, _) | (_, Status::Incomplete) => Status::Incomplete,
        (Status::Pass, Status::Pass) => Status::Pass,
    }
}

/// The verifier that wrote a report.
#[derive(Clone, Debug, Serialize)]
pub struct Verifier {
    /// `dlc-verify`.
    pub name: &'static str,
    /// This crate's version.
    pub version: &'static str,
    /// The DDK release contracts are rebuilt with.
    pub ddk: &'static str,
}

/// How many checks ended each way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Passed.
    pub pass: usize,
    /// Passed with a warning.
    pub warn: usize,
    /// Failed.
    pub fail: usize,
    /// Did not run.
    pub skip: usize,
}

/// The contract's terms as the messages state them.
#[derive(Clone, Debug, Serialize)]
pub struct ContractOverview {
    /// The network the offer's chain hash names.
    pub network: Option<&'static str>,
    /// The temporary contract id from the offer.
    pub temporary_contract_id: String,
    /// The contract id of the rebuilt funding transaction.
    pub contract_id: Option<String>,
    /// The collateral both parties put in.
    pub total_collateral_sat: u64,
    /// The offering party.
    pub offerer: PartyOverview,
    /// The accepting party, when there is an accept message.
    pub accepter: Option<PartyOverview>,
    /// The funding transaction's fee rate.
    pub fee_rate_per_vb: u64,
    /// The CET fee rule the contract was built with.
    pub fee_rule: Option<&'static str>,
    /// The names of the contract flags set.
    pub contract_flags: Vec<String>,
    /// When the oracle events mature.
    pub oracle_maturity: Option<MaturityRange>,
    /// The CETs' locktime.
    pub cet_locktime: LocktimeSummary,
    /// The refund's locktime.
    pub refund_locktime: LocktimeSummary,
    /// The rebuilt funding output.
    pub funding_output: Option<FundingOutput>,
    /// The payout-script-override records: CETs whose accepter output pays someone else.
    pub payout_overrides: Vec<OverrideRow>,
}

/// One party's side of the contract.
#[derive(Clone, Debug, Serialize)]
pub struct PartyOverview {
    /// What the party puts in.
    pub collateral_sat: u64,
    /// The party's key in the 2-of-2 funding output.
    pub funding_pubkey: String,
    /// Where the party's CET and refund payouts go.
    pub payout: ScriptSummary,
    /// Where the party's change goes.
    pub change: ScriptSummary,
}

/// The earliest and latest oracle maturity.
#[derive(Clone, Debug, Serialize)]
pub struct MaturityRange {
    /// The earliest maturity.
    pub earliest: TimeSummary,
    /// The latest maturity.
    pub latest: TimeSummary,
}

/// The funding output of the rebuilt funding transaction.
#[derive(Clone, Debug, Serialize)]
pub struct FundingOutput {
    /// The funding transaction id.
    pub txid: String,
    /// The output index.
    pub vout: usize,
    /// The output value.
    pub value_sat: u64,
}

/// One payout-script-override.
#[derive(Clone, Debug, Serialize)]
pub struct OverrideRow {
    /// The outcomes it covers, e.g. `outcome "down"` or `values 0 to 99`.
    pub covers: String,
    /// The script those CETs pay in place of the accepter's.
    pub script: ScriptSummary,
}

/// Who the refund and every CET pay.
#[derive(Clone, Debug, Serialize)]
pub struct Payouts {
    /// The refund transaction.
    pub refund: TransactionPayouts,
    /// Every CET, in contract order.
    pub cets: Vec<CetPayouts>,
}

/// The outputs of one transaction.
#[derive(Clone, Debug, Serialize)]
pub struct TransactionPayouts {
    /// The transaction id.
    pub txid: String,
    /// The transaction's locktime.
    pub locktime: LocktimeSummary,
    /// Its outputs, in order.
    pub outputs: Vec<PayoutOutput>,
}

/// The outputs of one CET.
#[derive(Clone, Debug, Serialize)]
pub struct CetPayouts {
    /// The CET's position among all CETs.
    pub index: usize,
    /// The contract info it belongs to.
    pub contract_info: usize,
    /// The outcome it settles as text: the enum outcome, or `first..last` for numeric values.
    pub outcome: String,
    /// The outcome it settles.
    pub settles: CetOutcome,
    /// The CET's transaction id.
    pub txid: String,
    /// Its outputs, in order.
    pub outputs: Vec<PayoutOutput>,
}

/// One output and who it pays.
#[derive(Clone, Debug, Serialize)]
pub struct PayoutOutput {
    /// Who the output pays.
    pub payee: Payee,
    /// The output value.
    pub value_sat: u64,
    /// The output script.
    pub script: ScriptSummary,
    /// For a third-party output, the record that redirected it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
}

/// Who an output pays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Payee {
    /// The offerer's payout script.
    Offerer,
    /// The accepter's payout script.
    Accepter,
    /// A script a CET record put in place of the accepter's.
    ThirdParty,
    /// A payout script both parties named.
    Shared,
    /// A script neither party nor any record named.
    Unknown,
}

impl Payee {
    /// The name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Offerer => "offerer",
            Self::Accepter => "accepter",
            Self::ThirdParty => "third-party",
            Self::Shared => "shared",
            Self::Unknown => "unknown",
        }
    }
}

/// Builds the report of `verification`.
pub fn report(verification: &Verification) -> Report {
    let mut counts = Counts::default();
    for check in &verification.checks {
        match check.status {
            CheckStatus::Pass => counts.pass += 1,
            CheckStatus::Warn => counts.warn += 1,
            CheckStatus::Fail => counts.fail += 1,
            CheckStatus::Skip => counts.skip += 1,
        }
    }
    let messages = verification.messages.as_ref();
    let contract = verification.contract.as_ref();
    let overview =
        messages.map(|messages| overview(&messages.offer, messages.accept.as_ref(), contract));
    let payouts = match (messages, contract) {
        (Some(messages), Some(contract)) => messages
            .accept
            .as_ref()
            .map(|accept| payouts(&messages.offer, accept, contract)),
        _ => None,
    };
    Report {
        schema: REPORT_SCHEMA,
        verifier: Verifier {
            name: "dlc-verify",
            version: crate::VERSION,
            ddk: DDK_VERSION,
        },
        status: verification.status,
        counts,
        contract: overview,
        checks: verification.checks.clone(),
        policy: None,
        payouts,
    }
}

fn network(offer: &OfferDlc) -> Option<Network> {
    network_from_chain_hash(&offer.chain_hash).map(|matched| matched.network)
}

fn overrides(offer: &OfferDlc) -> Vec<PayoutScriptOverride> {
    offer
        .tlvs
        .get::<PayoutScriptOverrides>()
        .ok()
        .flatten()
        .map(|record| record.overrides)
        .unwrap_or_default()
}

fn describe(outcome: &OverrideOutcome) -> String {
    match outcome {
        OverrideOutcome::Enum { outcome } => format!("outcome {outcome:?}"),
        OverrideOutcome::Numeric { start, end } => format!("values {start} to {end}"),
    }
}

fn overview(
    offer: &OfferDlc,
    accept: Option<&AcceptDlc>,
    contract: Option<&RebuiltContract>,
) -> ContractOverview {
    let network = network(offer);
    let total = offer.get_total_collateral();
    let maturities: Vec<u32> = match &offer.contract_info {
        ddk_messages::contract_msgs::ContractInfo::SingleContractInfo(single) => {
            maturity_epochs(&single.contract_info.oracle_info)
        }
        ddk_messages::contract_msgs::ContractInfo::DisjointContractInfo(disjoint) => disjoint
            .contract_infos
            .iter()
            .flat_map(|info| maturity_epochs(&info.oracle_info))
            .collect(),
    };
    let oracle_maturity =
        maturities
            .iter()
            .min()
            .zip(maturities.iter().max())
            .map(|(earliest, latest)| MaturityRange {
                earliest: TimeSummary::new(u64::from(*earliest)),
                latest: TimeSummary::new(u64::from(*latest)),
            });
    ContractOverview {
        network: network.map(network_name),
        temporary_contract_id: hex::encode(offer.temporary_contract_id),
        contract_id: contract.map(|contract| hex::encode(contract.contract_id)),
        total_collateral_sat: total.to_sat(),
        offerer: PartyOverview {
            collateral_sat: offer.offer_collateral.to_sat(),
            funding_pubkey: offer.funding_pubkey.to_string(),
            payout: ScriptSummary::new(&offer.payout_spk, network),
            change: ScriptSummary::new(&offer.change_spk, network),
        },
        accepter: accept.map(|accept| PartyOverview {
            collateral_sat: accept.accept_collateral.to_sat(),
            funding_pubkey: accept.funding_pubkey.to_string(),
            payout: ScriptSummary::new(&accept.payout_spk, network),
            change: ScriptSummary::new(&accept.change_spk, network),
        }),
        fee_rate_per_vb: offer.fee_rate_per_vb,
        fee_rule: contract.map(|contract| fee_rule_name(contract.fee_rule)),
        contract_flags: contract_flag_names(offer.contract_flags),
        oracle_maturity,
        cet_locktime: LocktimeSummary::new(offer.cet_locktime),
        refund_locktime: LocktimeSummary::new(offer.refund_locktime),
        funding_output: contract.map(|contract| FundingOutput {
            txid: contract.transactions.fund.compute_txid().to_string(),
            vout: contract.fund_output_index,
            value_sat: contract.fund_output_value.to_sat(),
        }),
        payout_overrides: overrides(offer)
            .iter()
            .map(|record| OverrideRow {
                covers: describe(&record.outcome),
                script: ScriptSummary::new(&record.script_pubkey, network),
            })
            .collect(),
    }
}

fn maturity_epochs(info: &ddk_messages::oracle_msgs::OracleInfo) -> Vec<u32> {
    use ddk_messages::oracle_msgs::OracleInfo;
    match info {
        OracleInfo::Single(single) => {
            vec![single.oracle_announcement.oracle_event.event_maturity_epoch]
        }
        OracleInfo::Multi(multi) => multi
            .oracle_announcements
            .iter()
            .map(|announcement| announcement.oracle_event.event_maturity_epoch)
            .collect(),
    }
}

/// What a CET settles: an enum outcome, or the numeric values it covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CetOutcome {
    /// An enum outcome.
    Enum {
        /// The outcome string the oracle attests.
        outcome: String,
    },
    /// A range of numeric outcomes.
    Numeric {
        /// The lowest value the CET settles.
        first: u64,
        /// The highest value the CET settles.
        last: u64,
    },
    /// The CET could not be matched to an outcome.
    Unknown,
}

impl CetOutcome {
    fn label(&self, position: usize) -> String {
        match self {
            Self::Enum { outcome } => outcome.clone(),
            Self::Numeric { first, last } if first == last => format!("{first}"),
            Self::Numeric { first, last } => format!("{first}..{last}"),
            Self::Unknown => format!("CET {position}"),
        }
    }

    fn covered_by(&self, record: &OverrideOutcome) -> bool {
        match (self, record) {
            (Self::Enum { outcome }, OverrideOutcome::Enum { outcome: covered }) => {
                outcome == covered
            }
            (Self::Numeric { first, last }, OverrideOutcome::Numeric { start, end }) => {
                first >= start && last <= end
            }
            _ => false,
        }
    }
}

/// What each CET of `info` settles, in CET order.
fn settles(info: &ExecutionInfo, total: bitcoin::Amount) -> Vec<CetOutcome> {
    match &info.contract_descriptor {
        ExecutionDescriptor::Enum(descriptor) => descriptor
            .outcome_payouts
            .iter()
            .map(|payout| CetOutcome::Enum {
                outcome: payout.outcome.clone(),
            })
            .collect(),
        ExecutionDescriptor::Numerical(descriptor) => {
            let Ok(ranges) = descriptor.get_range_payouts(total) else {
                return Vec::new();
            };
            let numeric = &descriptor.oracle_numeric_infos;
            let largest = numeric
                .nb_digits
                .iter()
                .filter_map(|digits| {
                    u32::try_from(*digits)
                        .ok()
                        .and_then(|digits| (numeric.base as u64).checked_pow(digits))
                })
                .max()
                .map_or(0, |values| values.saturating_sub(1));
            let last_position = ranges.len().saturating_sub(1);
            ranges
                .iter()
                .enumerate()
                .map(|(position, range)| {
                    let first = range.start as u64;
                    let mut last = first.saturating_add((range.count as u64).saturating_sub(1));
                    if position == last_position && numeric.has_diff_nb_digits() {
                        last = last.max(largest);
                    }
                    CetOutcome::Numeric { first, last }
                })
                .collect()
        }
    }
}

fn payouts(offer: &OfferDlc, accept: &AcceptDlc, contract: &RebuiltContract) -> Payouts {
    let network = network(offer);
    let overrides = overrides(offer);
    let total = offer.get_total_collateral();
    let label = |transaction: &Transaction, settles: Option<&CetOutcome>| -> Vec<PayoutOutput> {
        transaction
            .output
            .iter()
            .map(|output| {
                let script = output.script_pubkey.as_script();
                let redirect = settles.and_then(|settles| {
                    overrides.iter().find(|record| {
                        settles.covered_by(&record.outcome)
                            && record.script_pubkey.as_script() == script
                    })
                });
                let (payee, record) = match redirect {
                    Some(record) => (
                        Payee::ThirdParty,
                        Some(format!(
                            "payout-script-overrides ({PAYOUT_SCRIPT_OVERRIDES_TYPE}): {}",
                            describe(&record.outcome)
                        )),
                    ),
                    None => (payee(script, offer, accept), None),
                };
                PayoutOutput {
                    payee,
                    value_sat: output.value.to_sat(),
                    script: ScriptSummary::new(script, network),
                    record,
                }
            })
            .collect()
    };

    let refund = &contract.transactions.refund;
    let mut cets = Vec::with_capacity(contract.transactions.cets.len());
    for (info_index, (info, range)) in contract
        .execution_infos
        .iter()
        .zip(&contract.cet_ranges)
        .enumerate()
    {
        let settled = settles(info, total);
        for (position, index) in range.clone().enumerate() {
            let Some(cet) = contract.transactions.cets.get(index) else {
                continue;
            };
            let settles = settled
                .get(position)
                .cloned()
                .unwrap_or(CetOutcome::Unknown);
            cets.push(CetPayouts {
                index,
                contract_info: info_index,
                outcome: settles.label(position),
                outputs: label(cet, Some(&settles)),
                settles,
                txid: cet.compute_txid().to_string(),
            });
        }
    }
    Payouts {
        refund: TransactionPayouts {
            txid: refund.compute_txid().to_string(),
            locktime: LocktimeSummary::new(refund.lock_time.to_consensus_u32()),
            outputs: label(refund, None),
        },
        cets,
    }
}

fn payee(script: &Script, offer: &OfferDlc, accept: &AcceptDlc) -> Payee {
    let offerer = offer.payout_spk.as_script() == script;
    let accepter = accept.payout_spk.as_script() == script;
    match (offerer, accepter) {
        (true, true) => Payee::Shared,
        (true, false) => Payee::Offerer,
        (false, true) => Payee::Accepter,
        (false, false) => Payee::Unknown,
    }
}

/// How many CETs the text report lists before eliding the middle.
pub const TEXT_CET_LIMIT: usize = 40;

/// Renders `report` as text for a terminal.
pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    let line = |out: &mut String, text: &str| {
        out.push_str(text);
        out.push('\n');
    };
    line(
        &mut out,
        &format!(
            "dlc-verify {} (DDK {})",
            report.verifier.version, report.verifier.ddk
        ),
    );
    let counts = report.counts;
    let mut result = format!(
        "Result: {}  ({} passed, {} warned, {} failed, {} skipped",
        report.status.name().to_uppercase(),
        counts.pass,
        counts.warn,
        counts.fail,
        counts.skip
    );
    if let Some(policy) = &report.policy {
        result.push_str(&format!("; policy {}", policy.status.name()));
    }
    result.push(')');
    line(&mut out, &result);

    if let Some(contract) = &report.contract {
        out.push('\n');
        line(&mut out, "Contract");
        let mut rows: Vec<(String, String)> = Vec::new();
        rows.push((
            "Network".into(),
            contract.network.unwrap_or("unknown").into(),
        ));
        if let Some(id) = &contract.contract_id {
            rows.push(("Contract id".into(), id.clone()));
        }
        rows.push((
            "Temporary id".into(),
            contract.temporary_contract_id.clone(),
        ));
        let accept_share = contract
            .total_collateral_sat
            .saturating_sub(contract.offerer.collateral_sat);
        rows.push((
            "Collateral".into(),
            format!(
                "{} sat: offerer {}, accepter {}",
                sats(contract.total_collateral_sat),
                sats(contract.offerer.collateral_sat),
                sats(accept_share)
            ),
        ));
        let mut fee = format!("{} sat/vB", contract.fee_rate_per_vb);
        if let Some(rule) = contract.fee_rule {
            fee.push_str(&format!(", CET fee rule {rule}"));
        }
        rows.push(("Fee rate".into(), fee));
        rows.push((
            "Flags".into(),
            if contract.contract_flags.is_empty() {
                "none".into()
            } else {
                contract.contract_flags.join(", ")
            },
        ));
        if let Some(maturity) = &contract.oracle_maturity {
            rows.push((
                "Oracle maturity".into(),
                if maturity.earliest.unix == maturity.latest.unix {
                    maturity.earliest.utc.clone()
                } else {
                    format!("{} to {}", maturity.earliest.utc, maturity.latest.utc)
                },
            ));
        }
        rows.push(("CET locktime".into(), locktime(&contract.cet_locktime)));
        rows.push((
            "Refund locktime".into(),
            locktime(&contract.refund_locktime),
        ));
        if let Some(funding) = &contract.funding_output {
            rows.push((
                "Funding output".into(),
                format!(
                    "{}:{}, {} sat",
                    funding.txid,
                    funding.vout,
                    sats(funding.value_sat)
                ),
            ));
        }
        rows.push((
            "Offerer pays to".into(),
            contract.offerer.payout.display().to_owned(),
        ));
        if let Some(accepter) = &contract.accepter {
            rows.push((
                "Accepter pays to".into(),
                accepter.payout.display().to_owned(),
            ));
        }
        for record in &contract.payout_overrides {
            rows.push((
                "Third party".into(),
                format!("{} for {}", record.script.display(), record.covers),
            ));
        }
        let width = rows.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
        for (key, value) in rows {
            line(&mut out, &format!("  {key:<width$}  {value}"));
        }
    }

    out.push('\n');
    line(&mut out, "Checks");
    let width = report
        .checks
        .iter()
        .map(|check| check.id.len())
        .max()
        .unwrap_or(0);
    for check in &report.checks {
        line(
            &mut out,
            &format!(
                "  {:<4}  {:<width$}  {}",
                check.status.name(),
                check.id,
                check.detail
            ),
        );
    }

    if let Some(policy) = &report.policy {
        out.push('\n');
        line(
            &mut out,
            &match &policy.name {
                Some(name) => format!("Policy {name}"),
                None => "Policy".to_owned(),
            },
        );
        let width = policy
            .checks
            .iter()
            .map(|check| check.id.len())
            .max()
            .unwrap_or(0);
        for check in &policy.checks {
            line(
                &mut out,
                &format!(
                    "  {:<4}  {:<width$}  {}",
                    check.status.name(),
                    check.id,
                    check.detail
                ),
            );
        }
    }

    if let Some(payouts) = &report.payouts {
        out.push('\n');
        line(
            &mut out,
            &format!(
                "Refund ({})",
                match payouts.refund.locktime.kind {
                    LocktimeKind::Time => format!(
                        "from {}",
                        format_unix(u64::from(payouts.refund.locktime.value))
                    ),
                    LocktimeKind::Height => format!("from block {}", payouts.refund.locktime.value),
                    LocktimeKind::None => "no lock".to_owned(),
                }
            ),
        );
        line(&mut out, &format!("  {}", outputs(&payouts.refund.outputs)));

        out.push('\n');
        line(&mut out, &format!("CET payouts ({})", payouts.cets.len()));
        let multiple_infos = payouts.cets.iter().any(|cet| cet.contract_info > 0);
        let label = |cet: &CetPayouts| {
            if multiple_infos {
                format!("[{}] {}", cet.contract_info, cet.outcome)
            } else {
                cet.outcome.clone()
            }
        };
        let width = payouts
            .cets
            .iter()
            .map(|cet| label(cet).len())
            .max()
            .unwrap_or(0);
        let shown: Vec<&CetPayouts> = if payouts.cets.len() > TEXT_CET_LIMIT {
            let half = TEXT_CET_LIMIT / 2;
            payouts
                .cets
                .iter()
                .take(half)
                .chain(payouts.cets.iter().skip(payouts.cets.len() - half))
                .collect()
        } else {
            payouts.cets.iter().collect()
        };
        for (position, cet) in shown.iter().enumerate() {
            if payouts.cets.len() > TEXT_CET_LIMIT && position == TEXT_CET_LIMIT / 2 {
                line(
                    &mut out,
                    &format!(
                        "  ... {} more (the JSON report lists every CET)",
                        payouts.cets.len() - TEXT_CET_LIMIT
                    ),
                );
            }
            line(
                &mut out,
                &format!("  {:<width$}  {}", label(cet), outputs(&cet.outputs)),
            );
        }
    }
    out
}

fn locktime(summary: &LocktimeSummary) -> String {
    match (&summary.kind, &summary.utc) {
        (LocktimeKind::Time, Some(utc)) => utc.clone(),
        (LocktimeKind::Height, _) => format!("block {}", summary.value),
        _ => "0 (no lock)".to_owned(),
    }
}

fn outputs(outputs: &[PayoutOutput]) -> String {
    if outputs.is_empty() {
        return "no outputs".to_owned();
    }
    outputs
        .iter()
        .map(|output| match output.payee {
            Payee::Offerer | Payee::Accepter | Payee::Shared => {
                format!("{} {} sat", output.payee.name(), sats(output.value_sat))
            }
            Payee::ThirdParty | Payee::Unknown => format!(
                "{} {} sat to {}",
                output.payee.name(),
                sats(output.value_sat),
                output.script.display()
            ),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Formats sats with thousands separators.
pub fn sats(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_sats() {
        assert_eq!(sats(0), "0");
        assert_eq!(sats(999), "999");
        assert_eq!(sats(1000), "1,000");
        assert_eq!(sats(100_000_000), "100,000,000");
    }
}
