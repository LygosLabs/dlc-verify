//! Comparing a verified contract with a policy.

use std::collections::BTreeSet;

use dlc_verify_core::decode::tlv_records;
use dlc_verify_core::inspect::{OracleSummary, summarize_offer};
use dlc_verify_core::network::{network_name, parse_network};
use dlc_verify_core::report::{
    CetOutcome, ContractOverview, PartyOverview, Payee, PayoutOutput, PolicyOutcome, Report, sats,
};
use dlc_verify_core::summary::LocktimeSummary;
use dlc_verify_core::time::{LocktimeKind, format_duration, format_unix};
use dlc_verify_core::{Check, CheckStatus, MessageKind, Messages, Verification};

use crate::schema::{
    CetRule, Destination, OraclePolicy, Party, PartyPolicy, Pay, Policy, destination_script,
    funding_key, oracle_key,
};

/// Every policy check, in report order. A policy runs only the checks for what it states.
pub const POLICY_CHECK_IDS: [&str; 16] = [
    "policy.network",
    "policy.collateral",
    "policy.offerer",
    "policy.accepter",
    "policy.fee-rate",
    "policy.contract-flags",
    "policy.tlvs",
    "policy.oracle-pubkeys",
    "policy.oracle-events",
    "policy.oracle-maturity",
    "policy.oracle-threshold",
    "policy.cet-locktime",
    "policy.refund-locktime",
    "policy.refund-payout",
    "policy.cet-payouts",
    "policy.cet-coverage",
];

/// How many problems a check's detail lists before counting the rest.
const DETAIL_LIMIT: usize = 5;

const NO_OFFER: &str = "not run: the offer did not decode";
const NO_ACCEPT: &str = "not run: there is no accept message";
const NO_REBUILD: &str = "not run: the contract was not rebuilt";

/// Checks `verification` (and `report`, its report) against `policy`.
pub fn evaluate(policy: &Policy, verification: &Verification, report: &Report) -> PolicyOutcome {
    let context = verification
        .messages
        .as_ref()
        .zip(report.contract.as_ref())
        .map(|(messages, overview)| Context {
            policy,
            messages,
            overview,
            report,
            oracles: summarize_offer(&messages.offer)
                .contract
                .infos
                .into_iter()
                .map(|info| info.oracle)
                .collect(),
        });
    let checks = stated(policy)
        .into_iter()
        .map(|id| match &context {
            Some(context) => context.run(id),
            None => skip(id, NO_OFFER),
        })
        .collect();
    PolicyOutcome::new(policy.name.clone(), checks)
}

/// Builds the report of `verification` with `policy`'s result attached.
pub fn report_with_policy(policy: &Policy, verification: &Verification) -> Report {
    let report = dlc_verify_core::report(verification);
    let outcome = evaluate(policy, verification, &report);
    report.with_policy(outcome)
}

/// The checks `policy` asks for, in [`POLICY_CHECK_IDS`] order.
fn stated(policy: &Policy) -> Vec<&'static str> {
    let oracle = policy.oracle.as_ref();
    let locktimes = policy.locktimes.as_ref();
    [
        ("policy.network", policy.network.is_some()),
        ("policy.collateral", policy.total_collateral_sat.is_some()),
        ("policy.offerer", policy.offerer.is_some()),
        ("policy.accepter", policy.accepter.is_some()),
        ("policy.fee-rate", policy.max_fee_rate_per_vb.is_some()),
        ("policy.contract-flags", policy.contract_flags.is_some()),
        ("policy.tlvs", policy.allowed_tlvs.is_some()),
        (
            "policy.oracle-pubkeys",
            oracle.is_some_and(|oracle| oracle.pubkeys.is_some()),
        ),
        (
            "policy.oracle-events",
            oracle.is_some_and(|oracle| oracle.event_ids.is_some()),
        ),
        (
            "policy.oracle-maturity",
            oracle.is_some_and(|oracle| oracle.maturity.is_some()),
        ),
        (
            "policy.oracle-threshold",
            oracle.is_some_and(|oracle| oracle.threshold.is_some()),
        ),
        (
            "policy.cet-locktime",
            locktimes.is_some_and(|locktimes| locktimes.cet.is_some()),
        ),
        (
            "policy.refund-locktime",
            locktimes.is_some_and(|locktimes| {
                locktimes.refund.is_some()
                    || locktimes.refund_delay.is_some()
                    || locktimes.refund_delay_min.is_some()
            }),
        ),
        ("policy.refund-payout", policy.refund.is_some()),
        ("policy.cet-payouts", !policy.cets.is_empty()),
        ("policy.cet-coverage", policy.require_every_cet),
    ]
    .into_iter()
    .filter_map(|(id, stated)| stated.then_some(id))
    .collect()
}

struct Context<'a> {
    policy: &'a Policy,
    messages: &'a Messages,
    overview: &'a ContractOverview,
    report: &'a Report,
    oracles: Vec<OracleSummary>,
}

impl Context<'_> {
    fn run(&self, id: &'static str) -> Check {
        let policy = self.policy;
        let overview = self.overview;
        let oracle = policy.oracle.clone().unwrap_or_default();
        let locktimes = policy.locktimes.clone().unwrap_or_default();
        match id {
            "policy.network" => network(policy.network.as_deref().unwrap_or_default(), overview),
            "policy.collateral" => {
                let expected = policy.total_collateral_sat.unwrap_or_default();
                let actual = overview.total_collateral_sat;
                if actual == expected {
                    pass(id, format!("{} sat", sats(actual)))
                } else {
                    fail(
                        id,
                        format!(
                            "total collateral is {} sat; the policy expects {}",
                            sats(actual),
                            sats(expected)
                        ),
                    )
                }
            }
            "policy.offerer" => party(
                id,
                &policy.offerer.clone().unwrap_or_default(),
                Some(&overview.offerer),
            ),
            "policy.accepter" => party(
                id,
                &policy.accepter.clone().unwrap_or_default(),
                overview.accepter.as_ref(),
            ),
            "policy.fee-rate" => {
                let max = policy.max_fee_rate_per_vb.unwrap_or_default();
                let actual = overview.fee_rate_per_vb;
                if actual <= max {
                    pass(id, format!("{actual} sat/vB, within {max}"))
                } else {
                    fail(
                        id,
                        format!("{actual} sat/vB is above the policy's maximum of {max}"),
                    )
                }
            }
            "policy.contract-flags" => {
                let expected: BTreeSet<&str> = policy
                    .contract_flags
                    .iter()
                    .flatten()
                    .map(String::as_str)
                    .collect();
                let actual: BTreeSet<&str> =
                    overview.contract_flags.iter().map(String::as_str).collect();
                if actual == expected {
                    pass(id, flag_list(&actual))
                } else {
                    fail(
                        id,
                        format!(
                            "the offer's flags are {}; the policy expects {}",
                            flag_list(&actual),
                            flag_list(&expected)
                        ),
                    )
                }
            }
            "policy.tlvs" => self.tlvs(policy.allowed_tlvs.as_deref().unwrap_or_default()),
            "policy.oracle-pubkeys" => self.oracle_pubkeys(&oracle),
            "policy.oracle-events" => self.oracle_events(&oracle),
            "policy.oracle-maturity" => self.oracle_maturity(&oracle),
            "policy.oracle-threshold" => self.oracle_threshold(&oracle),
            "policy.cet-locktime" => {
                let expected = LocktimeSummary::new(locktimes.cet.unwrap_or_default());
                let actual = &overview.cet_locktime;
                if actual.value == expected.value {
                    pass(id, locktime(actual))
                } else {
                    fail(
                        id,
                        format!(
                            "the CET locktime is {}; the policy expects {}",
                            locktime(actual),
                            locktime(&expected)
                        ),
                    )
                }
            }
            "policy.refund-locktime" => self.refund_locktime(
                locktimes.refund,
                locktimes.refund_delay,
                locktimes.refund_delay_min,
            ),
            "policy.refund-payout" => self.refund_payout(),
            "policy.cet-payouts" => self.cet_payouts(),
            "policy.cet-coverage" => self.cet_coverage(),
            _ => skip(id, "not run: unknown policy check"),
        }
    }

    fn missing_payouts(&self, id: &'static str) -> Check {
        if self.messages.accept.is_none() {
            skip(id, NO_ACCEPT)
        } else {
            skip(id, NO_REBUILD)
        }
    }

    fn tlvs(&self, allowed: &[u64]) -> Check {
        let id = "policy.tlvs";
        let mut found = Vec::new();
        found.extend(
            tlv_records(MessageKind::Offer, &self.messages.offer.tlvs)
                .into_iter()
                .map(|record| ("offer", record.tlv_type)),
        );
        if let Some(accept) = &self.messages.accept {
            found.extend(
                tlv_records(MessageKind::Accept, &accept.tlvs)
                    .into_iter()
                    .map(|record| ("accept", record.tlv_type)),
            );
        }
        if let Some(sign) = &self.messages.sign {
            found.extend(
                tlv_records(MessageKind::Sign, &sign.tlvs)
                    .into_iter()
                    .map(|record| ("sign", record.tlv_type)),
            );
        }
        let problems: Vec<String> = found
            .iter()
            .filter(|(_, tlv_type)| !allowed.contains(tlv_type))
            .map(|(message, tlv_type)| {
                format!("the {message} carries TLV {tlv_type}, which the policy does not allow")
            })
            .collect();
        let listed: Vec<String> = found
            .iter()
            .map(|(message, tlv_type)| format!("{tlv_type} on the {message}"))
            .collect();
        verdict(
            id,
            problems,
            if listed.is_empty() {
                "no TLV records".to_owned()
            } else {
                format!("allowed: {}", listed.join(", "))
            },
        )
    }

    fn announcements(
        &self,
    ) -> impl Iterator<Item = &dlc_verify_core::inspect::AnnouncementSummary> {
        self.oracles
            .iter()
            .flat_map(|oracle| oracle.announcements.iter())
    }

    fn oracle_pubkeys(&self, oracle: &OraclePolicy) -> Check {
        let id = "policy.oracle-pubkeys";
        let allowed: Result<BTreeSet<String>, _> = oracle
            .pubkeys
            .iter()
            .flatten()
            .map(|key| oracle_key(key))
            .collect();
        let allowed = match allowed {
            Ok(allowed) => allowed,
            Err(error) => return fail(id, format!("the policy is invalid: {error}")),
        };
        let mut count = 0;
        let problems = self
            .announcements()
            .inspect(|_| count += 1)
            .filter(|announcement| !allowed.contains(&announcement.oracle_public_key))
            .map(|announcement| {
                format!(
                    "event {:?} is announced by {}, which the policy does not list",
                    announcement.event_id, announcement.oracle_public_key
                )
            })
            .collect();
        verdict(
            id,
            problems,
            format!("{count} announcement(s), each by a listed oracle"),
        )
    }

    fn oracle_events(&self, oracle: &OraclePolicy) -> Check {
        let id = "policy.oracle-events";
        let allowed: BTreeSet<&str> = oracle
            .event_ids
            .iter()
            .flatten()
            .map(String::as_str)
            .collect();
        let mut seen = BTreeSet::new();
        let problems = self
            .announcements()
            .inspect(|announcement| {
                seen.insert(announcement.event_id.clone());
            })
            .filter(|announcement| !allowed.contains(announcement.event_id.as_str()))
            .map(|announcement| {
                format!(
                    "event {:?} is not one the policy lists",
                    announcement.event_id
                )
            })
            .collect();
        let seen: Vec<String> = seen.into_iter().map(|event| format!("{event:?}")).collect();
        verdict(id, problems, seen.join(", "))
    }

    fn oracle_maturity(&self, oracle: &OraclePolicy) -> Check {
        let id = "policy.oracle-maturity";
        let expected = oracle.maturity.unwrap_or_default();
        let problems = self
            .announcements()
            .filter(|announcement| announcement.maturity.unix != expected)
            .map(|announcement| {
                format!(
                    "event {:?} matures at {}; the policy expects {}",
                    announcement.event_id,
                    announcement.maturity.utc,
                    format_unix(expected)
                )
            })
            .collect();
        verdict(
            id,
            problems,
            format!("every event matures at {}", format_unix(expected)),
        )
    }

    fn oracle_threshold(&self, oracle: &OraclePolicy) -> Check {
        let id = "policy.oracle-threshold";
        let expected = oracle.threshold.unwrap_or_default();
        let problems = self
            .oracles
            .iter()
            .enumerate()
            .filter(|(_, oracle)| oracle.threshold != expected)
            .map(|(index, oracle)| {
                format!(
                    "contract info {index} needs {} of {} oracles; the policy expects {expected}",
                    oracle.threshold,
                    oracle.announcements.len()
                )
            })
            .collect();
        let shapes: BTreeSet<String> = self
            .oracles
            .iter()
            .map(|oracle| format!("{} of {}", oracle.threshold, oracle.announcements.len()))
            .collect();
        verdict(
            id,
            problems,
            shapes.into_iter().collect::<Vec<_>>().join(", "),
        )
    }

    fn refund_locktime(
        &self,
        exact: Option<u32>,
        delay: Option<u64>,
        delay_min: Option<u64>,
    ) -> Check {
        let id = "policy.refund-locktime";
        let actual = &self.overview.refund_locktime;
        let mut problems = Vec::new();
        if let Some(expected) = exact
            && actual.value != expected
        {
            problems.push(format!(
                "the refund locktime is {}; the policy expects {}",
                locktime(actual),
                locktime(&LocktimeSummary::new(expected))
            ));
        }
        let mut gap = None;
        if delay.is_some() || delay_min.is_some() {
            let earliest = self
                .overview
                .oracle_maturity
                .as_ref()
                .map(|maturity| maturity.earliest.unix);
            match (actual.kind, earliest) {
                (LocktimeKind::Time, Some(earliest)) => {
                    let refund = u64::from(actual.value);
                    if refund < earliest {
                        problems.push(format!(
                            "the refund unlocks {} before the earliest oracle maturity",
                            format_duration(earliest - refund)
                        ));
                    } else {
                        let seconds = refund - earliest;
                        gap = Some(seconds);
                        if let Some(expected) = delay
                            && seconds != expected
                        {
                            problems.push(format!(
                                "the refund unlocks {} after the earliest oracle maturity; the \
                                 policy expects {}",
                                format_duration(seconds),
                                format_duration(expected)
                            ));
                        }
                        if let Some(minimum) = delay_min
                            && seconds < minimum
                        {
                            problems.push(format!(
                                "the refund unlocks {} after the earliest oracle maturity; the \
                                 policy expects at least {}",
                                format_duration(seconds),
                                format_duration(minimum)
                            ));
                        }
                    }
                }
                (LocktimeKind::Time, None) => {
                    problems.push("the contract has no oracle maturity to measure from".to_owned());
                }
                _ => problems.push(format!(
                    "the refund locktime is {}, not a time, so it has no delay after maturity",
                    locktime(actual)
                )),
            }
        }
        let detail = match gap {
            Some(seconds) => format!(
                "{}, {} after the earliest oracle maturity",
                locktime(actual),
                format_duration(seconds)
            ),
            None => locktime(actual),
        };
        verdict(id, problems, detail)
    }

    fn refund_payout(&self) -> Check {
        let id = "policy.refund-payout";
        let Some(payouts) = &self.report.payouts else {
            return self.missing_payouts(id);
        };
        let pays = self
            .policy
            .refund
            .as_ref()
            .map(|refund| refund.pay.as_slice())
            .unwrap_or_default();
        match match_outputs(pays, &payouts.refund.outputs) {
            Ok(()) => pass(
                id,
                format!("pays {}", describe_outputs(&payouts.refund.outputs)),
            ),
            Err(problem) => fail(id, format!("the refund {problem}")),
        }
    }

    fn cet_payouts(&self) -> Check {
        let id = "policy.cet-payouts";
        let Some(payouts) = &self.report.payouts else {
            return self.missing_payouts(id);
        };
        let mut problems = Vec::new();
        let mut followed = BTreeSet::new();
        for rule in &self.policy.cets {
            let mut touched = false;
            for cet in &payouts.cets {
                if rule
                    .contract_info
                    .is_some_and(|info| info != cet.contract_info)
                {
                    continue;
                }
                match applies(rule, &cet.settles) {
                    Applies::No => {}
                    Applies::Partly => {
                        touched = true;
                        problems.push(format!(
                            "CET {} settles {}, which straddles the policy's {}",
                            cet.index,
                            cet.outcome,
                            rule_label(rule)
                        ));
                    }
                    Applies::Yes => {
                        touched = true;
                        followed.insert(cet.index);
                        if let Err(problem) = match_outputs(&rule.pay, &cet.outputs) {
                            problems.push(format!("CET {} ({}) {problem}", cet.index, cet.outcome));
                        }
                    }
                }
            }
            if !touched {
                problems.push(format!("no CET settles the policy's {}", rule_label(rule)));
            }
        }
        verdict(
            id,
            problems,
            format!(
                "{} CET(s) pay what the policy's {} rule(s) say",
                followed.len(),
                self.policy.cets.len()
            ),
        )
    }

    fn cet_coverage(&self) -> Check {
        let id = "policy.cet-coverage";
        let Some(payouts) = &self.report.payouts else {
            return self.missing_payouts(id);
        };
        let uncovered: Vec<String> = payouts
            .cets
            .iter()
            .filter(|cet| {
                !self.policy.cets.iter().any(|rule| {
                    rule.contract_info
                        .is_none_or(|info| info == cet.contract_info)
                        && applies(rule, &cet.settles) == Applies::Yes
                })
            })
            .map(|cet| format!("CET {} ({})", cet.index, cet.outcome))
            .collect();
        if uncovered.is_empty() {
            pass(
                id,
                format!("each of the {} CETs matches a rule", payouts.cets.len()),
            )
        } else {
            let count = uncovered.len();
            fail(
                id,
                format!(
                    "{count} of {} CETs match no rule: {}",
                    payouts.cets.len(),
                    join(uncovered, ", ")
                ),
            )
        }
    }
}

fn network(expected: &str, overview: &ContractOverview) -> Check {
    let id = "policy.network";
    let Some(expected) = parse_network(expected).map(network_name) else {
        return fail(
            id,
            format!("the policy names an unknown network {expected:?}"),
        );
    };
    match overview.network {
        Some(actual) if actual == expected => pass(id, actual),
        Some(actual) => fail(
            id,
            format!("the offer is for {actual}; the policy expects {expected}"),
        ),
        None => fail(
            id,
            format!("the offer's chain hash names no known network; the policy expects {expected}"),
        ),
    }
}

fn party(id: &'static str, expected: &PartyPolicy, actual: Option<&PartyOverview>) -> Check {
    let Some(actual) = actual else {
        return skip(id, NO_ACCEPT);
    };
    let mut problems = Vec::new();
    let mut matched = Vec::new();
    if let Some(key) = &expected.funding_pubkey {
        match funding_key(key) {
            Ok(key) if key == actual.funding_pubkey => matched.push("funding key"),
            Ok(key) => problems.push(format!(
                "the funding key is {}; the policy expects {key}",
                actual.funding_pubkey
            )),
            Err(error) => problems.push(format!("the policy is invalid: {error}")),
        }
    }
    if let Some(payout) = &expected.payout {
        match destination_script(payout) {
            Ok(script) if script == actual.payout.hex => matched.push("payout script"),
            Ok(_) => problems.push(format!(
                "the payout goes to {}; the policy expects {payout}",
                actual.payout.display()
            )),
            Err(error) => problems.push(format!("the policy is invalid: {error}")),
        }
    }
    if let Some(collateral) = expected.collateral_sat {
        if collateral == actual.collateral_sat {
            matched.push("collateral");
        } else {
            problems.push(format!(
                "the collateral is {} sat; the policy expects {}",
                sats(actual.collateral_sat),
                sats(collateral)
            ));
        }
    }
    let detail = if matched.is_empty() {
        "nothing to compare".to_owned()
    } else {
        format!("{} match", matched.join(", "))
    };
    verdict(id, problems, detail)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Applies {
    Yes,
    Partly,
    No,
}

/// Whether `rule` covers a CET that settles `settles`.
fn applies(rule: &CetRule, settles: &CetOutcome) -> Applies {
    match (&rule.outcome, &rule.values, settles) {
        (Some(expected), None, CetOutcome::Enum { outcome }) if expected == outcome => Applies::Yes,
        (None, Some([low, high]), CetOutcome::Numeric { first, last }) => {
            if first >= low && last <= high {
                Applies::Yes
            } else if last < low || first > high {
                Applies::No
            } else {
                Applies::Partly
            }
        }
        _ => Applies::No,
    }
}

fn rule_label(rule: &CetRule) -> String {
    let covers = match (&rule.outcome, &rule.values) {
        (Some(outcome), _) => format!("outcome {outcome:?}"),
        (None, Some([first, last])) => format!("values {first}..{last}"),
        (None, None) => "rule with no outcome".to_owned(),
    };
    match rule.contract_info {
        Some(info) => format!("{covers} in contract info {info}"),
        None => covers,
    }
}

/// Matches `outputs` one to one with `pays`, in any order.
fn match_outputs(pays: &[Pay], outputs: &[PayoutOutput]) -> Result<(), String> {
    let expected = pays
        .iter()
        .map(|pay| pay.destination().map(|destination| (destination, pay)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot be checked: the policy is invalid: {error}"))?;
    let mut used = vec![false; outputs.len()];
    if expected.len() == outputs.len() && assign(&expected, outputs, &mut used) {
        Ok(())
    } else {
        Err(format!(
            "pays {}; the policy expects {}",
            describe_outputs(outputs),
            describe_pays(pays)
        ))
    }
}

fn assign(expected: &[(Destination, &Pay)], outputs: &[PayoutOutput], used: &mut [bool]) -> bool {
    let Some(((destination, pay), rest)) = expected.split_first() else {
        return true;
    };
    for (index, output) in outputs.iter().enumerate() {
        if used.get(index).copied().unwrap_or(true) || !pays_to(destination, pay, output) {
            continue;
        }
        if let Some(slot) = used.get_mut(index) {
            *slot = true;
        }
        if assign(rest, outputs, used) {
            return true;
        }
        if let Some(slot) = used.get_mut(index) {
            *slot = false;
        }
    }
    false
}

fn pays_to(destination: &Destination, pay: &Pay, output: &PayoutOutput) -> bool {
    let to = match destination {
        Destination::Party(Party::Offerer) => {
            matches!(output.payee, Payee::Offerer | Payee::Shared)
        }
        Destination::Party(Party::Accepter) => {
            matches!(output.payee, Payee::Accepter | Payee::Shared)
        }
        Destination::Party(Party::ThirdParty) => output.payee == Payee::ThirdParty,
        Destination::Script(script) => output.script.hex == *script,
    };
    to && pay.value_sat.is_none_or(|value| output.value_sat == value)
        && pay
            .min_value_sat
            .is_none_or(|minimum| output.value_sat >= minimum)
}

fn describe_outputs(outputs: &[PayoutOutput]) -> String {
    if outputs.is_empty() {
        return "nothing".to_owned();
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

fn describe_pays(pays: &[Pay]) -> String {
    pays.iter()
        .map(|pay| {
            let to = match (&pay.party, &pay.address, &pay.script) {
                (Some(party), _, _) => party.name().to_owned(),
                (None, Some(address), _) => address.clone(),
                (None, None, Some(script)) => format!("script {script}"),
                (None, None, None) => "nowhere".to_owned(),
            };
            match (pay.value_sat, pay.min_value_sat) {
                (Some(value), _) => format!("{to} {} sat", sats(value)),
                (None, Some(minimum)) => format!("{to} at least {} sat", sats(minimum)),
                (None, None) => to,
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn flag_list(flags: &BTreeSet<&str>) -> String {
    if flags.is_empty() {
        "no flags".to_owned()
    } else {
        flags.iter().copied().collect::<Vec<_>>().join(", ")
    }
}

fn locktime(summary: &LocktimeSummary) -> String {
    match (summary.kind, &summary.utc) {
        (LocktimeKind::Time, Some(utc)) => format!("{} ({utc})", summary.value),
        (LocktimeKind::Height, _) => format!("block {}", summary.value),
        _ => format!("{} (no lock)", summary.value),
    }
}

fn join(problems: Vec<String>, separator: &str) -> String {
    let more = problems.len().saturating_sub(DETAIL_LIMIT);
    let mut text = problems
        .into_iter()
        .take(DETAIL_LIMIT)
        .collect::<Vec<_>>()
        .join(separator);
    if more > 0 {
        text.push_str(&format!("{separator}and {more} more"));
    }
    text
}

fn verdict(id: &'static str, problems: Vec<String>, pass_detail: impl Into<String>) -> Check {
    if problems.is_empty() {
        pass(id, pass_detail)
    } else {
        fail(id, join(problems, "; "))
    }
}

fn pass(id: &'static str, detail: impl Into<String>) -> Check {
    Check {
        id,
        status: CheckStatus::Pass,
        detail: detail.into(),
    }
}

fn fail(id: &'static str, detail: impl Into<String>) -> Check {
    Check {
        id,
        status: CheckStatus::Fail,
        detail: detail.into(),
    }
}

fn skip(id: &'static str, detail: impl Into<String>) -> Check {
    Check {
        id,
        status: CheckStatus::Skip,
        detail: detail.into(),
    }
}
