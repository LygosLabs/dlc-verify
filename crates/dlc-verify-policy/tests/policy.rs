//! Policies against the signed fixtures.

use std::path::PathBuf;

use dlc_verify_core::{CheckStatus, Input, Options, PolicyOutcome, Status, verify};
use dlc_verify_policy::{
    CetRule, OraclePolicy, POLICY_CHECK_IDS, Party, Pay, Policy, RefundRule, evaluate,
    report_with_policy,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> (Input, Options) {
    let path = repo_root().join("fixtures").join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", path.display()));
    let value: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| unreachable!("parsing {}: {error}", path.display()));
    let input = Input::from_bundle(&text)
        .unwrap_or_else(|error| unreachable!("{name}: not a bundle: {error}"));
    (
        input,
        Options {
            now: value["now"].as_u64(),
        },
    )
}

fn policy_file(name: &str) -> Policy {
    let path = repo_root().join("fixtures/policies").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", path.display()));
    Policy::parse(&text).unwrap_or_else(|error| unreachable!("{name}: {error}"))
}

fn run_input(policy: &Policy, input: &Input, options: &Options) -> PolicyOutcome {
    let verification = verify(input, options);
    let report = dlc_verify_core::report(&verification);
    evaluate(policy, &verification, &report)
}

fn run(policy: &Policy, fixture_name: &str) -> PolicyOutcome {
    let (input, options) = fixture(fixture_name);
    run_input(policy, &input, &options)
}

fn status(outcome: &PolicyOutcome, id: &str) -> CheckStatus {
    outcome
        .checks
        .iter()
        .find(|check| check.id == id)
        .map(|check| check.status)
        .unwrap_or_else(|| unreachable!("no {id} check in {outcome:#?}"))
}

fn detail<'a>(outcome: &'a PolicyOutcome, id: &str) -> &'a str {
    outcome
        .checks
        .iter()
        .find(|check| check.id == id)
        .map(|check| check.detail.as_str())
        .unwrap_or_else(|| unreachable!("no {id} check"))
}

fn assert_all_pass(outcome: &PolicyOutcome) {
    for check in &outcome.checks {
        assert_eq!(
            check.status,
            CheckStatus::Pass,
            "{}: {}",
            check.id,
            check.detail
        );
    }
    assert_eq!(outcome.status, Status::Pass);
}

const THIRD_PARTY: &str = "00148807efc1dbbaa930ffb7e4a3bafabc9434c9303c";

#[test]
fn the_example_policies_pass_their_fixtures() {
    let enum_policy = policy_file("enum-payout-override.toml");
    let outcome = run(&enum_policy, "enum-payout-override");
    assert_all_pass(&outcome);
    assert_eq!(outcome.checks.len(), POLICY_CHECK_IDS.len());
    assert_eq!(outcome.name.as_deref(), Some("enum-payout-override"));

    let numeric_policy = policy_file("numeric-payout-override.json");
    assert_all_pass(&run(&numeric_policy, "numeric-payout-override"));
}

#[test]
fn checks_follow_the_catalogue_order() {
    let outcome = run(
        &policy_file("enum-payout-override.toml"),
        "enum-payout-override",
    );
    let ids: Vec<&str> = outcome.checks.iter().map(|check| check.id).collect();
    assert_eq!(ids, POLICY_CHECK_IDS);
}

#[test]
fn a_policy_runs_only_what_it_states() {
    let mut policy = Policy::new(None);
    assert!(run(&policy, "enum-dual-funded").checks.is_empty());
    policy.network = Some("regtest".to_owned());
    let outcome = run(&policy, "enum-dual-funded");
    assert_eq!(outcome.checks.len(), 1);
    assert_eq!(status(&outcome, "policy.network"), CheckStatus::Pass);
}

#[test]
fn a_redirected_payout_the_policy_does_not_expect_fails() {
    // enum-dual-funded pays "down" to the accepter, not the third party the policy names.
    let outcome = run(
        &policy_file("enum-payout-override.toml"),
        "enum-dual-funded",
    );
    assert_eq!(outcome.status, Status::Fail);
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);
    assert!(
        detail(&outcome, "policy.cet-payouts").contains("CET 1 (down) pays accepter 100,000 sat"),
        "{}",
        detail(&outcome, "policy.cet-payouts")
    );
    assert_eq!(status(&outcome, "policy.oracle-events"), CheckStatus::Fail);
    assert_eq!(status(&outcome, "policy.tlvs"), CheckStatus::Pass);
}

#[test]
fn an_unexpected_third_party_fails() {
    let mut policy = Policy::new(None);
    policy.cets = vec![CetRule {
        outcome: Some("down".to_owned()),
        pay: vec![Pay::party(Party::Accepter)],
        ..CetRule::default()
    }];
    let outcome = run(&policy, "enum-payout-override");
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);
    assert!(detail(&outcome, "policy.cet-payouts").contains("third-party 100,000 sat to bcrt1q"));

    policy.cets[0].pay = vec![Pay::party(Party::ThirdParty)];
    assert_eq!(
        status(&run(&policy, "enum-payout-override"), "policy.cet-payouts"),
        CheckStatus::Pass
    );
}

#[test]
fn the_wrong_network_fails() {
    let mut policy = Policy::new(None);
    policy.network = Some("testnet4".to_owned());
    let outcome = run(&policy, "enum-dual-funded");
    assert_eq!(status(&outcome, "policy.network"), CheckStatus::Fail);
    assert_eq!(
        detail(&outcome, "policy.network"),
        "the offer is for regtest; the policy expects testnet4"
    );
    assert_eq!(
        status(&run(&policy, "enum-refund-to-accepter"), "policy.network"),
        CheckStatus::Pass
    );
}

#[test]
fn contract_flags_must_match_exactly() {
    let mut policy = Policy::new(None);
    policy.contract_flags = Some(Vec::new());
    assert_eq!(
        status(
            &run(&policy, "enum-refund-to-accepter"),
            "policy.contract-flags"
        ),
        CheckStatus::Fail
    );
    policy.contract_flags = Some(vec!["refund-to-accepter".to_owned()]);
    assert_eq!(
        status(
            &run(&policy, "enum-refund-to-accepter"),
            "policy.contract-flags"
        ),
        CheckStatus::Pass
    );
    assert_eq!(
        status(&run(&policy, "enum-dual-funded"), "policy.contract-flags"),
        CheckStatus::Fail
    );
}

#[test]
fn the_refund_must_pay_who_the_policy_says() {
    let mut policy = Policy::new(None);
    policy.refund = Some(RefundRule {
        pay: vec![Pay::party(Party::Offerer), Pay::party(Party::Accepter)],
    });
    let outcome = run(&policy, "enum-refund-to-accepter");
    assert_eq!(status(&outcome, "policy.refund-payout"), CheckStatus::Fail);
    assert_eq!(
        detail(&outcome, "policy.refund-payout"),
        "the refund pays accepter 100,000 sat; the policy expects offerer, accepter"
    );

    policy.refund = Some(RefundRule {
        pay: vec![Pay {
            value_sat: Some(100_000),
            ..Pay::party(Party::Accepter)
        }],
    });
    assert_eq!(
        status(
            &run(&policy, "enum-refund-to-accepter"),
            "policy.refund-payout"
        ),
        CheckStatus::Pass
    );
}

#[test]
fn an_unlisted_oracle_fails() {
    let mut policy = Policy::new(None);
    policy.oracle = Some(OraclePolicy {
        pubkeys: Some(vec![
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_owned(),
        ]),
        threshold: Some(2),
        ..OraclePolicy::default()
    });
    let outcome = run(&policy, "enum-dual-funded");
    assert_eq!(status(&outcome, "policy.oracle-pubkeys"), CheckStatus::Fail);
    assert_eq!(
        status(&outcome, "policy.oracle-threshold"),
        CheckStatus::Fail
    );
    assert_eq!(
        detail(&outcome, "policy.oracle-threshold"),
        "contract info 0 needs 1 of 1 oracles; the policy expects 2"
    );
}

#[test]
fn multi_oracle_thresholds_are_checked() {
    let mut policy = Policy::new(None);
    policy.oracle = Some(OraclePolicy {
        threshold: Some(2),
        ..OraclePolicy::default()
    });
    let outcome = run(&policy, "enum-multi-oracle");
    assert_eq!(
        status(&outcome, "policy.oracle-threshold"),
        CheckStatus::Pass
    );
    assert_eq!(detail(&outcome, "policy.oracle-threshold"), "2 of 3");
}

#[test]
fn locktimes_are_checked() {
    let mut policy = policy_file("enum-payout-override.toml");
    if let Some(locktimes) = policy.locktimes.as_mut() {
        locktimes.cet = Some(0);
        locktimes.refund_delay = Some(14 * 86_400);
    }
    let outcome = run(&policy, "enum-payout-override");
    assert_eq!(status(&outcome, "policy.cet-locktime"), CheckStatus::Fail);
    assert_eq!(
        status(&outcome, "policy.refund-locktime"),
        CheckStatus::Fail
    );
    assert!(
        detail(&outcome, "policy.refund-locktime")
            .contains("7d 0h after the earliest oracle maturity; the policy expects 14d 0h"),
        "{}",
        detail(&outcome, "policy.refund-locktime")
    );
}

#[test]
fn a_numeric_rule_that_cuts_a_cet_fails() {
    let mut policy = Policy::new(None);
    policy.cets = vec![CetRule {
        values: Some([0, 300]),
        pay: vec![Pay::script(THIRD_PARTY)],
        ..CetRule::default()
    }];
    let outcome = run(&policy, "numeric-payout-override");
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);
    assert!(
        detail(&outcome, "policy.cet-payouts")
            .contains("CET 0 settles 0..319, which straddles the policy's values 0..300")
    );
}

#[test]
fn a_rule_no_cet_settles_fails() {
    let mut policy = Policy::new(None);
    policy.cets = vec![CetRule {
        outcome: Some("sideways".to_owned()),
        pay: vec![Pay::party(Party::Offerer)],
        ..CetRule::default()
    }];
    let outcome = run(&policy, "enum-dual-funded");
    assert_eq!(
        detail(&outcome, "policy.cet-payouts"),
        "no CET settles the policy's outcome \"sideways\""
    );
}

#[test]
fn coverage_lists_the_cets_no_rule_covers() {
    let mut policy = Policy::new(None);
    policy.require_every_cet = true;
    policy.cets = vec![CetRule {
        values: Some([0, 319]),
        pay: vec![Pay::script(THIRD_PARTY)],
        ..CetRule::default()
    }];
    let outcome = run(&policy, "numeric-payout-override");
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Pass);
    assert_eq!(status(&outcome, "policy.cet-coverage"), CheckStatus::Fail);
    assert_eq!(
        detail(&outcome, "policy.cet-coverage"),
        "10 of 11 CETs match no rule: CET 1 (320..359), CET 2 (360..399), CET 3 (400..439), \
         CET 4 (440..479), CET 5 (480..519), and 5 more"
    );
}

#[test]
fn rules_can_target_one_contract_info() {
    let mut policy = Policy::new(None);
    policy.require_every_cet = true;
    policy.cets = vec![
        CetRule {
            outcome: Some("up".to_owned()),
            contract_info: Some(0),
            pay: vec![Pay::party(Party::Offerer)],
            ..CetRule::default()
        },
        CetRule {
            outcome: Some("down".to_owned()),
            contract_info: Some(0),
            pay: vec![Pay::party(Party::Accepter)],
            ..CetRule::default()
        },
        CetRule {
            outcome: Some("flat".to_owned()),
            contract_info: Some(0),
            pay: vec![Pay::party(Party::Offerer), Pay::party(Party::Accepter)],
            ..CetRule::default()
        },
        CetRule {
            values: Some([0, 1023]),
            contract_info: Some(1),
            pay: vec![],
            ..CetRule::default()
        },
    ];
    let outcome = run(&policy, "disjoint-enum-numeric");
    // The numeric rule's empty pay list matches no CET's outputs.
    assert_eq!(status(&outcome, "policy.cet-coverage"), CheckStatus::Pass);
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);
    assert!(
        !detail(&outcome, "policy.cet-payouts").contains("CET 0 "),
        "the enum CETs follow their rules: {}",
        detail(&outcome, "policy.cet-payouts")
    );

    policy.cets[3].contract_info = Some(0);
    let outcome = run(&policy, "disjoint-enum-numeric");
    assert_eq!(status(&outcome, "policy.cet-coverage"), CheckStatus::Fail);
}

#[test]
fn an_offer_alone_leaves_the_policy_incomplete() {
    let (mut input, options) = fixture("enum-payout-override");
    input.accept = None;
    input.sign = None;
    let outcome = run_input(&policy_file("enum-payout-override.toml"), &input, &options);
    assert_eq!(outcome.status, Status::Incomplete);
    assert_eq!(status(&outcome, "policy.network"), CheckStatus::Pass);
    assert_eq!(status(&outcome, "policy.offerer"), CheckStatus::Pass);
    for id in [
        "policy.accepter",
        "policy.refund-payout",
        "policy.cet-payouts",
        "policy.cet-coverage",
    ] {
        assert_eq!(status(&outcome, id), CheckStatus::Skip, "{id}");
    }
}

#[test]
fn an_offer_that_does_not_decode_skips_everything() {
    let input = Input {
        offer: vec![0xa7, 0x1a, 0, 0],
        accept: None,
        sign: None,
    };
    let outcome = run_input(
        &policy_file("enum-payout-override.toml"),
        &input,
        &Options::default(),
    );
    assert_eq!(outcome.status, Status::Incomplete);
    assert!(
        outcome
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Skip)
    );
}

#[test]
fn the_policy_status_folds_into_the_report() {
    let (input, options) = fixture("enum-dual-funded");
    let verification = verify(&input, &options);
    assert_eq!(verification.status, Status::Pass);
    let report = report_with_policy(&policy_file("enum-payout-override.toml"), &verification);
    assert_eq!(report.status, Status::Fail);
    let json = serde_json::to_value(&report).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(json["policy"]["status"], "fail");
    assert_eq!(json["policy"]["name"], "enum-payout-override");
    assert!(
        dlc_verify_core::render_text(&report).contains("policy fail"),
        "the result line names the policy"
    );
}

#[test]
fn toml_and_json_read_the_same_policy() {
    let toml = policy_file("enum-payout-override.toml");
    let json = toml
        .to_json()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        Policy::parse(&json).unwrap_or_else(|error| unreachable!("{error}")),
        toml
    );
}

#[test]
fn bad_policies_are_rejected() {
    let cases = [
        ("schema = \"dlc-verify.policy.v2\"", "schema is"),
        ("network = \"regtest\"", "missing field `schema`"),
        (
            "schema = \"dlc-verify.policy.v1\"\nnetwrok = \"regtest\"",
            "unknown field `netwrok`",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\nnetwork = \"liquid\"",
            "network \"liquid\"",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[[cets]]\noutcome = \"up\"\nvalues = [1, 2]\npay = [{ party = \"offerer\" }]",
            "exactly one of outcome and values",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[[cets]]\nvalues = [5, 2]\npay = [{ party = \"offerer\" }]",
            "run backwards",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[[cets]]\noutcome = \"up\"\npay = [{ party = \"offerer\", script = \"0014\" }]",
            "exactly one of party, address and script",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[[cets]]\noutcome = \"up\"\npay = [{ party = \"liquidator\" }]",
            "unknown variant `liquidator`",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[refund]\npay = [{ address = \"bc1qnotanaddress\" }]",
            "is not an address",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[oracle]\npubkeys = [\"abcd\"]",
            "not a 32-byte x-only or 33-byte compressed key",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[offerer]\nfunding_pubkey = \"02\"",
            "is not a public key",
        ),
        (
            "schema = \"dlc-verify.policy.v1\"\n[refund]\npay = []",
            "at least one output",
        ),
        (
            "{\"schema\": \"dlc-verify.policy.v1\", \"cets\": 3}",
            "invalid JSON policy",
        ),
    ];
    for (text, expected) in cases {
        let error = Policy::parse(text)
            .err()
            .unwrap_or_else(|| unreachable!("accepted: {text}"));
        assert!(
            error.0.contains(expected),
            "{text}\n  gave: {error}\n  expected: {expected}"
        );
    }
}
