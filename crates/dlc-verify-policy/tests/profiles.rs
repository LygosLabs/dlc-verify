//! The oracle registry, the Midnight event names and the Lygos profiles.

use std::path::PathBuf;

use dlc_verify_core::{CheckStatus, Input, Options, PolicyOutcome, Status, verify};
use dlc_verify_policy::midnight::{
    MidnightEvent, maturity_label, midnight_event_id, midnight_outcomes, midnight_preimage,
    quarter, sorted_liquidators,
};
use dlc_verify_policy::profiles::{LoanTerms, MidnightTerms, lygos_loan, lygos_midnight};
use dlc_verify_policy::registry::{parse_registry, registry_entry};
use dlc_verify_policy::{Policy, Profile, evaluate, profile_policy, registry};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    let path = repo_root().join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", path.display()))
}

/// A bundle and its `now` (none for the examples, which have no clock).
fn bundle(path: &str) -> (Input, Options) {
    let text = read(path);
    let value: Value =
        serde_json::from_str(&text).unwrap_or_else(|error| unreachable!("parsing {path}: {error}"));
    let input = Input::from_bundle(&text).unwrap_or_else(|error| unreachable!("{path}: {error}"));
    (
        input,
        Options {
            now: value["now"].as_u64(),
        },
    )
}

fn run(policy: &Policy, path: &str) -> PolicyOutcome {
    let (input, options) = bundle(path);
    let verification = verify(&input, &options);
    let report = dlc_verify_core::report(&verification);
    evaluate(policy, &verification, &report)
}

fn status(outcome: &PolicyOutcome, id: &str) -> CheckStatus {
    outcome
        .checks
        .iter()
        .find(|check| check.id == id)
        .map(|check| check.status)
        .unwrap_or_else(|| unreachable!("no {id} check in {outcome:#?}"))
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

const MIDNIGHT: &str = "fixtures/midnight-liquidator.json";
const LOAN: &str = "examples/testnet-loan-118c9fc9.json";
const OLD_LOAN: &str = "examples/loan-matured-7932e4c2.json";

fn midnight_terms() -> MidnightTerms {
    toml::from_str(&read("fixtures/terms/midnight-liquidator.toml"))
        .unwrap_or_else(|error| unreachable!("midnight terms: {error}"))
}

fn loan_terms() -> LoanTerms {
    toml::from_str(&read("fixtures/terms/testnet-loan-118c9fc9.toml"))
        .unwrap_or_else(|error| unreachable!("loan terms: {error}"))
}

fn midnight(terms: &MidnightTerms) -> Policy {
    lygos_midnight(terms)
        .unwrap_or_else(|error| unreachable!("lygos-midnight: {error}"))
        .policy
}

fn loan(terms: &LoanTerms) -> Policy {
    lygos_loan(terms)
        .unwrap_or_else(|error| unreachable!("lygos-loan: {error}"))
        .policy
}

// The registry.

#[test]
fn the_registry_parses_and_names_its_oracles() {
    let entries = registry().unwrap_or_else(|error| unreachable!("{error}"));
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        ["magnolia-mainnet", "magnolia-testnet", "chainlink-testnet4"]
    );
    let testnet =
        registry_entry("magnolia-testnet").unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        testnet.pubkey,
        "dde465c101a1aaa5a88c0d35d21744eb5352c62b7c7665d62d5f20c770ddfd8f"
    );
    assert!(
        registry_entry("nobody")
            .map_err(|error| error.0)
            .is_err_and(|error| error.contains("magnolia-mainnet"))
    );
}

#[test]
fn bad_registry_entries_are_refused() {
    let entry = |extra: &str| {
        format!(
            "[[oracle]]\nname = \"a\"\nprovider = \"p\"\npubkey = \"{}\"\n{extra}",
            "dde465c101a1aaa5a88c0d35d21744eb5352c62b7c7665d62d5f20c770ddfd8f"
        )
    };
    assert!(parse_registry(&entry("")).is_ok());
    assert!(parse_registry(&entry("quarter = \"2027Q1\"")).is_ok());
    assert!(parse_registry(&entry("quarter = \"2027Q5\"")).is_err());
    assert!(parse_registry(&entry("colour = \"red\"")).is_err());
    assert!(parse_registry(&format!("{}\n{}", entry(""), entry(""))).is_err());
    let compressed = entry("").replace("pubkey = \"", "pubkey = \"02");
    assert!(parse_registry(&compressed).is_err());
}

// Midnight event names.

/// The golden vectors the Midnight oracle's Go workflow pins
/// (LygosLabs/chainlink-oracle `packages/workflows-go/dlcmsg/testdata/midnight-vectors.json`).
#[test]
fn midnight_event_ids_match_the_oracles_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(&read(
        "crates/dlc-verify-policy/tests/data/midnight-vectors.json",
    ))
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(vectors.len(), 5);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or_default();
        let text = |key: &str| vector[key].as_str().unwrap_or_default().to_owned();
        let number = |key: &str| vector[key].as_u64().unwrap_or_default();
        let event = MidnightEvent {
            chain_id: number("chainId"),
            originator: text("originator"),
            market_id: text("marketId"),
            request_id: text("requestId"),
            controller: text("controller"),
            mint_deadline: number("mintDeadline"),
            announced_at: number("announcedAt"),
        };
        let liquidators = sorted_liquidators(
            vector["liquidators"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        )
        .unwrap_or_else(|error| unreachable!("{name}: {error}"));
        let preimage = midnight_preimage(&event, &liquidators)
            .unwrap_or_else(|error| unreachable!("{name}: {error}"));
        assert_eq!(preimage, text("expectedPreimage"), "{name}");
        let event_id = midnight_event_id(&event, &liquidators, number("maturity"))
            .unwrap_or_else(|error| unreachable!("{name}: {error}"));
        assert_eq!(event_id, text("expectedEventId"), "{name}");
        let first_mint = !vector["successor"].as_bool().unwrap_or(false);
        let expected: Vec<String> = vector["expectedOutcomes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|outcome| outcome.as_str().map(str::to_owned))
            .collect();
        assert_eq!(
            midnight_outcomes(first_mint, &liquidators),
            expected,
            "{name}"
        );
    }
}

/// The digest dlc-verify-tvc's mint attester pins.
#[test]
fn midnight_digest_matches_the_mint_attester() {
    let event = MidnightEvent {
        chain_id: 8453,
        originator: format!("0x{}", "56".repeat(20)),
        market_id: "ab".repeat(32),
        request_id: "0f8b7c2e-4d1a-4e6b-9c3f-2a5d8e7b1c40".to_owned(),
        controller: format!("0x{}", "c0".repeat(20)),
        mint_deadline: 1_790_000_000,
        announced_at: 1_789_000_000,
    };
    let liquidators = sorted_liquidators([
        format!("0x{}", "cc".repeat(20)).as_str(),
        format!("0x{}", "aa".repeat(20)).as_str(),
    ])
    .unwrap_or_else(|error| unreachable!("{error}"));
    let preimage =
        midnight_preimage(&event, &liquidators).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        hex::encode(Sha256::digest(preimage.as_bytes())),
        "bf923f92df8d8c9180e8ce5ced2a70b74ebc35ae934f01f7537b0e1755485d38"
    );
}

#[test]
fn maturity_labels_and_quarters_are_utc() {
    for (maturity, label, expected_quarter) in [
        (1_798_210_800, "25DEC26", "2026Q4"),
        (1_806_073_200, "26MAR27", "2027Q1"),
        (1_813_935_600, "25JUN27", "2027Q2"),
        (1_821_798_000, "24SEP27", "2027Q3"),
        (1_798_156_800, "25DEC26", "2026Q4"),
        (1_798_156_799, "24DEC26", "2026Q4"),
        (1_798_761_599, "31DEC26", "2026Q4"),
        (1_798_761_600, "01JAN27", "2027Q1"),
    ] {
        assert_eq!(maturity_label(maturity), label, "{maturity}");
        assert_eq!(quarter(maturity), expected_quarter, "{maturity}");
    }
}

#[test]
fn bad_midnight_terms_are_refused() {
    let event = MidnightEvent {
        request_id: "0F8B7C2E-4D1A-4E6B-9C3F-2A5D8E7B1C40".to_owned(),
        ..midnight_terms().event.unwrap_or_default()
    };
    let liquidators = vec![format!("0x{}", "11".repeat(20))];
    assert!(midnight_preimage(&event, &liquidators).is_err());
    assert!(midnight_preimage(&midnight_terms().event.unwrap_or_default(), &[]).is_err());
    let twice = format!("0x{}", "11".repeat(20));
    assert!(
        sorted_liquidators([
            twice.as_str(),
            twice.to_uppercase().replace("0X", "0x").as_str()
        ])
        .is_err()
    );
    assert!(sorted_liquidators(["0x1234"]).is_err());
}

// lygos-loan.

#[test]
fn lygos_loan_passes_a_testnet_loan() {
    assert_all_pass(&run(&loan(&loan_terms()), LOAN));
    // With no terms the profile still checks the loan's shape.
    assert_all_pass(&run(&loan(&LoanTerms::default()), LOAN));
}

#[test]
fn lygos_loan_catches_the_wrong_terms() {
    let outcome = run(
        &loan(&LoanTerms {
            collateral_sat: Some(9_000),
            ..loan_terms()
        }),
        LOAN,
    );
    assert_eq!(status(&outcome, "policy.collateral"), CheckStatus::Fail);
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);

    let outcome = run(
        &loan(&LoanTerms {
            oracle: Some("magnolia-mainnet".to_owned()),
            ..loan_terms()
        }),
        LOAN,
    );
    assert_eq!(status(&outcome, "policy.oracle-pubkeys"), CheckStatus::Fail);

    let outcome = run(
        &loan(&LoanTerms {
            refund_to_accepter: true,
            ..loan_terms()
        }),
        LOAN,
    );
    assert_eq!(status(&outcome, "policy.contract-flags"), CheckStatus::Fail);
    assert_eq!(status(&outcome, "policy.refund-payout"), CheckStatus::Fail);
}

#[test]
fn loans_before_rollovers_need_rollover_false() {
    let outcome = run(&loan(&LoanTerms::default()), OLD_LOAN);
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);
    let outcome = run(
        &loan(&LoanTerms {
            rollover: false,
            ..LoanTerms::default()
        }),
        OLD_LOAN,
    );
    // The old example has no sign message, so the policy is complete but the report is not.
    for check in &outcome.checks {
        assert_eq!(
            check.status,
            CheckStatus::Pass,
            "{}: {}",
            check.id,
            check.detail
        );
    }
}

#[test]
fn lygos_loan_refuses_a_midnight_loan() {
    let outcome = run(&loan(&LoanTerms::default()), MIDNIGHT);
    assert_eq!(status(&outcome, "policy.contract-flags"), CheckStatus::Fail);
    assert_eq!(status(&outcome, "policy.tlvs"), CheckStatus::Fail);
    assert_eq!(status(&outcome, "policy.oracle-pubkeys"), CheckStatus::Fail);
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);
    assert_eq!(outcome.status, Status::Fail);
}

// lygos-midnight.

#[test]
fn lygos_midnight_passes_the_midnight_vector() {
    let built = lygos_midnight(&midnight_terms()).unwrap_or_else(|error| unreachable!("{error}"));
    assert!(built.notes.is_empty(), "{:?}", built.notes);
    assert_all_pass(&run(&built.policy, MIDNIGHT));
}

#[test]
fn a_liquidation_paying_someone_else_fails() {
    let mut terms = midnight_terms();
    if let Some(liquidator) = terms.liquidators.first_mut() {
        // The lender's script, not the liquidator's.
        liquidator.payout = "bcrt1q3483k0uzgljf4e2mec5zhvc0fym0tfv685xaqg".to_owned();
    }
    let outcome = run(&midnight(&terms), MIDNIGHT);
    assert_eq!(status(&outcome, "policy.cet-payouts"), CheckStatus::Fail);
}

#[test]
fn a_liquidator_the_terms_do_not_name_fails_coverage() {
    let mut terms = midnight_terms();
    terms.liquidators.pop();
    terms.event = None;
    let outcome = run(&midnight(&terms), MIDNIGHT);
    assert_eq!(status(&outcome, "policy.cet-coverage"), CheckStatus::Fail);
}

#[test]
fn a_successor_loan_has_no_not_minted_outcome() {
    let terms = MidnightTerms {
        first_mint: false,
        event: None,
        ..midnight_terms()
    };
    let outcome = run(&midnight(&terms), MIDNIGHT);
    assert_eq!(status(&outcome, "policy.cet-coverage"), CheckStatus::Fail);
}

#[test]
fn the_event_id_binds_the_loan_terms() {
    let mut terms = midnight_terms();
    if let Some(event) = terms.event.as_mut() {
        event.request_id = "00000000-0000-4000-8000-000000000000".to_owned();
    }
    let outcome = run(&midnight(&terms), MIDNIGHT);
    assert_eq!(status(&outcome, "policy.oracle-events"), CheckStatus::Fail);
}

#[test]
fn a_short_refund_delay_fails() {
    let mut policy = midnight(&midnight_terms());
    if let Some(locktimes) = policy.locktimes.as_mut() {
        locktimes.refund_delay_min = Some(15 * 86_400);
    }
    let outcome = run(&policy, MIDNIGHT);
    assert_eq!(
        status(&outcome, "policy.refund-locktime"),
        CheckStatus::Fail
    );
}

#[test]
fn lygos_midnight_says_what_it_cannot_check() {
    let built =
        lygos_midnight(&MidnightTerms::default()).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(built.notes.len(), 2, "{:?}", built.notes);
    let oracle = built.policy.oracle.unwrap_or_default();
    assert!(oracle.pubkeys.is_none());
    assert!(!built.policy.require_every_cet);

    // A maturity whose quarter has no registry key.
    let built = lygos_midnight(&MidnightTerms {
        maturity: Some(1_806_073_200),
        ..MidnightTerms::default()
    })
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(
        built.notes.iter().any(|note| note.contains("2027Q1")),
        "{:?}",
        built.notes
    );
}

// Terms files.

#[test]
fn terms_files_parse_as_toml_or_json() {
    let toml = read("fixtures/terms/midnight-liquidator.toml");
    let from_toml = profile_policy(Profile::LygosMidnight, Some(&toml))
        .unwrap_or_else(|error| unreachable!("{error}"));
    let json =
        serde_json::to_string(&midnight_terms()).unwrap_or_else(|error| unreachable!("{error}"));
    let from_json = profile_policy(Profile::LygosMidnight, Some(&json))
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(from_toml, from_json);
    assert!(profile_policy(Profile::LygosLoan, None).is_ok());
}

#[test]
fn bad_terms_are_refused() {
    let error = |profile, text: &str| {
        profile_policy(profile, Some(text))
            .map(|_| ())
            .map_err(|error| error.0)
            .err()
            .unwrap_or_else(|| unreachable!("{text:?} was accepted"))
    };
    assert!(error(Profile::LygosLoan, "colateral_sat = 1").contains("colateral_sat"));
    assert!(
        error(
            Profile::LygosLoan,
            "oracle = \"magnolia-mainnet\"\noracle_pubkeys = []"
        )
        .contains("not both")
    );
    assert!(error(Profile::LygosLoan, "oracle = \"delphi\"").contains("delphi"));
    assert!(error(Profile::LygosLoan, "network = \"moon\"").contains("moon"));
    assert!(
        error(
            Profile::LygosMidnight,
            "[[liquidators]]\naddress = \"0x11\"\npayout = \"00\""
        )
        .contains("EVM address")
    );
    let event_without_maturity =
        read("fixtures/terms/midnight-liquidator.toml").replace("maturity = 1767225600", "");
    assert!(error(Profile::LygosMidnight, &event_without_maturity).contains("maturity"));
}

#[test]
fn profiles_are_named() {
    for profile in Profile::ALL {
        assert_eq!(Profile::from_name(profile.name()), Some(profile));
        assert!(!profile.about().is_empty());
    }
    assert_eq!(Profile::from_name("lygos"), None);
}
