//! Keyless settlement of every fixture: each attested CET and each refund comes out fully
//! signed, and libbitcoinconsensus accepts it as a spend of the funding output.

use std::path::{Path, PathBuf};

use bitcoin::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize};
use ddk_messages::TlvRecord;
use ddk_messages::oracle_msgs::OracleAttestation;
use dlc_verify_core::report::Payee;
use dlc_verify_core::{CetOutcome, Input, Options, Status, Verification, verify};
use dlc_verify_settle::{
    Broadcast, Kind, SettleError, Settlement, attestations_from_bundle, parse_attestation,
    parse_attestations, refund, render_text, settle,
};
use serde_json::Value;

struct Fixture {
    name: String,
    text: String,
    value: Value,
    now: Option<u64>,
}

impl Fixture {
    fn input(&self) -> Input {
        Input::from_bundle(&self.text)
            .unwrap_or_else(|error| unreachable!("{}: {error}", self.name))
    }

    fn verification(&self) -> Verification {
        verify(&self.input(), &Options { now: self.now })
    }

    fn attestations(&self) -> Vec<OracleAttestation> {
        attestations_from_bundle(&self.text)
            .unwrap_or_else(|error| unreachable!("{}: {error}", self.name))
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn fixture(name: &str) -> Fixture {
    read(&fixtures_dir().join(format!("{name}.json")))
}

fn read(path: &Path) -> Fixture {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", path.display()));
    let value: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| unreachable!("parsing {}: {error}", path.display()));
    Fixture {
        name: path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default(),
        now: value["now"].as_u64(),
        text,
        value,
    }
}

fn all_fixtures() -> Vec<Fixture> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(fixtures_dir())
        .unwrap_or_else(|error| unreachable!("reading fixtures: {error}"))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(paths.len() >= 9, "expected the generated fixtures");
    paths.iter().map(|path| read(path)).collect()
}

/// Checks `settlement`'s transaction with libbitcoinconsensus as a spend of the funding output,
/// and that it pays what the settlement says.
fn assert_spends_funding(name: &str, verification: &Verification, settlement: &Settlement) {
    let contract = verification
        .contract
        .as_ref()
        .unwrap_or_else(|| unreachable!("{name}: no contract"));
    let bytes = hex::decode(&settlement.transaction)
        .unwrap_or_else(|error| unreachable!("{name}: {error}"));
    let transaction: Transaction =
        deserialize(&bytes).unwrap_or_else(|error| unreachable!("{name}: {error}"));
    assert_eq!(
        transaction.compute_txid().to_string(),
        settlement.txid,
        "{name}"
    );
    assert_eq!(transaction.input.len(), 1, "{name}");
    let input = &transaction.input[0];
    assert_eq!(
        input.previous_output.txid,
        contract.transactions.fund.compute_txid(),
        "{name}"
    );
    assert_eq!(
        input.previous_output.vout as usize, contract.fund_output_index,
        "{name}"
    );
    assert_eq!(input.witness.len(), 4, "{name}: 2-of-2 witness");
    let funding_output = &contract.transactions.fund.output[contract.fund_output_index];
    bitcoinconsensus::verify(
        funding_output.script_pubkey.as_bytes(),
        funding_output.value.to_sat(),
        &serialize(&transaction),
        None,
        0,
    )
    .unwrap_or_else(|error| unreachable!("{name}: consensus rejects the spend: {error:?}"));

    let paid: u64 = transaction
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .sum();
    assert_eq!(
        paid + settlement.fee_sat,
        funding_output.value.to_sat(),
        "{name}"
    );
    assert_eq!(settlement.outputs.len(), transaction.output.len(), "{name}");
    for (output, expected) in transaction.output.iter().zip(&settlement.outputs) {
        assert_eq!(output.value.to_sat(), expected.value_sat, "{name}");
        assert_eq!(
            hex::encode(output.script_pubkey.as_bytes()),
            expected.script.hex,
            "{name}"
        );
    }
    assert_eq!(settlement.vsize, transaction.vsize() as u64, "{name}");
    assert_eq!(
        settlement.spends.value_sat,
        funding_output.value.to_sat(),
        "{name}"
    );
}

/// The numeric value an attestation's binary digits spell, most significant first.
fn digits_value(outcomes: &[String]) -> u64 {
    outcomes
        .iter()
        .fold(0, |value, digit| value * 2 + u64::from(digit == "1"))
}

#[test]
fn every_attested_fixture_settles_to_the_attested_outcome() {
    let mut settled = 0;
    for fixture in all_fixtures() {
        let attestations = fixture.attestations();
        if attestations.is_empty() {
            continue;
        }
        let name = &fixture.name;
        let verification = fixture.verification();
        assert_eq!(verification.status, Status::Pass, "{name}");
        let settlement = settle(&verification, &attestations, fixture.now)
            .unwrap_or_else(|error| unreachable!("{name}: {error}"));
        assert_eq!(settlement.kind, Kind::Cet, "{name}");
        assert_eq!(settlement.verification, Status::Pass, "{name}");
        assert_spends_funding(name, &verification, &settlement);

        let cet = settlement
            .cet
            .as_ref()
            .unwrap_or_else(|| unreachable!("{name}: no CET"));
        let outcomes = &attestations[0].outcomes;
        match &cet.settles {
            CetOutcome::Enum { outcome } => {
                assert_eq!(std::slice::from_ref(outcome), outcomes.as_slice(), "{name}");
            }
            CetOutcome::Numeric { first, last } => {
                let value = digits_value(outcomes);
                assert!(
                    (*first..=*last).contains(&value),
                    "{name}: {value} not in {first}..{last}"
                );
            }
            CetOutcome::Unknown => unreachable!("{name}: CET outcome unknown"),
        }
        assert!(!cet.attestations.is_empty(), "{name}");
        settled += 1;
    }
    assert!(settled >= 7, "expected every attested fixture to settle");
}

#[test]
fn the_cet_pays_what_the_report_says() {
    let fixture = fixture("enum-dual-funded");
    let verification = fixture.verification();
    let settlement = settle(&verification, &fixture.attestations(), fixture.now)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let cet = settlement
        .cet
        .as_ref()
        .unwrap_or_else(|| unreachable!("no CET"));
    assert_eq!(cet.outcome, "down");
    assert_eq!(cet.contract_info, 0);
    assert_eq!(settlement.outputs.len(), 1);
    assert_eq!(settlement.outputs[0].payee, Payee::Accepter);
    assert_eq!(settlement.outputs[0].value_sat, 100_000);
    assert_eq!(
        settlement.broadcast,
        Broadcast::AfterTime {
            unix: 1_767_225_600,
            utc: "2026-01-01T00:00:00Z".to_owned(),
            reached: Some(false),
        }
    );
    let later = settle(&verification, &fixture.attestations(), Some(1_767_229_200))
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        later.broadcast,
        Broadcast::AfterTime {
            reached: Some(true),
            ..
        }
    ));
    assert_eq!(later.transaction, settlement.transaction);
}

#[test]
fn a_midnight_liquidation_pays_the_liquidator() {
    let fixture = fixture("midnight-liquidator");
    let verification = fixture.verification();
    let settlement = settle(&verification, &fixture.attestations(), fixture.now)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let cet = settlement
        .cet
        .as_ref()
        .unwrap_or_else(|| unreachable!("no CET"));
    assert_eq!(
        cet.outcome,
        "liquidated-by-0x1111111111111111111111111111111111111111"
    );
    assert_eq!(settlement.outputs.len(), 1);
    let output = &settlement.outputs[0];
    assert_eq!(output.payee, Payee::ThirdParty);
    assert_eq!(output.value_sat, 100_000);
    assert_eq!(
        output.script.address.as_deref(),
        Some("bcrt1q3qr7lswmh25nplahuj3m474ujs6vjvpu6976ja")
    );
    assert!(output.record.is_some());
    // Midnight CETs have no locktime.
    assert_eq!(settlement.broadcast, Broadcast::Now);
}

#[test]
fn a_disjoint_contract_settles_in_the_attested_contract_info() {
    let fixture = fixture("disjoint-enum-numeric");
    let verification = fixture.verification();
    let settlement = settle(&verification, &fixture.attestations(), fixture.now)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let cet = settlement
        .cet
        .as_ref()
        .unwrap_or_else(|| unreachable!("no CET"));
    assert_eq!(cet.contract_info, 1);
    let contract = verification
        .contract
        .as_ref()
        .unwrap_or_else(|| unreachable!("no contract"));
    assert!(contract.cet_ranges[1].contains(&cet.index));
}

#[test]
fn a_threshold_contract_needs_enough_oracles() {
    let fixture = fixture("enum-multi-oracle");
    let verification = fixture.verification();
    let attestations = fixture.attestations();
    assert_eq!(attestations.len(), 2);

    let settlement = settle(&verification, &attestations, fixture.now)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        settlement.cet.as_ref().map(|cet| cet.outcome.as_str()),
        Some("flat")
    );
    assert_eq!(
        settlement.cet.as_ref().map(|cet| cet.attestations.len()),
        Some(2)
    );

    // One attestation of a 2-of-3 contract decrypts nothing.
    let error = settle(&verification, &attestations[..1], fixture.now)
        .err()
        .unwrap_or_else(|| unreachable!("one of two oracles settled"));
    assert!(matches!(error, SettleError::NoCet(_)), "{error:?}");

    // The same attestation twice is still one oracle.
    let twice = [attestations[0].clone(), attestations[0].clone()];
    let error = settle(&verification, &twice, fixture.now)
        .err()
        .unwrap_or_else(|| unreachable!("a repeated attestation settled"));
    assert!(matches!(error, SettleError::NoCet(_)), "{error:?}");
}

#[test]
fn an_attestation_for_another_contract_is_refused() {
    let fixture = fixture("enum-dual-funded");
    let other = read(&fixtures_dir().join("enum-single-funded.json"));
    let error = settle(&fixture.verification(), &other.attestations(), fixture.now)
        .err()
        .unwrap_or_else(|| unreachable!("a foreign attestation settled"));
    assert!(matches!(error, SettleError::Attestation(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("no attestation is for this contract")
    );
}

#[test]
fn a_forged_attestation_is_refused() {
    let fixture = fixture("enum-dual-funded");
    let mut forged = fixture.attestations();
    // Claim another outcome with the signature over "down".
    forged[0].outcomes = vec!["up".to_owned()];
    let error = settle(&fixture.verification(), &forged, fixture.now)
        .err()
        .unwrap_or_else(|| unreachable!("a forged attestation settled"));
    assert!(matches!(error, SettleError::Attestation(_)), "{error:?}");
    assert!(error.to_string().contains("does not verify"), "{error}");

    // A signature with another nonce than the announced one.
    let mut renonced = fixture.attestations();
    let other = read(&fixtures_dir().join("enum-single-funded.json")).attestations();
    renonced[0].signatures = other[0].signatures.clone();
    let error = settle(&fixture.verification(), &renonced, fixture.now)
        .err()
        .unwrap_or_else(|| unreachable!("a foreign signature settled"));
    assert!(matches!(error, SettleError::Attestation(_)), "{error:?}");
}

#[test]
fn settling_needs_every_message_and_an_attestation() {
    let fixture = fixture("enum-dual-funded");
    let mut input = fixture.input();
    input.sign = None;
    let unsigned = verify(&input, &Options { now: fixture.now });
    for result in [
        settle(&unsigned, &fixture.attestations(), fixture.now),
        refund(&unsigned, fixture.now),
    ] {
        let error = result
            .err()
            .unwrap_or_else(|| unreachable!("settled without the sign message"));
        assert!(matches!(error, SettleError::Incomplete(_)), "{error:?}");
        assert!(error.to_string().contains("no sign message"), "{error}");
    }
    let error = settle(&fixture.verification(), &[], fixture.now)
        .err()
        .unwrap_or_else(|| unreachable!("settled without an attestation"));
    assert!(matches!(error, SettleError::Attestation(_)), "{error:?}");
}

#[test]
fn a_wrong_signature_is_refused() {
    let fixture = fixture("enum-dual-funded");
    let mut verification = fixture.verification();
    let messages = verification
        .messages
        .as_mut()
        .unwrap_or_else(|| unreachable!("no messages"));
    let accepter_signature = messages
        .accept
        .as_ref()
        .map(|accept| accept.refund_signature)
        .unwrap_or_else(|| unreachable!("no accept"));
    // A valid signature, but by the accepter's key where the offerer's belongs.
    if let Some(sign) = messages.sign.as_mut() {
        sign.refund_signature = accepter_signature;
    }
    let error = refund(&verification, fixture.now)
        .err()
        .unwrap_or_else(|| unreachable!("a wrong refund signature settled"));
    assert!(matches!(error, SettleError::Signature(_)), "{error:?}");
}

#[test]
fn every_fixture_refunds() {
    for fixture in all_fixtures() {
        let name = &fixture.name;
        let verification = fixture.verification();
        let settlement = refund(&verification, fixture.now)
            .unwrap_or_else(|error| unreachable!("{name}: {error}"));
        assert_eq!(settlement.kind, Kind::Refund, "{name}");
        assert!(settlement.cet.is_none(), "{name}");
        assert_spends_funding(name, &verification, &settlement);
        let messages = verification
            .messages
            .as_ref()
            .unwrap_or_else(|| unreachable!("{name}: no messages"));
        assert_eq!(
            settlement.locktime.value, messages.offer.refund_locktime,
            "{name}"
        );
        assert!(
            matches!(
                settlement.broadcast,
                Broadcast::AfterTime {
                    reached: Some(false),
                    ..
                }
            ),
            "{name}: the refund is not yet valid at the fixture's time"
        );
    }
}

#[test]
fn the_refund_pays_the_accepter_with_flag_0x01() {
    let fixture = fixture("enum-refund-to-accepter");
    let settlement = refund(&fixture.verification(), fixture.now)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(settlement.outputs.len(), 1);
    assert_eq!(settlement.outputs[0].payee, Payee::Accepter);
}

#[test]
fn attestations_parse_in_every_shape() {
    let fixture = fixture("enum-dual-funded");
    let hex = fixture.value["attestations"][0]["hex"]
        .as_str()
        .unwrap_or_else(|| unreachable!("no attestation hex"))
        .to_owned();
    let expected = parse_attestation(&hex).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(expected.to_tlv_hex(), hex);
    assert_eq!(expected.outcomes, vec!["down".to_owned()]);

    let shapes = [
        hex.clone(),
        format!("0x{hex}\n"),
        format!("  {}  {}  ", &hex[..20], &hex[20..]),
        format!("{{\"hex\":\"{hex}\"}}"),
        format!("[\"{hex}\"]"),
        format!("[{{\"hex\":\"{hex}\",\"event_id\":\"ignored\"}}]"),
        format!("{{\"attestations\":[\"{hex}\"]}}"),
        format!("{{\"data\":{{\"attestations\":[{{\"hex\":\"{hex}\"}}]}}}}"),
        fixture.text.clone(),
    ];
    for shape in &shapes {
        let parsed =
            parse_attestations(shape).unwrap_or_else(|error| unreachable!("{shape}: {error}"));
        assert_eq!(parsed, vec![expected.clone()], "{shape}");
    }
    assert_eq!(
        parse_attestations("{\"offer\":\"00\"}").unwrap_or_else(|error| unreachable!("{error}")),
        Vec::new()
    );

    let offer_hex = fixture.value["offer"]
        .as_str()
        .unwrap_or_else(|| unreachable!("no offer"));
    for bad in [
        "",
        "zz",
        "fdd868",
        offer_hex,
        &format!("{hex}00"),
        "{\"hex\":5}",
        "{\"attestations\":\"x\"}",
        "[1]",
        "{",
    ] {
        let error = parse_attestations(bad)
            .err()
            .unwrap_or_else(|| unreachable!("{bad:?} parsed"));
        assert!(
            matches!(error, SettleError::Attestation(_)),
            "{bad:?}: {error:?}"
        );
    }
}

#[test]
fn text_shows_the_outcome_payees_and_transaction() {
    let fixture = fixture("midnight-liquidator");
    let settlement = settle(
        &fixture.verification(),
        &fixture.attestations(),
        fixture.now,
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let text = render_text(&settlement);
    assert!(text.starts_with(
        "Signed CET for outcome liquidated-by-0x1111111111111111111111111111111111111111"
    ));
    assert!(
        text.contains("100,000 sat to third-party bcrt1q3qr7lswmh25nplahuj3m474ujs6vjvpu6976ja")
    );
    assert!(text.contains("once the funding transaction confirms"));
    assert!(text.ends_with(&format!("{}\n", settlement.transaction)));
    assert!(!text.contains("Warning"));

    let json = serde_json::to_value(&settlement).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(json["schema"], "dlc-verify/settlement/v1");
    assert_eq!(json["kind"], "cet");
    assert_eq!(json["broadcast"]["when"], "now");
    assert_eq!(json["outputs"][0]["payee"], "third-party");

    let refund_text = render_text(
        &refund(&fixture.verification(), fixture.now)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    assert!(refund_text.starts_with("Signed refund"));
    assert!(refund_text.contains("median time passes 2026-01-15T00:00:00Z (not yet)"));
}
