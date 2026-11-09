//! The report's payee labels, its snapshots, and a cross-check against DDK's own verifier.
//!
//! Run with `UPDATE_SNAPSHOTS=1` to rewrite `fixtures/reports/` after an intended change.

use std::path::PathBuf;

use dlc_verify_core::report::{CetPayouts, Payee, Report, TEXT_CET_LIMIT};
use dlc_verify_core::{Input, Messages, Options, Status, decode, render_text, report, verify};
use lightning::util::ser::Writeable;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture_names() -> Vec<String> {
    let directory = repo_root().join("fixtures");
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", directory.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .filter_map(|path| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    names
}

fn fixture(name: &str) -> (Input, Options) {
    let path = repo_root().join("fixtures").join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", path.display()));
    let value: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| unreachable!("parsing {}: {error}", path.display()));
    let input = Input::from_bundle(&text)
        .unwrap_or_else(|error| unreachable!("{name}: not a bundle: {error}"));
    let options = Options {
        now: value["now"].as_u64(),
    };
    (input, options)
}

fn fixture_report(name: &str) -> Report {
    let (input, options) = fixture(name);
    report(&verify(&input, &options))
}

fn messages(input: &Input) -> Messages {
    decode(input).unwrap_or_else(|error| unreachable!("decode: {error}"))
}

fn encode(messages: &Messages) -> Input {
    Input {
        offer: messages.offer.encode(),
        accept: messages.accept.as_ref().map(Writeable::encode),
        sign: messages.sign.as_ref().map(Writeable::encode),
    }
}

fn cet<'a>(report: &'a Report, outcome: &str) -> &'a CetPayouts {
    report
        .payouts
        .as_ref()
        .and_then(|payouts| payouts.cets.iter().find(|cet| cet.outcome == outcome))
        .unwrap_or_else(|| unreachable!("no CET for {outcome}"))
}

/// Compares `actual` with the snapshot at `path`, or rewrites it under `UPDATE_SNAPSHOTS=1`.
fn snapshot(path: &PathBuf, actual: &str) {
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| unreachable!("creating {}: {error}", parent.display()));
        }
        std::fs::write(path, actual)
            .unwrap_or_else(|error| unreachable!("writing {}: {error}", path.display()));
        return;
    }
    let expected = std::fs::read_to_string(path).unwrap_or_else(|error| {
        unreachable!(
            "reading {}: {error}; run with UPDATE_SNAPSHOTS=1 to create it",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "{} is out of date; run with UPDATE_SNAPSHOTS=1 to update it.\n--- actual ---\n{actual}",
        path.display()
    );
}

#[test]
fn reports_match_their_snapshots() {
    let directory = repo_root().join("fixtures").join("reports");
    for name in fixture_names() {
        let report = fixture_report(&name);
        let json = serde_json::to_string_pretty(&report)
            .unwrap_or_else(|error| unreachable!("{name}: {error}"));
        snapshot(
            &directory.join(format!("{name}.json")),
            &format!("{json}\n"),
        );
        snapshot(
            &directory.join(format!("{name}.txt")),
            &render_text(&report),
        );
    }
}

#[test]
fn every_output_has_a_known_payee() {
    for name in fixture_names() {
        let report = fixture_report(&name);
        let payouts = report
            .payouts
            .as_ref()
            .unwrap_or_else(|| unreachable!("{name}: no payouts"));
        let total = report
            .contract
            .as_ref()
            .map_or(0, |contract| contract.total_collateral_sat);
        for (label, outputs) in std::iter::once(("refund".to_owned(), &payouts.refund.outputs))
            .chain(
                payouts
                    .cets
                    .iter()
                    .map(|cet| (format!("CET {}", cet.outcome), &cet.outputs)),
            )
        {
            assert!(!outputs.is_empty(), "{name}: {label} has no outputs");
            for output in outputs {
                assert_ne!(output.payee, Payee::Unknown, "{name}: {label}");
                assert_ne!(output.payee, Payee::Shared, "{name}: {label}");
            }
            let paid: u64 = outputs.iter().map(|output| output.value_sat).sum();
            assert!(paid <= total, "{name}: {label} pays {paid} of {total}");
        }
    }
}

#[test]
fn an_enum_override_pays_the_third_party() {
    let report = fixture_report("enum-payout-override");
    let down = cet(&report, "down");
    assert_eq!(down.outputs.len(), 1);
    let output = &down.outputs[0];
    assert_eq!(output.payee, Payee::ThirdParty);
    assert_eq!(output.value_sat, 100_000);
    assert_eq!(
        output.record.as_deref(),
        Some("payout-script-overrides (65005): outcome \"down\"")
    );
    let up = cet(&report, "up");
    assert!(
        up.outputs
            .iter()
            .all(|output| output.payee == Payee::Offerer)
    );
    let overrides = &report
        .contract
        .as_ref()
        .unwrap_or_else(|| unreachable!("no contract"))
        .payout_overrides;
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].covers, "outcome \"down\"");
    assert_eq!(overrides[0].script.hex, output.script.hex);
}

#[test]
fn a_numeric_override_pays_the_third_party_for_its_range_only() {
    let report = fixture_report("numeric-payout-override");
    let payouts = report
        .payouts
        .as_ref()
        .unwrap_or_else(|| unreachable!("no payouts"));
    let third_party: Vec<&str> = payouts
        .cets
        .iter()
        .filter(|cet| {
            cet.outputs
                .iter()
                .any(|output| output.payee == Payee::ThirdParty)
        })
        .map(|cet| cet.outcome.as_str())
        .collect();
    assert_eq!(third_party, ["0..319"]);
    let last = payouts
        .cets
        .last()
        .unwrap_or_else(|| unreachable!("no CETs"));
    assert_eq!(last.outcome, "680..1023");
}

#[test]
fn the_refund_to_accepter_flag_pays_the_whole_refund_to_the_accepter() {
    let report = fixture_report("enum-refund-to-accepter");
    let refund = &report
        .payouts
        .as_ref()
        .unwrap_or_else(|| unreachable!("no payouts"))
        .refund;
    assert_eq!(refund.outputs.len(), 1);
    assert_eq!(refund.outputs[0].payee, Payee::Accepter);
    assert_eq!(refund.outputs[0].value_sat, 100_000);

    let report = fixture_report("enum-dual-funded");
    let refund = &report
        .payouts
        .as_ref()
        .unwrap_or_else(|| unreachable!("no payouts"))
        .refund;
    let payees: Vec<Payee> = refund.outputs.iter().map(|output| output.payee).collect();
    assert!(payees.contains(&Payee::Offerer) && payees.contains(&Payee::Accepter));
}

#[test]
fn disjoint_contracts_label_cets_by_contract_info() {
    let report = fixture_report("disjoint-enum-numeric");
    let payouts = report
        .payouts
        .as_ref()
        .unwrap_or_else(|| unreachable!("no payouts"));
    let infos: Vec<usize> = payouts.cets.iter().map(|cet| cet.contract_info).collect();
    assert_eq!(infos.first(), Some(&0));
    assert_eq!(infos.last(), Some(&1));
    let indexes: Vec<usize> = payouts.cets.iter().map(|cet| cet.index).collect();
    assert_eq!(indexes, (0..payouts.cets.len()).collect::<Vec<_>>());
    assert!(render_text(&report).contains("[1] 680..1023"));
}

#[test]
fn an_offer_alone_has_terms_but_no_payouts() {
    let (input, options) = fixture("enum-dual-funded");
    let input = Input {
        accept: None,
        sign: None,
        ..input
    };
    let report = report(&verify(&input, &options));
    assert_eq!(report.status, Status::Incomplete);
    assert!(report.payouts.is_none());
    let contract = report
        .contract
        .as_ref()
        .unwrap_or_else(|| unreachable!("the offer decodes"));
    assert!(contract.accepter.is_none());
    assert!(contract.contract_id.is_none());
    assert_eq!(contract.total_collateral_sat, 100_000);
}

#[test]
fn a_bad_offer_has_no_contract() {
    let report = report(&verify(
        &Input {
            offer: vec![0xa7, 0x1a, 0x00],
            accept: None,
            sign: None,
        },
        &Options::default(),
    ));
    assert_eq!(report.status, Status::Fail);
    assert!(report.contract.is_none());
    assert!(report.payouts.is_none());
    assert!(render_text(&report).starts_with("dlc-verify "));
}

#[test]
fn long_cet_lists_are_elided_in_text() {
    let mut report = fixture_report("numeric-dual-funded");
    let Some(payouts) = report.payouts.as_mut() else {
        unreachable!("no payouts")
    };
    let template = payouts.cets[0].clone();
    payouts.cets = (0..TEXT_CET_LIMIT + 10)
        .map(|index| CetPayouts {
            index,
            outcome: format!("outcome-{index}"),
            ..template.clone()
        })
        .collect();
    let text = render_text(&report);
    assert!(text.contains("outcome-0 "));
    assert!(text.contains("outcome-19 "));
    assert!(!text.contains("outcome-20 "));
    assert!(text.contains("... 10 more (the JSON report lists every CET)"));
    assert!(text.contains(&format!("outcome-{} ", TEXT_CET_LIMIT + 9)));
}

#[test]
fn the_json_report_has_a_schema_and_counts() {
    let report = fixture_report("enum-single-funded");
    let value = serde_json::to_value(&report).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(value["schema"], "dlc-verify.report.v1");
    assert_eq!(value["status"], "pass");
    assert_eq!(value["verifier"]["ddk"], "2.0.0-rc.10");
    assert_eq!(value["counts"]["fail"], 0);
    assert_eq!(
        value["counts"]["pass"].as_u64(),
        Some(report.checks.len() as u64)
    );
    assert_eq!(
        value["payouts"]["cets"][0]["outputs"][0]["payee"],
        "offerer"
    );
}

/// DDK's own verifier accepts every fixture and rebuilds the same transactions.
#[test]
fn ddk_agrees_on_every_fixture() {
    for name in fixture_names() {
        let (input, options) = fixture(&name);
        let decoded = messages(&input);
        let (Some(accept), Some(sign)) = (decoded.accept.as_ref(), decoded.sign.as_ref()) else {
            unreachable!("{name}: fixture has an accept and a sign")
        };
        let verified = ddk::contract::verify_signed_contract(&decoded.offer, accept, sign)
            .unwrap_or_else(|error| unreachable!("{name}: DDK rejects the fixture: {error}"));
        let ours = verify(&input, &options);
        assert_eq!(ours.status, Status::Pass, "{name}");
        let rebuilt = ours
            .contract
            .as_ref()
            .unwrap_or_else(|| unreachable!("{name}: not rebuilt"));
        assert_eq!(rebuilt.contract_id, verified.contract_id(), "{name}");
        let theirs = verified.transactions();
        assert_eq!(
            rebuilt.transactions.fund.compute_txid(),
            theirs.fund.compute_txid(),
            "{name}"
        );
        assert_eq!(
            rebuilt.transactions.refund.compute_txid(),
            theirs.refund.compute_txid(),
            "{name}"
        );
        let ours_cets: Vec<_> = rebuilt
            .transactions
            .cets
            .iter()
            .map(|cet| cet.compute_txid())
            .collect();
        let theirs_cets: Vec<_> = theirs.cets.iter().map(|cet| cet.compute_txid()).collect();
        assert_eq!(ours_cets, theirs_cets, "{name}");
    }
}

/// DDK's verifier and ours both reject the same signature tampering.
#[test]
fn ddk_agrees_on_tampered_signatures() {
    type Tamper = fn(&mut Messages);
    let tampers: [(&str, Tamper); 4] = [
        ("accepter refund signature", |messages| {
            if let (Some(accept), Some(sign)) = (messages.accept.as_mut(), messages.sign.as_ref()) {
                accept.refund_signature = sign.refund_signature;
            }
        }),
        ("offerer refund signature", |messages| {
            if let (Some(accept), Some(sign)) = (messages.accept.as_ref(), messages.sign.as_mut()) {
                sign.refund_signature = accept.refund_signature;
            }
        }),
        ("offerer adaptor signatures", |messages| {
            if let (Some(accept), Some(sign)) = (messages.accept.as_ref(), messages.sign.as_mut()) {
                sign.cet_adaptor_signatures = accept.cet_adaptor_signatures.clone();
            }
        }),
        ("offerer funding witness", |messages| {
            if let Some(byte) = messages
                .sign
                .as_mut()
                .and_then(|sign| sign.funding_signatures.funding_signatures.first_mut())
                .and_then(|signature| signature.witness_elements.first_mut())
                .and_then(|element| element.witness.get_mut(10))
            {
                *byte ^= 1;
            }
        }),
    ];
    for name in ["enum-dual-funded", "numeric-payout-override"] {
        let (input, options) = fixture(name);
        for (label, tamper) in tampers {
            let mut decoded = messages(&input);
            tamper(&mut decoded);
            let (Some(accept), Some(sign)) = (decoded.accept.as_ref(), decoded.sign.as_ref())
            else {
                unreachable!("{name}: fixture has an accept and a sign")
            };
            assert!(
                ddk::contract::verify_signed_contract(&decoded.offer, accept, sign).is_err(),
                "{name}: DDK accepts a bad {label}"
            );
            let ours = verify(&encode(&decoded), &options);
            assert_eq!(ours.status, Status::Fail, "{name}: we accept a bad {label}");
        }
    }
}
