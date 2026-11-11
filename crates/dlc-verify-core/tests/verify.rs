//! The verifier passes every generated vector and fails each tampered one on the right check.

use std::path::PathBuf;

use ddk_messages::contract_msgs::{ContractDescriptor, ContractInfo};
use dlc_verify_core::verify::{CHECK_IDS, fee_rule_name};
use dlc_verify_core::{
    CheckStatus, Input, Messages, Options, Status, Verification, decode, verify,
};
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

/// A fixture's input and its `now`.
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

fn status(verification: &Verification, id: &str) -> CheckStatus {
    verification
        .check(id)
        .unwrap_or_else(|| unreachable!("no check {id}"))
        .status
}

fn report(verification: &Verification) -> String {
    verification
        .checks
        .iter()
        .map(|check| format!("{} {}: {}", check.status.name(), check.id, check.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Verifies a tampered copy of `name` and asserts it fails on check `id`.
fn assert_fails_on(name: &str, id: &str, tamper: impl FnOnce(&mut Messages)) -> Verification {
    let (input, options) = fixture(name);
    let mut decoded = messages(&input);
    tamper(&mut decoded);
    let verification = verify(&encode(&decoded), &options);
    assert_eq!(
        verification.status,
        Status::Fail,
        "{name}:\n{}",
        report(&verification)
    );
    assert_eq!(
        status(&verification, id),
        CheckStatus::Fail,
        "{name}:\n{}",
        report(&verification)
    );
    verification
}

#[test]
fn every_fixture_passes() {
    let names = fixture_names();
    assert!(names.len() >= 8, "expected the generated fixtures");
    for name in names {
        let (input, options) = fixture(&name);
        let verification = verify(&input, &options);
        assert_eq!(verification.checks.len(), CHECK_IDS.len(), "{name}");
        let ids: Vec<&str> = verification.checks.iter().map(|check| check.id).collect();
        assert_eq!(ids, CHECK_IDS, "{name}");
        assert_eq!(
            verification.status,
            Status::Pass,
            "{name}:\n{}",
            report(&verification)
        );
        let contract = verification
            .contract
            .as_ref()
            .unwrap_or_else(|| unreachable!("{name}: no rebuilt contract"));
        let sign = verification
            .messages
            .as_ref()
            .and_then(|messages| messages.sign.as_ref())
            .unwrap_or_else(|| unreachable!("{name}: no sign"));
        assert_eq!(sign.contract_id, contract.contract_id, "{name}");
        assert!(!fee_rule_name(contract.fee_rule).is_empty());
    }
}

#[test]
fn rebuilt_funding_transaction_matches_the_signed_one() {
    for name in fixture_names() {
        let path = repo_root().join("fixtures").join(format!("{name}.json"));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| unreachable!("reading {}: {error}", path.display()));
        let value: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| unreachable!("parsing {}: {error}", path.display()));
        let signed = value["funding_transaction"]
            .as_str()
            .unwrap_or_else(|| unreachable!("{name}: no funding transaction"));
        let signed: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &hex::decode(signed).unwrap_or_else(|error| unreachable!("{name}: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("{name}: {error}"));
        let (input, options) = fixture(&name);
        let verification = verify(&input, &options);
        let contract = verification
            .contract
            .unwrap_or_else(|| unreachable!("{name}: no rebuilt contract"));
        assert_eq!(
            contract.transactions.fund.compute_txid(),
            signed.compute_txid(),
            "{name}"
        );
    }
}

#[test]
fn an_offer_alone_is_incomplete() {
    let (input, options) = fixture("enum-dual-funded");
    let offer_only = Input {
        offer: input.offer,
        accept: None,
        sign: None,
    };
    let verification = verify(&offer_only, &options);
    assert_eq!(
        verification.status,
        Status::Incomplete,
        "{}",
        report(&verification)
    );
    assert_eq!(status(&verification, "decode.accept"), CheckStatus::Skip);
    assert_eq!(
        status(&verification, "oracle.announcement-signature"),
        CheckStatus::Pass
    );
    assert_eq!(
        status(&verification, "oracle.outcome-coverage"),
        CheckStatus::Pass
    );
    assert_eq!(status(&verification, "tx.build"), CheckStatus::Skip);
    assert!(verification.contract.is_none());
}

#[test]
fn an_offer_and_accept_check_the_accepters_signatures() {
    for name in fixture_names() {
        let (input, options) = fixture(&name);
        let without_sign = Input {
            sign: None,
            ..input
        };
        let verification = verify(&without_sign, &options);
        assert_eq!(
            verification.status,
            Status::Incomplete,
            "{name}:\n{}",
            report(&verification)
        );
        for id in ["tx.build", "sig.accept.cet-adaptors", "sig.accept.refund"] {
            assert_eq!(status(&verification, id), CheckStatus::Pass, "{name}: {id}");
        }
        for id in [
            "sig.offer.cet-adaptors",
            "sig.offer.refund",
            "sig.offer.funding",
            "sig.contract-id",
        ] {
            assert_eq!(status(&verification, id), CheckStatus::Skip, "{name}: {id}");
        }
    }
}

#[test]
fn a_bad_offer_fails_and_skips_everything_else() {
    let input = Input {
        offer: vec![0xa7, 0x1a, 0x00],
        accept: None,
        sign: None,
    };
    let verification = verify(&input, &Options::default());
    assert_eq!(verification.status, Status::Fail);
    assert_eq!(status(&verification, "decode.offer"), CheckStatus::Fail);
    assert!(
        verification
            .checks
            .iter()
            .skip(1)
            .all(|check| check.status == CheckStatus::Skip)
    );
    assert!(verification.messages.is_none());
}

#[test]
fn maturity_without_a_clock_warns() {
    let (input, _) = fixture("enum-dual-funded");
    let verification = verify(&input, &Options::default());
    assert_eq!(
        verification.status,
        Status::Pass,
        "{}",
        report(&verification)
    );
    assert_eq!(status(&verification, "oracle.maturity"), CheckStatus::Warn);
}

#[test]
fn maturity_in_the_past_warns() {
    let (input, _) = fixture("enum-dual-funded");
    let verification = verify(
        &input,
        &Options {
            now: Some(u64::from(u32::MAX)),
        },
    );
    assert_eq!(status(&verification, "oracle.maturity"), CheckStatus::Warn);
}

#[test]
fn a_wrong_accepter_refund_signature_fails() {
    assert_fails_on("enum-dual-funded", "sig.accept.refund", |messages| {
        let (Some(accept), Some(sign)) = (messages.accept.as_mut(), messages.sign.as_ref()) else {
            unreachable!("fixture has an accept and a sign")
        };
        accept.refund_signature = sign.refund_signature;
    });
}

#[test]
fn swapped_adaptor_signatures_fail() {
    assert_fails_on(
        "numeric-dual-funded",
        "sig.offer.cet-adaptors",
        |messages| {
            let (Some(accept), Some(sign)) = (messages.accept.as_ref(), messages.sign.as_mut())
            else {
                unreachable!("fixture has an accept and a sign")
            };
            sign.cet_adaptor_signatures = accept.cet_adaptor_signatures.clone();
        },
    );
}

#[test]
fn a_wrong_contract_id_fails() {
    assert_fails_on("enum-payout-override", "sig.contract-id", |messages| {
        let Some(sign) = messages.sign.as_mut() else {
            unreachable!("fixture has a sign")
        };
        sign.contract_id[0] ^= 1;
    });
}

#[test]
fn a_bad_funding_witness_fails() {
    assert_fails_on("enum-dual-funded", "sig.offer.funding", |messages| {
        let Some(sign) = messages.sign.as_mut() else {
            unreachable!("fixture has a sign")
        };
        let witness = sign
            .funding_signatures
            .funding_signatures
            .first_mut()
            .and_then(|signature| signature.witness_elements.first_mut())
            .unwrap_or_else(|| unreachable!("the offerer signs a funding input"));
        if let Some(byte) = witness.witness.get_mut(10) {
            *byte ^= 1;
        }
    });
}

#[test]
fn a_different_temporary_id_fails() {
    assert_fails_on("enum-multi-oracle", "structure.temp-id", |messages| {
        let Some(accept) = messages.accept.as_mut() else {
            unreachable!("fixture has an accept")
        };
        accept.temporary_contract_id[5] ^= 0xff;
    });
}

#[test]
fn a_payout_over_the_total_fails_without_panicking() {
    let verification = assert_fails_on("enum-dual-funded", "structure.collateral", |messages| {
        let ContractInfo::SingleContractInfo(single) = &mut messages.offer.contract_info else {
            unreachable!("a single contract info")
        };
        let total = single.total_collateral;
        let ContractDescriptor::EnumeratedContractDescriptor(descriptor) =
            &mut single.contract_info.contract_descriptor
        else {
            unreachable!("an enum descriptor")
        };
        if let Some(payout) = descriptor.payouts.first_mut() {
            payout.offer_payout = total + bitcoin::Amount::from_sat(1);
        }
    });
    assert_eq!(status(&verification, "tx.build"), CheckStatus::Skip);
    assert!(verification.contract.is_none());
}

#[test]
fn an_accepter_collateral_mismatch_fails() {
    assert_fails_on("enum-dual-funded", "structure.collateral", |messages| {
        let Some(accept) = messages.accept.as_mut() else {
            unreachable!("fixture has an accept")
        };
        accept.accept_collateral += bitcoin::Amount::from_sat(1);
    });
}

#[test]
fn an_excessive_fee_rate_fails() {
    assert_fails_on("enum-single-funded", "structure.fee-rate", |messages| {
        messages.offer.fee_rate_per_vb = 10_000;
    });
}

#[test]
fn unknown_contract_flags_fail() {
    assert_fails_on("enum-dual-funded", "structure.contract-flags", |messages| {
        messages.offer.contract_flags |= 0x80;
    });
}

#[test]
fn a_refund_before_maturity_fails() {
    assert_fails_on("enum-dual-funded", "locktime.refund", |messages| {
        messages.offer.refund_locktime = 500_000_001;
    });
}

#[test]
fn a_cet_locktime_after_maturity_fails() {
    assert_fails_on("enum-dual-funded", "locktime.cet", |messages| {
        messages.offer.cet_locktime = messages.offer.refund_locktime - 1;
    });
}

#[test]
fn the_refund_to_accepter_flag_is_named() {
    let (input, options) = fixture("enum-refund-to-accepter");
    let verification = verify(&input, &options);
    let flags = verification
        .check("structure.contract-flags")
        .unwrap_or_else(|| unreachable!("no flags check"));
    assert_eq!(flags.status, CheckStatus::Pass);
    assert_ne!(flags.detail, "none");
}

// The findings of the review of the TypeScript verifier (PR #10), pinned against the Rust one.

#[test]
fn a_contract_outcome_the_oracle_never_announced_fails() {
    assert_fails_on("enum-dual-funded", "oracle.outcome-coverage", |messages| {
        let ContractInfo::SingleContractInfo(single) = &mut messages.offer.contract_info else {
            unreachable!("a single contract info")
        };
        let ContractDescriptor::EnumeratedContractDescriptor(descriptor) =
            &mut single.contract_info.contract_descriptor
        else {
            unreachable!("an enum descriptor")
        };
        if let Some(payout) = descriptor.payouts.first_mut() {
            payout.outcome.push(' ');
        }
    });
}

#[test]
fn a_refund_without_a_locktime_fails() {
    assert_fails_on("enum-dual-funded", "locktime.refund", |messages| {
        messages.offer.refund_locktime = 0;
    });
}

/// The offer with one more TLV record of `tlv_type` (below 0xfd) after its fixed fields.
fn with_tlv(name: &str, tlv_type: u8) -> (Input, Options) {
    let (mut input, options) = fixture(name);
    input.offer.extend_from_slice(&[tlv_type, 1, 0]);
    (input, options)
}

#[test]
fn an_unknown_even_tlv_fails() {
    let (input, options) = with_tlv("enum-dual-funded", 0x10);
    let verification = verify(&input, &options);
    assert_eq!(
        verification.status,
        Status::Fail,
        "{}",
        report(&verification)
    );
    assert_eq!(
        status(&verification, "decode.unknown-tlvs"),
        CheckStatus::Fail,
        "{}",
        report(&verification)
    );
}

#[test]
fn an_unknown_odd_tlv_warns() {
    let (input, options) = with_tlv("enum-dual-funded", 0x11);
    let verification = verify(&input, &options);
    assert_eq!(
        status(&verification, "decode.unknown-tlvs"),
        CheckStatus::Warn,
        "{}",
        report(&verification)
    );
}
