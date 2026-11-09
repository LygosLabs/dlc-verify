//! End-to-end tests of the `dlc-verify` binary.

use std::path::PathBuf;
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dlc-verify"))
        .args(args)
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|error| unreachable!("could not run dlc-verify: {error}"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn version_and_help_exit_zero() {
    assert_eq!(run(&["--version"]).status.code(), Some(0));
    assert_eq!(run(&["--help"]).status.code(), Some(0));
}

#[test]
fn bad_arguments_exit_three() {
    assert_eq!(run(&["no-such-command"]).status.code(), Some(3));
    assert_eq!(run(&["inspect"]).status.code(), Some(3));
    assert_eq!(run(&["inspect", "--offer", "zz"]).status.code(), Some(3));
}

#[test]
fn inspect_json_bundle() {
    let output = run(&[
        "inspect",
        "examples/testnet-loan-118c9fc9.json",
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_str(&stdout(&output))
        .unwrap_or_else(|error| unreachable!("inspect output is not JSON: {error}"));
    assert_eq!(value["schema"], "dlc-verify.inspect.v1");
    assert_eq!(value["offer"]["network"], "regtest");
    assert_eq!(value["sign"]["protocol_version"], 1);
    assert_eq!(value["accept"]["cet_adaptor_signatures"], 5);
}

#[test]
fn inspect_reports_a_message_of_the_wrong_type() {
    let output = run(&["inspect", "--offer", "a71c0000"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("this is an accept message, not an offer"));
}

#[test]
fn inspect_reads_messages_from_files() {
    let bundle = std::fs::read_to_string(repo_root().join("examples/sample.json"))
        .unwrap_or_else(|error| unreachable!("{error}"));
    let value: serde_json::Value =
        serde_json::from_str(&bundle).unwrap_or_else(|error| unreachable!("{error}"));
    let dir = std::env::temp_dir().join(format!("dlc-verify-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| unreachable!("{error}"));
    let offer_path = dir.join("offer.hex");
    std::fs::write(&offer_path, value["offer"].as_str().unwrap_or_default())
        .unwrap_or_else(|error| unreachable!("{error}"));
    let offer_arg = format!("@{}", offer_path.display());
    let accept = value["accept"].as_str().unwrap_or_default();
    let output = run(&["inspect", "--offer", &offer_arg, "--accept", accept]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("loan-matured-7932e4c2"));
}

fn fixture_value(name: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(repo_root().join("fixtures").join(format!("{name}.json")))
        .unwrap_or_else(|error| unreachable!("{error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| unreachable!("{error}"))
}

fn hex_field<'a>(value: &'a serde_json::Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| unreachable!("fixture has no {field}"))
}

#[test]
fn verify_passes_a_signed_fixture() {
    let output = run(&[
        "verify",
        "fixtures/enum-payout-override.json",
        "--now",
        "1767139200",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("Result: PASS"));
    assert!(text.contains("third-party 100,000 sat to"));
}

#[test]
fn verify_json_report() {
    let output = run(&[
        "verify",
        "fixtures/enum-refund-to-accepter.json",
        "--format",
        "json",
        "--no-clock",
    ]);
    // Without a clock the maturity check warns, which does not change the result.
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_str(&stdout(&output))
        .unwrap_or_else(|error| unreachable!("verify output is not JSON: {error}"));
    assert_eq!(value["schema"], "dlc-verify.report.v1");
    assert_eq!(value["status"], "pass");
    assert_eq!(value["counts"]["warn"], 1);
    assert_eq!(value["contract"]["network"], "testnet4");
    assert_eq!(
        value["payouts"]["refund"]["outputs"][0]["payee"],
        "accepter"
    );
}

#[test]
fn verify_an_offer_alone_is_incomplete() {
    let fixture = fixture_value("enum-dual-funded");
    let output = run(&[
        "verify",
        "--offer",
        hex_field(&fixture, "offer"),
        "--no-clock",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("Result: INCOMPLETE"));
}

#[test]
fn verify_fails_a_tampered_sign_message() {
    let fixture = fixture_value("enum-dual-funded");
    // Bytes 6.. of a sign message are the contract id: flip a bit in its first byte.
    let mut sign = hex_field(&fixture, "sign").to_owned();
    let flipped =
        u8::from_str_radix(&sign[12..14], 16).unwrap_or_else(|error| unreachable!("{error}")) ^ 1;
    sign.replace_range(12..14, &format!("{flipped:02x}"));
    let output = run(&[
        "verify",
        "--offer",
        hex_field(&fixture, "offer"),
        "--accept",
        hex_field(&fixture, "accept"),
        "--sign",
        &sign,
        "--now",
        "1767139200",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("Result: FAIL"));
    assert!(text.contains("fail  sig.contract-id"));
}

#[test]
fn verify_rejects_now_with_no_clock() {
    let output = run(&[
        "verify",
        "fixtures/enum-dual-funded.json",
        "--now",
        "1",
        "--no-clock",
    ]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn verify_with_a_matching_policy_passes() {
    let output = run(&[
        "verify",
        "fixtures/enum-payout-override.json",
        "--now",
        "1767139200",
        "--policy",
        "fixtures/policies/enum-payout-override.toml",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("policy pass"), "{text}");
    assert!(text.contains("pass  policy.cet-payouts"), "{text}");

    let output = run(&[
        "verify",
        "fixtures/numeric-payout-override.json",
        "--now",
        "1767139200",
        "--format",
        "json",
        "--policy",
        "fixtures/policies/numeric-payout-override.json",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_str(&stdout(&output))
        .unwrap_or_else(|error| unreachable!("verify output is not JSON: {error}"));
    assert_eq!(value["status"], "pass");
    assert_eq!(value["policy"]["status"], "pass");
}

#[test]
fn verify_with_a_policy_the_contract_breaks_fails() {
    let output = run(&[
        "verify",
        "fixtures/enum-dual-funded.json",
        "--now",
        "1767139200",
        "--policy",
        "fixtures/policies/enum-payout-override.toml",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("Result: FAIL"), "{text}");
    assert!(text.contains("fail  policy.cet-payouts"), "{text}");
}

#[test]
fn verify_rejects_a_bad_policy_file() {
    let dir = std::env::temp_dir().join(format!("dlc-verify-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| unreachable!("{error}"));
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "schema = \"dlc-verify.policy.v1\"\nnetwrok = \"regtest\"\n",
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let path_arg = path.display().to_string();
    let bad = run(&[
        "verify",
        "fixtures/enum-dual-funded.json",
        "--no-clock",
        "--policy",
        &path_arg,
    ]);
    let missing = run(&[
        "verify",
        "fixtures/enum-dual-funded.json",
        "--no-clock",
        "--policy",
        "fixtures/policies/no-such-policy.toml",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(bad.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("unknown field `netwrok`"));
    assert_eq!(missing.status.code(), Some(3));
}

#[test]
fn verify_with_a_profile_and_terms() {
    let output = run(&[
        "verify",
        "fixtures/midnight-liquidator.json",
        "--now",
        "1767139200",
        "--profile",
        "lygos-midnight",
        "--terms",
        "fixtures/terms/midnight-liquidator.toml",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.contains("policy pass"), "{text}");
    assert!(text.contains("pass  policy.oracle-events"), "{text}");

    let output = run(&[
        "verify",
        "examples/testnet-loan-118c9fc9.json",
        "--no-clock",
        "--profile",
        "lygos-loan",
        "--terms",
        "fixtures/terms/testnet-loan-118c9fc9.toml",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn verify_with_the_wrong_profile_fails() {
    let output = run(&[
        "verify",
        "fixtures/midnight-liquidator.json",
        "--now",
        "1767139200",
        "--profile",
        "lygos-loan",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("fail  policy.contract-flags"));
}

#[test]
fn profile_arguments_are_checked() {
    let both = run(&[
        "verify",
        "fixtures/midnight-liquidator.json",
        "--no-clock",
        "--profile",
        "lygos-midnight",
        "--policy",
        "fixtures/policies/enum-payout-override.toml",
    ]);
    assert_eq!(both.status.code(), Some(3));
    let terms_alone = run(&[
        "verify",
        "fixtures/midnight-liquidator.json",
        "--no-clock",
        "--terms",
        "fixtures/terms/midnight-liquidator.toml",
    ]);
    assert_eq!(terms_alone.status.code(), Some(3));
    let unknown = run(&["profile", "lygos-options"]);
    assert_eq!(unknown.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("lygos-midnight"));
}

#[test]
fn profile_prints_the_policy_it_builds() {
    let output = run(&[
        "profile",
        "lygos-midnight",
        "--terms",
        "fixtures/terms/midnight-liquidator.toml",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_str(&stdout(&output))
        .unwrap_or_else(|error| unreachable!("profile output is not JSON: {error}"));
    assert_eq!(value["schema"], "dlc-verify.policy.v1");
    assert_eq!(value["contract_flags"][0], "refund-to-accepter");
    assert_eq!(value["require_every_cet"], true);

    let output = run(&["profile", "lygos-midnight"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("dlc-verify: lygos-midnight:"));
}

#[test]
fn oracles_lists_the_registry() {
    let output = run(&["oracles"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("magnolia-testnet"));
    let output = run(&["oracles", "--format", "json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout(&output))
        .unwrap_or_else(|error| unreachable!("oracles output is not JSON: {error}"));
    assert_eq!(value[0]["name"], "magnolia-mainnet");
}
