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
