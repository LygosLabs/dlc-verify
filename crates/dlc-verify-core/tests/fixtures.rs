//! Every vector in `fixtures/` and every bundle in `examples/` decodes strictly.

use std::path::{Path, PathBuf};

use dlc_verify_core::{Input, decode, inspect};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json_files(directory: &str) -> Vec<PathBuf> {
    let directory = repo_root().join(directory);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", directory.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    files
}

fn read(path: &Path) -> (String, Value) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| unreachable!("reading {}: {error}", path.display()));
    let value = serde_json::from_str(&text)
        .unwrap_or_else(|error| unreachable!("parsing {}: {error}", path.display()));
    (text, value)
}

fn input(path: &Path, text: &str) -> Input {
    Input::from_bundle(text)
        .unwrap_or_else(|error| unreachable!("{}: not a bundle: {error}", path.display()))
}

#[test]
fn fixtures_decode_strictly() {
    let files = json_files("fixtures");
    assert!(files.len() >= 8, "expected the generated fixtures");
    for path in files {
        let (text, fixture) = read(&path);
        let messages = decode(&input(&path, &text))
            .unwrap_or_else(|error| unreachable!("{}: {error}", path.display()));
        assert!(messages.accept.is_some(), "{}: no accept", path.display());
        assert!(messages.sign.is_some(), "{}: no sign", path.display());

        let inspection = inspect(&input(&path, &text));
        assert!(inspection.errors.is_empty(), "{}", path.display());
        let offer = inspection
            .offer
            .unwrap_or_else(|| unreachable!("{}: no offer summary", path.display()));
        assert_eq!(
            Some(offer.network.unwrap_or("unknown")),
            fixture["network"].as_str(),
            "{}",
            path.display()
        );
    }
}

#[test]
fn fixtures_cover_the_contract_shapes() {
    let fixture = |name: &str| {
        let path = repo_root().join("fixtures").join(format!("{name}.json"));
        let (text, _) = read(&path);
        inspect(&input(&path, &text))
            .offer
            .unwrap_or_else(|| unreachable!("{name}: no offer summary"))
    };

    assert_eq!(fixture("enum-refund-to-accepter").contract_flags, 0x01);
    // A Midnight loan: the refund goes to the accepter and one liquidation pays a third party.
    assert_eq!(fixture("midnight-liquidator").contract_flags, 0x01);
    for name in [
        "enum-payout-override",
        "numeric-payout-override",
        "midnight-liquidator",
    ] {
        let overrides = fixture(name)
            .payout_overrides
            .unwrap_or_else(|| unreachable!("{name}: no override record"));
        assert_eq!(overrides.len(), 1, "{name}");
    }
    assert!(fixture("enum-dual-funded").payout_overrides.is_none());
}

#[test]
fn examples_decode_strictly() {
    for path in json_files("examples") {
        let (text, _) = read(&path);
        decode(&input(&path, &text))
            .unwrap_or_else(|error| unreachable!("{}: {error}", path.display()));
    }
}
