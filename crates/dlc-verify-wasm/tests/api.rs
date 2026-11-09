//! The module's JSON API, tested natively. `tools/wasm-smoke.mjs` runs the same kind of checks
//! against the compiled module.

use std::path::PathBuf;

use dlc_verify_wasm::api;
use serde_json::{Value, json};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| unreachable!("reading {path}: {error}"))
}

fn bundle(name: &str) -> Value {
    serde_json::from_str(&read(&format!("fixtures/{name}.json")))
        .unwrap_or_else(|error| unreachable!("{name}: {error}"))
}

fn call(function: fn(&str) -> String, request: &Value) -> Value {
    serde_json::from_str(&function(&request.to_string()))
        .unwrap_or_else(|error| unreachable!("the response is not JSON: {error}"))
}

fn ok(response: Value) -> Value {
    assert_eq!(response["ok"], true, "{response}");
    response
}

fn error_kind(response: &Value) -> &str {
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["kind"].as_str().unwrap_or_default()
}

#[test]
fn verify_matches_the_report_snapshots() {
    for name in [
        "enum-dual-funded",
        "midnight-liquidator",
        "numeric-dual-funded",
        "disjoint-enum-numeric",
    ] {
        let bundle = bundle(name);
        let response = ok(call(
            api::verify,
            &json!({"input": bundle, "now": bundle["now"]}),
        ));
        let expected: Value = serde_json::from_str(&read(&format!("fixtures/reports/{name}.json")))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(response["report"], expected, "{name}");
        assert_eq!(
            response["text"],
            read(&format!("fixtures/reports/{name}.txt")),
            "{name}"
        );
        assert_eq!(response["notes"], json!([]));
    }
}

#[test]
fn verify_reads_every_input_shape() {
    let bundle = bundle("enum-dual-funded");
    let now = bundle["now"].clone();
    let expected = ok(call(api::verify, &json!({"input": bundle, "now": now})))["report"].clone();
    for request in [
        json!({"input": bundle.to_string(), "now": now}),
        json!({
            "offer": bundle["offer"],
            "accept": bundle["accept"],
            "sign": bundle["sign"],
            "now": now,
        }),
    ] {
        assert_eq!(ok(call(api::verify, &request))["report"], expected);
    }

    let offer_only = ok(call(api::verify, &json!({"input": bundle["offer"]})));
    assert_eq!(offer_only["report"]["status"], "incomplete");
}

#[test]
fn verify_applies_a_profile_or_a_policy() {
    let bundle = bundle("midnight-liquidator");
    let response = ok(call(
        api::verify,
        &json!({
            "input": bundle,
            "now": bundle["now"],
            "profile": "lygos-midnight",
            "terms": read("fixtures/terms/midnight-liquidator.toml"),
        }),
    ));
    assert_eq!(response["report"]["policy"]["status"], "pass");
    assert!(
        response["text"]
            .as_str()
            .is_some_and(|text| text.contains("policy pass"))
    );

    let policy = ok(call(
        api::profile_policy,
        &json!({"profile": "lygos-midnight", "terms": read("fixtures/terms/midnight-liquidator.toml")}),
    ));
    let response = ok(call(
        api::verify,
        &json!({"input": bundle, "now": bundle["now"], "policy": policy["policy"].to_string()}),
    ));
    assert_eq!(response["report"]["policy"]["status"], "pass");

    // The loan profile does not fit a Midnight contract.
    let response = ok(call(
        api::verify,
        &json!({"input": bundle, "now": bundle["now"], "profile": "lygos-loan"}),
    ));
    assert_eq!(response["report"]["status"], "fail");
}

#[test]
fn bad_requests_say_why() {
    let bundle = bundle("enum-dual-funded");
    let cases = [
        (api::verify(""), "request"),
        (api::verify("[]"), "request"),
        (api::verify(r#"{"input": 5}"#), "request"),
        (
            api::verify(r#"{"offer": "00", "colour": "red"}"#),
            "request",
        ),
        (api::verify("{}"), "input"),
        (api::verify(r#"{"offer": "zz"}"#), "input"),
        (api::verify(r#"{"accept": "00"}"#), "input"),
        (
            call_text(
                api::verify,
                &json!({"input": bundle, "offer": bundle["offer"]}),
            ),
            "request",
        ),
        (
            call_text(api::verify, &json!({"input": bundle, "terms": "x = 1"})),
            "request",
        ),
        (
            call_text(
                api::verify,
                &json!({"input": bundle, "policy": "{}", "profile": "lygos-loan"}),
            ),
            "request",
        ),
        (
            call_text(
                api::verify,
                &json!({"input": bundle, "policy": "not = [toml"}),
            ),
            "policy",
        ),
        (
            call_text(api::verify, &json!({"input": bundle, "profile": "nope"})),
            "policy",
        ),
        (
            call_text(api::verify, &json!({"input": bundle, "attestations": []})),
            "request",
        ),
        (
            call_text(api::refund, &json!({"input": bundle, "policy": "{}"})),
            "request",
        ),
        (
            call_text(api::inspect, &json!({"input": bundle, "now": 1})),
            "request",
        ),
        (
            call_text(
                api::profile_policy,
                &json!({"input": bundle, "profile": "lygos-loan"}),
            ),
            "request",
        ),
        (api::profile_policy("{}"), "request"),
    ];
    for (response, kind) in cases {
        let response: Value =
            serde_json::from_str(&response).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(error_kind(&response), kind, "{response}");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
    }
}

fn call_text(function: fn(&str) -> String, request: &Value) -> String {
    function(&request.to_string())
}

#[test]
fn settle_and_refund() {
    let midnight = bundle("midnight-liquidator");
    let response = ok(call(
        api::settle,
        &json!({"input": midnight, "now": midnight["now"]}),
    ));
    assert_eq!(response["settlement"]["kind"], "cet");
    assert_eq!(response["settlement"]["outputs"][0]["payee"], "third-party");
    assert!(
        response["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("Signed CET for outcome liquidated-by-0x1111"))
    );

    // Attestations as a hex string, a list of objects, or the fixture's list as JSON text.
    let attestations = &midnight["attestations"];
    let without: Value = json!({
        "offer": midnight["offer"],
        "accept": midnight["accept"],
        "sign": midnight["sign"],
    });
    for given in [
        attestations[0]["hex"].clone(),
        attestations.clone(),
        Value::from(attestations.to_string()),
    ] {
        let mut request = without.clone();
        request["attestations"] = given;
        let settled = ok(call(api::settle, &request));
        assert_eq!(
            settled["settlement"]["txid"],
            response["settlement"]["txid"]
        );
    }
    assert_eq!(error_kind(&call(api::settle, &without)), "attestation");

    let multi = bundle("enum-multi-oracle");
    let request = json!({"input": multi, "attestations": [multi["attestations"][0]]});
    assert_eq!(error_kind(&call(api::settle, &request)), "no-cet");

    let other = bundle("enum-single-funded");
    let request = json!({"input": multi, "attestations": other["attestations"]});
    assert_eq!(error_kind(&call(api::settle, &request)), "attestation");

    let unsigned = json!({
        "offer": multi["offer"],
        "accept": multi["accept"],
        "attestations": multi["attestations"],
    });
    assert_eq!(error_kind(&call(api::settle, &unsigned)), "incomplete");
    assert_eq!(
        error_kind(&call(
            api::refund,
            &json!({"offer": multi["offer"], "accept": multi["accept"]})
        )),
        "incomplete"
    );

    let refund = ok(call(
        api::refund,
        &json!({"input": bundle("enum-refund-to-accepter"), "now": 4_000_000_000_u64}),
    ));
    assert_eq!(refund["settlement"]["kind"], "refund");
    assert_eq!(refund["settlement"]["broadcast"]["reached"], true);
    assert_eq!(refund["settlement"]["outputs"][0]["payee"], "accepter");
}

#[test]
fn inspect_profiles_oracles_and_version() {
    let response = ok(call(
        api::inspect,
        &json!({"input": bundle("enum-dual-funded")}),
    ));
    assert_eq!(response["inspection"]["schema"], "dlc-verify.inspect.v1");

    let profiles: Value =
        serde_json::from_str(&api::profiles()).unwrap_or_else(|error| unreachable!("{error}"));
    let profiles = ok(profiles);
    let names: Vec<&str> = profiles["profiles"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|entry| entry["name"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names, ["lygos-loan", "lygos-midnight"]);

    let oracles: Value =
        serde_json::from_str(&api::oracles()).unwrap_or_else(|error| unreachable!("{error}"));
    assert!(
        ok(oracles)["oracles"]
            .as_array()
            .is_some_and(|list| !list.is_empty())
    );

    let policy = ok(call(api::profile_policy, &json!({"profile": "lygos-loan"})));
    assert!(policy["policy"].is_object());
    assert_eq!(api::version(), dlc_verify_core::VERSION);
}
