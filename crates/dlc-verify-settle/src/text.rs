//! A settlement as text for a terminal.

use dlc_verify_core::Status;
use dlc_verify_core::report::sats;

use crate::{Broadcast, Kind, Settlement};

/// Renders `settlement` as text: what it pays, when it can be broadcast, and the signed
/// transaction hex last.
pub fn render_text(settlement: &Settlement) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(match (&settlement.kind, &settlement.cet) {
        (Kind::Cet, Some(cet)) => format!(
            "Signed CET for outcome {}  (CET {}, contract info {})",
            cet.outcome, cet.index, cet.contract_info
        ),
        (Kind::Cet, None) => "Signed CET".to_owned(),
        (Kind::Refund, _) => "Signed refund".to_owned(),
    });
    if settlement.verification != Status::Pass {
        lines.push(format!(
            "Warning: the messages did not pass verification ({}); run `dlc-verify verify` and \
             read the report before broadcasting.",
            settlement.verification.name()
        ));
    }
    lines.push(String::new());
    let row = |label: &str, value: String| format!("  {label:<12}{value}");
    lines.push(row("Contract id", settlement.contract_id.clone()));
    lines.push(row("Txid", settlement.txid.clone()));
    lines.push(row(
        "Spends",
        format!(
            "{}:{}, {} sat",
            settlement.spends.txid,
            settlement.spends.vout,
            sats(settlement.spends.value_sat)
        ),
    ));
    if let Some(cet) = &settlement.cet {
        for attestation in &cet.attestations {
            lines.push(row(
                "Attested",
                format!(
                    "oracle {} ({}): event {}, outcome {}",
                    attestation.oracle_index,
                    attestation.oracle_public_key,
                    attestation.event_id,
                    attestation.outcomes.join(" ")
                ),
            ));
        }
    }
    for output in &settlement.outputs {
        lines.push(row(
            "Pays",
            format!(
                "{} sat to {} {}",
                sats(output.value_sat),
                output.payee.name(),
                output.script.display()
            ),
        ));
    }
    lines.push(row(
        "Fee",
        format!("{} sat, {} vB", sats(settlement.fee_sat), settlement.vsize),
    ));
    lines.push(row("Broadcast", broadcast(&settlement.broadcast)));
    lines.push(String::new());
    lines.push(settlement.transaction.clone());
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

fn broadcast(when: &Broadcast) -> String {
    let confirmed = "once the funding transaction confirms";
    match when {
        Broadcast::Now => confirmed.to_owned(),
        Broadcast::AfterHeight { height } => format!("{confirmed}, from block {}", height + 1),
        Broadcast::AfterTime { utc, reached, .. } => {
            let state = match reached {
                Some(true) => " (passed)",
                Some(false) => " (not yet)",
                None => "",
            };
            format!("{confirmed} and the chain's median time passes {utc}{state}")
        }
    }
}
