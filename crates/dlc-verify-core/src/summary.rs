//! Readable summaries of the values inside DLC messages, shared by `inspect` and reports.

use bitcoin::{Network, Script, Transaction};
use ddk_messages::FundingInput;
use serde::Serialize;

use crate::time::{LocktimeKind, format_unix, locktime_kind};

/// A script, with its address on the contract's network when it has one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScriptSummary {
    /// The script in hex.
    pub hex: String,
    /// The script's address, if it is a standard output script and the network is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The script type, e.g. `p2wpkh`.
    pub kind: &'static str,
}

impl ScriptSummary {
    /// Summarizes `script`.
    pub fn new(script: &Script, network: Option<Network>) -> Self {
        Self {
            hex: hex::encode(script.as_bytes()),
            address: network.and_then(|network| {
                bitcoin::Address::from_script(script, network)
                    .ok()
                    .map(|address| address.to_string())
            }),
            kind: script_kind(script),
        }
    }

    /// The address if there is one, otherwise the script hex.
    pub fn display(&self) -> &str {
        self.address.as_deref().unwrap_or(&self.hex)
    }
}

/// The type of an output script.
pub fn script_kind(script: &Script) -> &'static str {
    if script.is_empty() {
        "empty"
    } else if script.is_p2wpkh() {
        "p2wpkh"
    } else if script.is_p2wsh() {
        "p2wsh"
    } else if script.is_p2tr() {
        "p2tr"
    } else if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else if script.is_op_return() {
        "op_return"
    } else if script.witness_version().is_some() {
        "witness"
    } else {
        "nonstandard"
    }
}

/// A locktime and what it means.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LocktimeSummary {
    /// The raw value.
    pub value: u32,
    /// Height, time, or no lock.
    pub kind: LocktimeKind,
    /// The time as RFC 3339, when it is a time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utc: Option<String>,
}

impl LocktimeSummary {
    /// Summarizes `value`.
    pub fn new(value: u32) -> Self {
        let kind = locktime_kind(value);
        Self {
            value,
            kind,
            utc: (kind == LocktimeKind::Time).then(|| format_unix(u64::from(value))),
        }
    }
}

/// A Unix time and its RFC 3339 form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TimeSummary {
    /// Seconds since 1970.
    pub unix: u64,
    /// RFC 3339 UTC.
    pub utc: String,
}

impl TimeSummary {
    /// Summarizes `unix`.
    pub fn new(unix: u64) -> Self {
        Self {
            unix,
            utc: format_unix(unix),
        }
    }
}

/// A funding input as the message carries it, with the spent output read from `prev_tx`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FundingInputSummary {
    /// The serial id that orders it among the funding transaction's inputs.
    pub serial_id: u64,
    /// The spent output, `txid:vout`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outpoint: Option<String>,
    /// The spent output's value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_sat: Option<u64>,
    /// The spent output's script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptSummary>,
    /// Why the spent output could not be read, if it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_tx_error: Option<String>,
    /// The input's sequence.
    pub sequence: u32,
    /// The largest witness the input's owner expects to provide.
    pub max_witness_len: u16,
    /// The P2SH redeem script, in hex, for nested segwit inputs.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub redeem_script: String,
    /// Set when the input spends an earlier DLC's funding output (a splice).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dlc_input: Option<DlcInputSummary>,
}

/// The earlier DLC a splice input spends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DlcInputSummary {
    /// The earlier contract's id.
    pub contract_id: String,
    /// The funding key of this input's owner in the earlier contract.
    pub local_fund_pubkey: String,
    /// The counterparty's funding key in the earlier contract.
    pub remote_fund_pubkey: String,
}

/// The output a funding input spends.
pub struct SpentOutput {
    /// The spent outpoint.
    pub outpoint: bitcoin::OutPoint,
    /// The spent output.
    pub txout: bitcoin::TxOut,
}

/// Reads the output a funding input spends from its `prev_tx`.
///
/// # Errors
///
/// Fails when `prev_tx` is not a transaction or has no output at `prev_tx_vout`.
pub fn spent_output(input: &FundingInput) -> Result<SpentOutput, String> {
    let tx: Transaction = bitcoin::consensus::deserialize(&input.prev_tx)
        .map_err(|error| format!("prev_tx is not a transaction: {error}"))?;
    let txout = usize::try_from(input.prev_tx_vout)
        .ok()
        .and_then(|vout| tx.output.get(vout))
        .cloned()
        .ok_or_else(|| {
            format!(
                "prev_tx has {} outputs, no output {}",
                tx.output.len(),
                input.prev_tx_vout
            )
        })?;
    Ok(SpentOutput {
        outpoint: bitcoin::OutPoint {
            txid: tx.compute_txid(),
            vout: input.prev_tx_vout,
        },
        txout,
    })
}

impl FundingInputSummary {
    /// Summarizes `input`.
    pub fn new(input: &FundingInput, network: Option<Network>) -> Self {
        let spent = spent_output(input);
        let (outpoint, value_sat, script, prev_tx_error) = match spent {
            Ok(spent) => (
                Some(spent.outpoint.to_string()),
                Some(spent.txout.value.to_sat()),
                Some(ScriptSummary::new(&spent.txout.script_pubkey, network)),
                None,
            ),
            Err(error) => (None, None, None, Some(error)),
        };
        Self {
            serial_id: input.input_serial_id,
            outpoint,
            value_sat,
            script,
            prev_tx_error,
            sequence: input.sequence,
            max_witness_len: input.max_witness_len,
            redeem_script: hex::encode(input.redeem_script.as_bytes()),
            dlc_input: input.dlc_input.as_ref().map(|dlc| DlcInputSummary {
                contract_id: hex::encode(dlc.contract_id),
                local_fund_pubkey: dlc.local_fund_pubkey.to_string(),
                remote_fund_pubkey: dlc.remote_fund_pubkey.to_string(),
            }),
        }
    }
}
