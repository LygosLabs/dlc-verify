//! The policy format: what a contract must look like, read from TOML or JSON.

use std::fmt;
use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf};
use dlc_verify_core::network::parse_network;
use serde::{Deserialize, Serialize};

/// The schema name every policy file states.
pub const POLICY_SCHEMA: &str = "dlc-verify.policy.v1";

/// Why a policy could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

/// The terms a contract must have. Every field is optional: the policy checks only what it
/// states.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Always [`POLICY_SCHEMA`].
    pub schema: String,
    /// A name to show in reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The network the offer's chain hash must name: `mainnet`, `testnet`, `testnet4`,
    /// `signet` or `regtest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// The total collateral, in sats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_collateral_sat: Option<u64>,
    /// The highest acceptable fee rate, in sat/vB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_rate_per_vb: Option<u64>,
    /// The exact set of contract flags, by name (`refund-to-accepter`). An empty list means no
    /// flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_flags: Option<Vec<String>>,
    /// The TLV record types the messages may carry. Any other record fails the policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tlvs: Option<Vec<u64>>,
    /// The offering party.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offerer: Option<PartyPolicy>,
    /// The accepting party.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepter: Option<PartyPolicy>,
    /// The oracles and events the contract settles on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<OraclePolicy>,
    /// The CET and refund locktimes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locktimes: Option<LocktimePolicy>,
    /// Who the refund transaction pays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund: Option<RefundRule>,
    /// Who the CETs pay, by outcome.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cets: Vec<CetRule>,
    /// Fail when a CET matches none of the `cets` rules.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_every_cet: bool,
}

/// What one party's messages must say.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartyPolicy {
    /// The party's funding public key, compressed, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_pubkey: Option<String>,
    /// The party's payout destination: an address or a script in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout: Option<String>,
    /// The party's collateral, in sats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_sat: Option<u64>,
}

/// The oracles a contract may use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OraclePolicy {
    /// Every announcement must be signed by one of these keys (x-only or compressed, in hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkeys: Option<Vec<String>>,
    /// Every announcement's event id must be one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ids: Option<Vec<String>>,
    /// Every announcement must mature at this Unix time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maturity: Option<u64>,
    /// Every contract info must need this many oracles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u16>,
}

/// The locktimes a contract must have.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocktimePolicy {
    /// The exact CET locktime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cet: Option<u32>,
    /// The exact refund locktime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund: Option<u32>,
    /// The exact gap, in seconds, between the earliest oracle maturity and the refund locktime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_delay: Option<u64>,
    /// The smallest acceptable gap, in seconds, between the earliest oracle maturity and the
    /// refund locktime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_delay_min: Option<u64>,
}

/// Who the refund transaction pays.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundRule {
    /// The refund's outputs, in any order. The refund must have exactly these.
    pub pay: Vec<Pay>,
}

/// Who the CETs settling some outcomes pay.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CetRule {
    /// The enum outcome the rule covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// The numeric values the rule covers, both ends included. Every CET whose values lie inside
    /// follows the rule; a CET that lies partly inside fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<[u64; 2]>,
    /// Only the CETs of this contract info (by position in the offer), for offers with several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_info: Option<usize>,
    /// The CETs' outputs, in any order. Each CET must have exactly these.
    pub pay: Vec<Pay>,
}

/// A party a payout can go to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Party {
    /// The offering party's payout script.
    Offerer,
    /// The accepting party's payout script.
    Accepter,
    /// Any script a payout-script-override record put in place of the accepter's.
    ThirdParty,
}

impl Party {
    /// The name used in policies and reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Offerer => "offerer",
            Self::Accepter => "accepter",
            Self::ThirdParty => "third-party",
        }
    }
}

/// One expected output. Exactly one of `party`, `address` and `script` names where it goes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pay {
    /// The party paid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<Party>,
    /// The address paid. Only its script is compared, so the address's network prefix does not
    /// matter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The script paid, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// The exact output value, in sats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sat: Option<u64>,
    /// The smallest acceptable output value, in sats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_value_sat: Option<u64>,
}

/// Where an expected output goes, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// A party's payout script.
    Party(Party),
    /// A script, in lowercase hex.
    Script(String),
}

impl Pay {
    /// Pays `party`.
    pub fn party(party: Party) -> Self {
        Self {
            party: Some(party),
            ..Self::default()
        }
    }

    /// Pays the script `script_hex`.
    pub fn script(script_hex: impl Into<String>) -> Self {
        Self {
            script: Some(script_hex.into()),
            ..Self::default()
        }
    }

    /// Where the output goes.
    pub fn destination(&self) -> Result<Destination, PolicyError> {
        match (&self.party, &self.address, &self.script) {
            (Some(party), None, None) => Ok(Destination::Party(*party)),
            (None, Some(address), None) => address_script(address).map(Destination::Script),
            (None, None, Some(script)) => script_hex(script).map(Destination::Script),
            _ => Err(PolicyError(
                "a pay entry needs exactly one of party, address and script".to_owned(),
            )),
        }
    }

    fn validate(&self, place: &str) -> Result<(), PolicyError> {
        self.destination()
            .map_err(|error| PolicyError(format!("{place}: {error}")))?;
        if self.value_sat.is_some() && self.min_value_sat.is_some() {
            return Err(PolicyError(format!(
                "{place}: give value_sat or min_value_sat, not both"
            )));
        }
        Ok(())
    }
}

/// The script an address pays, in hex. The address's network is not checked.
pub fn address_script(address: &str) -> Result<String, PolicyError> {
    Address::<NetworkUnchecked>::from_str(address.trim())
        .map(|address| hex::encode(address.assume_checked().script_pubkey().as_bytes()))
        .map_err(|error| PolicyError(format!("{address:?} is not an address: {error}")))
}

/// A script given in hex, normalized to lowercase.
pub fn script_hex(script: &str) -> Result<String, PolicyError> {
    let bytes = hex::decode(script.trim())
        .map_err(|error| PolicyError(format!("{script:?} is not a hex script: {error}")))?;
    if bytes.is_empty() {
        return Err(PolicyError("a script cannot be empty".to_owned()));
    }
    Ok(hex::encode(ScriptBuf::from_bytes(bytes).as_bytes()))
}

/// A payout destination given as an address or a script in hex, as a script in hex.
pub fn destination_script(text: &str) -> Result<String, PolicyError> {
    address_script(text).or_else(|address_error| {
        script_hex(text).map_err(|_| {
            PolicyError(format!(
                "{text:?} is neither an address nor a hex script ({address_error})"
            ))
        })
    })
}

/// An oracle key as 32 x-only bytes in hex. Accepts x-only (32-byte) and compressed (33-byte)
/// keys.
pub fn oracle_key(key: &str) -> Result<String, PolicyError> {
    let bytes = hex::decode(key.trim())
        .map_err(|error| PolicyError(format!("oracle key {key:?} is not hex: {error}")))?;
    let x_only = match (bytes.len(), bytes.first()) {
        (32, _) => bytes.as_slice(),
        (33, Some(0x02 | 0x03)) => &bytes[1..],
        _ => {
            return Err(PolicyError(format!(
                "oracle key {key:?} is not a 32-byte x-only or 33-byte compressed key"
            )));
        }
    };
    bitcoin::secp256k1::XOnlyPublicKey::from_slice(x_only)
        .map(|key| key.to_string())
        .map_err(|error| PolicyError(format!("oracle key {key:?} is not on the curve: {error}")))
}

/// A funding key as compressed hex.
pub fn funding_key(key: &str) -> Result<String, PolicyError> {
    bitcoin::secp256k1::PublicKey::from_str(key.trim())
        .map(|key| key.to_string())
        .map_err(|error| PolicyError(format!("funding key {key:?} is not a public key: {error}")))
}

impl Policy {
    /// An empty policy (it checks nothing) with the schema set.
    pub fn new(name: Option<String>) -> Self {
        Self {
            schema: POLICY_SCHEMA.to_owned(),
            name,
            ..Self::default()
        }
    }

    /// Reads a policy from TOML or JSON (text starting with `{`) and validates it.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let policy: Self = if text.trim_start().starts_with('{') {
            serde_json::from_str(text)
                .map_err(|error| PolicyError(format!("invalid JSON policy: {error}")))?
        } else {
            toml::from_str(text)
                .map_err(|error| PolicyError(format!("invalid TOML policy: {error}")))?
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Checks that every value in the policy is well formed.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != POLICY_SCHEMA {
            return Err(PolicyError(format!(
                "schema is {:?}; expected {POLICY_SCHEMA:?}",
                self.schema
            )));
        }
        if let Some(network) = &self.network
            && parse_network(network).is_none()
        {
            return Err(PolicyError(format!(
                "network {network:?} is not mainnet, testnet, testnet4, signet or regtest"
            )));
        }
        for (place, party) in [("offerer", &self.offerer), ("accepter", &self.accepter)] {
            let Some(party) = party else { continue };
            if let Some(key) = &party.funding_pubkey {
                funding_key(key).map_err(|error| PolicyError(format!("{place}: {error}")))?;
            }
            if let Some(payout) = &party.payout {
                destination_script(payout)
                    .map_err(|error| PolicyError(format!("{place}.payout: {error}")))?;
            }
        }
        if let Some(oracle) = &self.oracle {
            for key in oracle.pubkeys.iter().flatten() {
                oracle_key(key)?;
            }
            if oracle.threshold == Some(0) {
                return Err(PolicyError("oracle.threshold cannot be 0".to_owned()));
            }
        }
        if let Some(refund) = &self.refund {
            if refund.pay.is_empty() {
                return Err(PolicyError(
                    "refund.pay must list at least one output".to_owned(),
                ));
            }
            for (index, pay) in refund.pay.iter().enumerate() {
                pay.validate(&format!("refund.pay[{index}]"))?;
            }
        }
        for (index, rule) in self.cets.iter().enumerate() {
            let place = format!("cets[{index}]");
            match (&rule.outcome, &rule.values) {
                (Some(_), None) => {}
                (None, Some([first, last])) => {
                    if first > last {
                        return Err(PolicyError(format!(
                            "{place}: values [{first}, {last}] run backwards"
                        )));
                    }
                }
                _ => {
                    return Err(PolicyError(format!(
                        "{place}: give exactly one of outcome and values"
                    )));
                }
            }
            if rule.pay.is_empty() {
                return Err(PolicyError(format!(
                    "{place}.pay must list at least one output"
                )));
            }
            for (pay_index, pay) in rule.pay.iter().enumerate() {
                pay.validate(&format!("{place}.pay[{pay_index}]"))?;
            }
        }
        Ok(())
    }

    /// The policy as pretty JSON.
    pub fn to_json(&self) -> Result<String, PolicyError> {
        serde_json::to_string_pretty(self).map_err(|error| PolicyError(error.to_string()))
    }
}
