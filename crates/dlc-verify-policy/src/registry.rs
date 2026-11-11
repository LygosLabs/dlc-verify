//! Oracle public keys dlc-verify knows by name.
//!
//! The registry ships inside the crate (`src/registry.toml`). Profiles use it to fill in the
//! oracle keys a contract may use when the terms name an oracle, or name none.

use serde::{Deserialize, Serialize};

use crate::schema::{PolicyError, oracle_key};

const REGISTRY_TOML: &str = include_str!("registry.toml");

/// One oracle key in the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleEntry {
    /// The name profiles and terms files use, such as `magnolia-mainnet`.
    pub name: String,
    /// Who runs the oracle.
    pub provider: String,
    /// The oracle's x-only public key, in hex.
    pub pubkey: String,
    /// The profiles that trust this key when the terms name no oracle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// The network the oracle attests for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// For oracles that rotate keys by calendar quarter (Midnight): the UTC quarter, `YYYYQn`,
    /// of the event maturities this key signs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarter: Option<String>,
    /// What the oracle is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    #[serde(default)]
    oracle: Vec<OracleEntry>,
}

/// Every oracle in the registry, in file order.
pub fn registry() -> Result<Vec<OracleEntry>, PolicyError> {
    parse_registry(REGISTRY_TOML)
}

/// The registry entry named `name`.
pub fn registry_entry(name: &str) -> Result<OracleEntry, PolicyError> {
    let entries = registry()?;
    let known = entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    entries
        .iter()
        .find(|entry| entry.name == name)
        .cloned()
        .ok_or_else(|| {
            PolicyError(format!(
                "the oracle registry has no oracle named {name:?} (known: {known})"
            ))
        })
}

/// The registry keys a profile trusts by default.
pub fn profile_oracles(profile: &str) -> Result<Vec<OracleEntry>, PolicyError> {
    Ok(registry()?
        .into_iter()
        .filter(|entry| entry.profiles.iter().any(|name| name == profile))
        .collect())
}

/// Reads a registry file and checks every entry.
pub fn parse_registry(text: &str) -> Result<Vec<OracleEntry>, PolicyError> {
    let file: RegistryFile = toml::from_str(text)
        .map_err(|error| PolicyError(format!("invalid oracle registry: {error}")))?;
    let mut names = std::collections::BTreeSet::new();
    for entry in &file.oracle {
        if !names.insert(entry.name.as_str()) {
            return Err(PolicyError(format!(
                "the oracle registry names {:?} twice",
                entry.name
            )));
        }
        let key = oracle_key(&entry.pubkey)
            .map_err(|error| PolicyError(format!("oracle registry {:?}: {error}", entry.name)))?;
        if key != entry.pubkey {
            return Err(PolicyError(format!(
                "oracle registry {:?}: write the key as 32-byte lowercase x-only hex",
                entry.name
            )));
        }
        if let Some(quarter) = &entry.quarter
            && !is_quarter(quarter)
        {
            return Err(PolicyError(format!(
                "oracle registry {:?}: quarter {quarter:?} is not YYYYQn",
                entry.name
            )));
        }
    }
    Ok(file.oracle)
}

fn is_quarter(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 6
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'Q'
        && matches!(bytes[5], b'1'..=b'4')
}
