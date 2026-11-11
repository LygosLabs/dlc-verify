//! Profiles: policies for a known kind of contract, built from a few deal terms.
//!
//! A profile knows the shape of one product's contracts: who funds them, which outcomes pay
//! whom, which flags and locktimes it uses and which oracles sign it. You supply what you know
//! about your own deal (all optional) and the profile writes the [`Policy`]. `docs/profiles.md`
//! describes the terms.
//!
//! - [`Profile::LygosLoan`]: a Lygos loan settled by the Magnolia or Chainlink loan oracle.
//! - [`Profile::LygosMidnight`]: a Lygos loan on a Midnight market, where a liquidation pays
//!   the liquidator through a payout-script override.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::midnight::{
    MIDNIGHT_REFUND_DELAY_MIN, MidnightEvent, evm_address, liquidation_outcome, midnight_event_id,
    quarter, sorted_liquidators,
};
use crate::registry::{profile_oracles, registry_entry};
use crate::schema::{
    CetRule, LocktimePolicy, OraclePolicy, POLICY_SCHEMA, Party, PartyPolicy, Pay, Policy,
    PolicyError, RefundRule, destination_script,
};

/// The refund delay of a Lygos loan: seven days after the oracle event matures.
pub const LOAN_REFUND_DELAY: u64 = 7 * 86_400;

/// The TLV type of DDK's payout-script override.
const PAYOUT_SCRIPT_OVERRIDE_TLV: u64 = 65_005;

/// A known kind of contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// A Lygos loan settled by the Magnolia or Chainlink loan oracle.
    LygosLoan,
    /// A Lygos loan on a Midnight market.
    LygosMidnight,
}

impl Profile {
    /// Every profile.
    pub const ALL: [Self; 2] = [Self::LygosLoan, Self::LygosMidnight];

    /// The profile's name, as `--profile` takes it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::LygosLoan => "lygos-loan",
            Self::LygosMidnight => "lygos-midnight",
        }
    }

    /// One line on what the profile checks.
    pub const fn about(self) -> &'static str {
        match self {
            Self::LygosLoan => {
                "Lygos loan: the borrower (offerer) funds the collateral; not-paid and repaid pay \
                 the borrower, liquidations and rollovers pay the lender; refund 7 days after \
                 maturity"
            }
            Self::LygosMidnight => {
                "Lygos Midnight loan: the borrower (offerer) funds the collateral; not-minted and \
                 released pay the borrower, each liquidation pays its liquidator; refund to the \
                 lender at least 14 days after the market's maturity"
            }
        }
    }

    /// The profile named `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.name() == name.trim())
    }
}

/// A profile's policy, and what the profile could not check from the terms given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfilePolicy {
    /// The policy to evaluate.
    pub policy: Policy,
    /// Terms the profile could not turn into checks, such as an oracle key it does not know.
    pub notes: Vec<String>,
}

/// One party's terms.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartyTerms {
    /// The party's funding public key, compressed, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_pubkey: Option<String>,
    /// Where the party is paid: an address or a script in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout: Option<String>,
}

/// A party's policy from its terms, or nothing when there is nothing to check.
fn party_policy(terms: Option<&PartyTerms>, collateral_sat: Option<u64>) -> Option<PartyPolicy> {
    let terms = terms.cloned().unwrap_or_default();
    let policy = PartyPolicy {
        funding_pubkey: terms.funding_pubkey,
        payout: terms.payout,
        collateral_sat,
    };
    (policy != PartyPolicy::default()).then_some(policy)
}

/// The terms of a Lygos loan. Every field is optional.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoanTerms {
    /// The network the offer's chain hash must name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// The collateral, in sats. The borrower funds all of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_sat: Option<u64>,
    /// The oracle, by registry name (`magnolia-mainnet`, `magnolia-testnet`,
    /// `chainlink-testnet4`). Without it or `oracle_pubkeys`, any loan oracle in the registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<String>,
    /// The oracle keys the contract may use, in place of `oracle`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_pubkeys: Option<Vec<String>>,
    /// The loan's oracle event id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// The loan's maturity, Unix seconds: when the oracle event matures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maturity: Option<u64>,
    /// The refund pays the lender (contract flag `0x01`) instead of the borrower.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refund_to_accepter: bool,
    /// The event has the `updated` outcome, which settles a rollover. Defaults to true; set it
    /// to false for loans made before rollovers existed.
    #[serde(default = "yes")]
    pub rollover: bool,
    /// The highest acceptable fee rate, in sat/vB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_rate_per_vb: Option<u64>,
    /// The borrower, who makes the offer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrower: Option<PartyTerms>,
    /// The lender, who accepts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lender: Option<PartyTerms>,
}

/// One liquidator of a Midnight loan.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidatorTerms {
    /// The liquidator's EVM address, as the oracle's outcome names it.
    pub address: String,
    /// Where the liquidator is paid on Bitcoin: an address or a script in hex.
    pub payout: String,
}

/// The terms of a Lygos Midnight loan. Every field is optional.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MidnightTerms {
    /// The network the offer's chain hash must name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// The collateral, in sats. The borrower funds all of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_sat: Option<u64>,
    /// The market's maturity, Unix seconds: when the oracle event matures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maturity: Option<u64>,
    /// The loan is its borrower's first mint on the market, so the event has a `not-minted`
    /// outcome. A successor loan's does not. Defaults to true.
    #[serde(default = "yes")]
    pub first_mint: bool,
    /// The oracle, by registry name. Without it or `oracle_pubkeys`, the registry's Midnight key
    /// for the maturity's quarter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<String>,
    /// The oracle keys the contract may use, in place of `oracle`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_pubkeys: Option<Vec<String>>,
    /// The highest acceptable fee rate, in sat/vB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_rate_per_vb: Option<u64>,
    /// The borrower, who makes the offer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrower: Option<PartyTerms>,
    /// The lender (Lygos), who accepts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lender: Option<PartyTerms>,
    /// Every liquidator the event names, with their Bitcoin payout.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub liquidators: Vec<LiquidatorTerms>,
    /// The terms the event id commits to. With them the profile checks the event id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<MidnightEvent>,
}

const fn yes() -> bool {
    true
}

impl Default for LoanTerms {
    fn default() -> Self {
        Self {
            network: None,
            collateral_sat: None,
            oracle: None,
            oracle_pubkeys: None,
            event_id: None,
            maturity: None,
            refund_to_accepter: false,
            rollover: true,
            max_fee_rate_per_vb: None,
            borrower: None,
            lender: None,
        }
    }
}

impl Default for MidnightTerms {
    fn default() -> Self {
        Self {
            network: None,
            collateral_sat: None,
            maturity: None,
            first_mint: true,
            oracle: None,
            oracle_pubkeys: None,
            max_fee_rate_per_vb: None,
            borrower: None,
            lender: None,
            liquidators: Vec::new(),
            event: None,
        }
    }
}

/// Builds `profile`'s policy from a terms file (TOML, or JSON starting with `{`), or from no
/// terms at all.
pub fn profile_policy(profile: Profile, terms: Option<&str>) -> Result<ProfilePolicy, PolicyError> {
    match profile {
        Profile::LygosLoan => lygos_loan(&parse_terms(terms)?),
        Profile::LygosMidnight => lygos_midnight(&parse_terms(terms)?),
    }
}

fn parse_terms<T: DeserializeOwned + Default>(text: Option<&str>) -> Result<T, PolicyError> {
    let Some(text) = text else {
        return Ok(T::default());
    };
    if text.trim_start().starts_with('{') {
        serde_json::from_str(text)
            .map_err(|error| PolicyError(format!("invalid JSON terms: {error}")))
    } else {
        toml::from_str(text).map_err(|error| PolicyError(format!("invalid TOML terms: {error}")))
    }
}

/// The policy of a Lygos loan.
///
/// The borrower offers and funds the whole collateral; the lender accepts with none. The
/// outcomes `not-paid` and `repaid` pay the borrower; `liquidated-by-maturation-date`,
/// `liquidated-by-price-threshold` and `updated` (a rollover; see [`LoanTerms::rollover`]) pay
/// the lender. The refund
/// unlocks seven days after maturity and pays the borrower, or the lender with
/// `refund_to_accepter`. No payout-script overrides.
pub fn lygos_loan(terms: &LoanTerms) -> Result<ProfilePolicy, PolicyError> {
    let profile = Profile::LygosLoan;
    let mut notes = Vec::new();
    let collateral = terms.collateral_sat;
    let pay = |party| Pay {
        value_sat: collateral,
        ..Pay::party(party)
    };
    let pubkeys = oracle_pubkeys(
        profile,
        terms.oracle.as_deref(),
        terms.oracle_pubkeys.as_ref(),
        None,
        &mut notes,
    )?;
    let mut outcomes = vec![
        ("not-paid", Party::Offerer),
        ("repaid", Party::Offerer),
        ("liquidated-by-maturation-date", Party::Accepter),
        ("liquidated-by-price-threshold", Party::Accepter),
    ];
    if terms.rollover {
        outcomes.push(("updated", Party::Accepter));
    }
    let mut cets = Vec::new();
    for (outcome, party) in outcomes {
        cets.push(CetRule {
            outcome: Some(outcome.to_owned()),
            pay: vec![pay(party)],
            ..CetRule::default()
        });
    }
    let refund_party = if terms.refund_to_accepter {
        Party::Accepter
    } else {
        Party::Offerer
    };
    let policy = Policy {
        schema: POLICY_SCHEMA.to_owned(),
        name: Some(profile.name().to_owned()),
        network: terms.network.clone(),
        total_collateral_sat: collateral,
        max_fee_rate_per_vb: terms.max_fee_rate_per_vb,
        contract_flags: Some(if terms.refund_to_accepter {
            vec!["refund-to-accepter".to_owned()]
        } else {
            Vec::new()
        }),
        allowed_tlvs: Some(Vec::new()),
        offerer: party_policy(terms.borrower.as_ref(), collateral),
        accepter: party_policy(terms.lender.as_ref(), Some(0)),
        oracle: Some(OraclePolicy {
            pubkeys,
            event_ids: terms.event_id.clone().map(|id| vec![id]),
            maturity: terms.maturity,
            threshold: Some(1),
        }),
        locktimes: Some(LocktimePolicy {
            refund_delay: Some(LOAN_REFUND_DELAY),
            ..LocktimePolicy::default()
        }),
        refund: Some(RefundRule {
            pay: vec![pay(refund_party)],
        }),
        cets,
        require_every_cet: true,
    };
    policy.validate()?;
    Ok(ProfilePolicy { policy, notes })
}

/// The policy of a Lygos Midnight loan.
///
/// The borrower offers and funds the whole collateral; Lygos accepts with none. The event's
/// outcomes are `not-minted` (first mints only) and `released`, which pay the borrower, then
/// `liquidated-by-<address>` for each liquidator, which pays that liquidator's Bitcoin payout
/// through a payout-script override (TLV 65005). The CETs have no locktime. The refund pays
/// Lygos (contract flag `0x01`) at least 14 days after the market's maturity.
pub fn lygos_midnight(terms: &MidnightTerms) -> Result<ProfilePolicy, PolicyError> {
    let profile = Profile::LygosMidnight;
    let mut notes = Vec::new();
    let collateral = terms.collateral_sat;
    let pay = |pay: Pay| Pay {
        value_sat: collateral,
        ..pay
    };

    let mut liquidators = terms
        .liquidators
        .iter()
        .map(|liquidator| {
            let address = evm_address(&liquidator.address)?;
            let script = destination_script(&liquidator.payout)
                .map_err(|error| PolicyError(format!("liquidator {address} payout: {error}")))?;
            Ok((address, script))
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    liquidators.sort();
    // Checks for duplicates and the limit; the order matches `liquidators`.
    let addresses = sorted_liquidators(liquidators.iter().map(|(address, _)| address.as_str()))?;

    let event_ids = match &terms.event {
        Some(event) => {
            let maturity = terms.maturity.ok_or_else(|| {
                PolicyError("event needs maturity: the event id is labelled with it".to_owned())
            })?;
            Some(vec![midnight_event_id(event, &addresses, maturity)?])
        }
        None => None,
    };
    let pubkeys = oracle_pubkeys(
        profile,
        terms.oracle.as_deref(),
        terms.oracle_pubkeys.as_ref(),
        terms.maturity,
        &mut notes,
    )?;

    let mut cets = Vec::new();
    let mut borrower_outcomes = vec!["released"];
    if terms.first_mint {
        borrower_outcomes.insert(0, "not-minted");
    }
    for outcome in borrower_outcomes {
        cets.push(CetRule {
            outcome: Some(outcome.to_owned()),
            pay: vec![pay(Pay::party(Party::Offerer))],
            ..CetRule::default()
        });
    }
    for (address, script) in &liquidators {
        cets.push(CetRule {
            outcome: Some(liquidation_outcome(address)),
            pay: vec![pay(Pay::script(script.clone()))],
            ..CetRule::default()
        });
    }
    if liquidators.is_empty() {
        notes.push(
            "no liquidators given: the liquidation CETs are not checked; list them under \
             [[liquidators]]"
                .to_owned(),
        );
    }

    let policy = Policy {
        schema: POLICY_SCHEMA.to_owned(),
        name: Some(profile.name().to_owned()),
        network: terms.network.clone(),
        total_collateral_sat: collateral,
        max_fee_rate_per_vb: terms.max_fee_rate_per_vb,
        contract_flags: Some(vec!["refund-to-accepter".to_owned()]),
        allowed_tlvs: Some(vec![PAYOUT_SCRIPT_OVERRIDE_TLV]),
        offerer: party_policy(terms.borrower.as_ref(), collateral),
        accepter: party_policy(terms.lender.as_ref(), Some(0)),
        oracle: Some(OraclePolicy {
            pubkeys,
            event_ids,
            maturity: terms.maturity,
            threshold: Some(1),
        }),
        locktimes: Some(LocktimePolicy {
            cet: Some(0),
            refund_delay_min: Some(MIDNIGHT_REFUND_DELAY_MIN),
            ..LocktimePolicy::default()
        }),
        refund: Some(RefundRule {
            pay: vec![pay(Pay::party(Party::Accepter))],
        }),
        cets,
        require_every_cet: !liquidators.is_empty(),
    };
    policy.validate()?;
    Ok(ProfilePolicy { policy, notes })
}

/// The oracle keys a profile accepts: the named registry oracle, the keys given, or the
/// registry's defaults for the profile (for Midnight, the key of the maturity's quarter).
fn oracle_pubkeys(
    profile: Profile,
    oracle: Option<&str>,
    pubkeys: Option<&Vec<String>>,
    quarter_of: Option<u64>,
    notes: &mut Vec<String>,
) -> Result<Option<Vec<String>>, PolicyError> {
    match (oracle, pubkeys) {
        (Some(_), Some(_)) => Err(PolicyError(
            "give oracle or oracle_pubkeys, not both".to_owned(),
        )),
        (Some(name), None) => Ok(Some(vec![registry_entry(name)?.pubkey])),
        (None, Some(keys)) => Ok(Some(keys.clone())),
        (None, None) => {
            let mut entries = profile_oracles(profile.name())?;
            if profile == Profile::LygosMidnight {
                let Some(maturity) = quarter_of else {
                    notes.push(
                        "no maturity given: the oracle key is not checked; Midnight keys are per \
                         quarter of the maturity"
                            .to_owned(),
                    );
                    return Ok(None);
                };
                let wanted = quarter(maturity);
                entries.retain(|entry| entry.quarter.as_deref() == Some(wanted.as_str()));
                if entries.is_empty() {
                    notes.push(format!(
                        "the registry has no Midnight oracle key for {wanted}: the oracle key is \
                         not checked; give it with oracle_pubkeys"
                    ));
                    return Ok(None);
                }
            }
            if entries.is_empty() {
                notes.push(format!(
                    "the registry has no oracle for {}: the oracle key is not checked",
                    profile.name()
                ));
                return Ok(None);
            }
            Ok(Some(
                entries.into_iter().map(|entry| entry.pubkey).collect(),
            ))
        }
    }
}
