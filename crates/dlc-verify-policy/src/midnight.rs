//! Midnight oracle event names, as the Midnight oracle announces them.
//!
//! A Midnight event is named `midnight-<DDMMMYY>-<digest>`: the market maturity as a UTC date,
//! then the SHA-256 of the loan's terms. The terms are canonical strings joined with `//`:
//!
//! ```text
//! lygos-midnight-v1 // chain id // originator // market id // request id
//!                   // liquidators, ascending, joined with "," // controller
//!                   // mint deadline // announced at
//! ```
//!
//! Integers are decimal, EVM values are lowercase `0x` hex, and the request id is a lowercase
//! hyphenated UUID.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::PolicyError;

/// The refund must unlock at least this long after the market's maturity.
pub const MIDNIGHT_REFUND_DELAY_MIN: u64 = 14 * 86_400;

/// The most liquidators one Midnight outcome list names.
pub const MAX_LIQUIDATORS: usize = 100;

/// The terms a Midnight event id commits to, other than the liquidators.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MidnightEvent {
    /// The EVM chain id of the Midnight deployment.
    pub chain_id: u64,
    /// The originator contract address, `0x` and 40 hex digits.
    pub originator: String,
    /// The market id, 32 bytes of hex (`0x` optional).
    pub market_id: String,
    /// The loan request id, a lowercase hyphenated UUID.
    pub request_id: String,
    /// The controller address, `0x` and 40 hex digits.
    pub controller: String,
    /// The mint deadline, Unix seconds.
    pub mint_deadline: u64,
    /// When the oracle announced the event, Unix seconds.
    pub announced_at: u64,
}

/// An EVM address as Midnight writes it: `0x` and 40 lowercase hex digits.
pub fn evm_address(text: &str) -> Result<String, PolicyError> {
    evm_hex(text, 20).map_err(|_| PolicyError(format!("{text:?} is not an EVM address")))
}

fn evm_hex(text: &str, len: usize) -> Result<String, PolicyError> {
    let digits = text.trim();
    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .unwrap_or(digits);
    let bytes = hex::decode(digits).map_err(|error| PolicyError(error.to_string()))?;
    if bytes.len() != len {
        return Err(PolicyError(format!("expected {len} bytes")));
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Liquidator addresses, normalized and in the ascending order the outcome list uses.
pub fn sorted_liquidators<'a>(
    addresses: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, PolicyError> {
    let mut liquidators = addresses
        .into_iter()
        .map(evm_address)
        .collect::<Result<Vec<_>, _>>()?;
    liquidators.sort();
    if let Some(pair) = liquidators.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(PolicyError(format!(
            "liquidator {} is listed twice",
            pair[0]
        )));
    }
    if liquidators.len() > MAX_LIQUIDATORS {
        return Err(PolicyError(format!(
            "{} liquidators; a Midnight event names at most {MAX_LIQUIDATORS}",
            liquidators.len()
        )));
    }
    Ok(liquidators)
}

/// The outcome that pays liquidator `address` (already normalized).
pub fn liquidation_outcome(address: &str) -> String {
    format!("liquidated-by-{address}")
}

/// The event's outcomes: `not-minted` (first mints only), `released`, then one liquidation per
/// liquidator, ascending.
pub fn midnight_outcomes(first_mint: bool, liquidators: &[String]) -> Vec<String> {
    let mut outcomes = Vec::with_capacity(liquidators.len() + 2);
    if first_mint {
        outcomes.push("not-minted".to_owned());
    }
    outcomes.push("released".to_owned());
    outcomes.extend(
        liquidators
            .iter()
            .map(|address| liquidation_outcome(address)),
    );
    outcomes
}

/// The string the event digest hashes.
pub fn midnight_preimage(
    event: &MidnightEvent,
    liquidators: &[String],
) -> Result<String, PolicyError> {
    let originator = evm_address(&event.originator)
        .map_err(|error| PolicyError(format!("event.originator: {error}")))?;
    let market_id = evm_hex(&event.market_id, 32).map_err(|_| {
        PolicyError(format!(
            "event.market_id {:?} is not 32 bytes of hex",
            event.market_id
        ))
    })?;
    let controller = evm_address(&event.controller)
        .map_err(|error| PolicyError(format!("event.controller: {error}")))?;
    if !is_request_id(&event.request_id) {
        return Err(PolicyError(format!(
            "event.request_id {:?} is not a lowercase hyphenated UUID",
            event.request_id
        )));
    }
    if liquidators.is_empty() {
        return Err(PolicyError(
            "a Midnight event names at least one liquidator".to_owned(),
        ));
    }
    Ok([
        "lygos-midnight-v1".to_owned(),
        event.chain_id.to_string(),
        originator,
        market_id,
        event.request_id.clone(),
        liquidators.join(","),
        controller,
        event.mint_deadline.to_string(),
        event.announced_at.to_string(),
    ]
    .join("//"))
}

/// The event id the Midnight oracle announces: `midnight-<DDMMMYY>-<sha256 hex>`.
pub fn midnight_event_id(
    event: &MidnightEvent,
    liquidators: &[String],
    maturity: u64,
) -> Result<String, PolicyError> {
    let preimage = midnight_preimage(event, liquidators)?;
    Ok(format!(
        "midnight-{}-{}",
        maturity_label(maturity),
        hex::encode(Sha256::digest(preimage.as_bytes()))
    ))
}

fn is_request_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// A maturity as a UTC date in option-expiry style: `25DEC26`.
pub fn maturity_label(maturity: u64) -> String {
    const MONTHS: [&str; 12] = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];
    let (year, month, day) = utc_date(maturity);
    let month = MONTHS
        .get(usize::from(month).saturating_sub(1))
        .copied()
        .unwrap_or("???");
    format!("{day:02}{month}{:02}", year.rem_euclid(100))
}

/// The UTC calendar quarter of a timestamp: `2026Q4`. Midnight signs every market maturing in a
/// quarter with that quarter's key.
pub fn quarter(timestamp: u64) -> String {
    let (year, month, _) = utc_date(timestamp);
    format!("{year:04}Q{}", (month - 1) / 3 + 1)
}

/// A Unix timestamp's UTC `(year, month, day)`, month and day from 1 (Howard Hinnant's
/// civil-from-days).
fn utc_date(timestamp: u64) -> (i64, u8, u8) {
    let z = i64::try_from(timestamp / 86_400).unwrap_or(i64::MAX / 2) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u8::try_from(month).unwrap_or(1),
        u8::try_from(day).unwrap_or(1),
    )
}
