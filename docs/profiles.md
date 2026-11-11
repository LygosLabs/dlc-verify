# Profiles

A [policy file](policy.md) states every term of a contract by hand. A profile builds that policy
for one kind of deal from a short terms file. dlc-verify ships two:

| Profile | Deal |
|---|---|
| `lygos-loan` | A Lygos loan settled by the loan oracle (Magnolia or Chainlink) |
| `lygos-midnight` | A Lygos Midnight loan, where a liquidation pays the liquidator named by the oracle |

```sh
dlc-verify verify messages.json --profile lygos-midnight --terms terms.toml
```

`--profile` and `--policy` cannot be combined. Without `--terms`, a profile checks only the shape
every deal of that kind has (outcomes, who each one pays, flags, locktimes); add terms to check
the amounts, keys and addresses of your deal.

To see the policy a profile builds, or to start a hand-written policy from it:

```sh
dlc-verify profile lygos-midnight --terms terms.toml > policy.json
dlc-verify verify messages.json --policy policy.json
```

When a profile cannot check something, for example because the terms leave out the maturity a
Midnight key is chosen by, it says so on stderr (`dlc-verify: lygos-midnight: ...`) and skips that
check.

Terms files are TOML or JSON, read the same way as policy files: unknown fields are errors and
every field is optional. Worked examples are in [`fixtures/terms`](../fixtures/terms).

## Roles

The core reports only the offerer and the accepter. In both Lygos profiles:

- the **borrower** is the offerer and funds all the collateral;
- the **lender** (Lygos) is the accepter and funds nothing.

## `lygos-loan`

| Outcome | Pays the whole collateral to |
|---|---|
| `not-paid` | borrower |
| `repaid` | borrower |
| `liquidated-by-maturation-date` | lender |
| `liquidated-by-price-threshold` | lender |
| `updated` (rollovers; set `rollover = false` to leave it out) | lender |

Every CET must be one of these. The refund unlocks exactly 7 days after the oracle event matures
and pays the borrower, or the lender when `refund_to_accepter = true` (contract flag `0x01`). No
unknown TLVs are allowed, and the contract uses one oracle.

| Term | Checks |
|---|---|
| `network` | The offer's chain hash (`mainnet`, `testnet`, `testnet4`, `signet`, `regtest`) |
| `collateral_sat` | The total collateral, the borrower's share and every payout's value |
| `oracle` | The oracle's key, by registry name (see `dlc-verify oracles`) |
| `oracle_pubkeys` | The oracle's key, given directly (instead of `oracle`) |
| `event_id` | The oracle event id |
| `maturity` | The oracle event's maturity, Unix seconds |
| `refund_to_accepter` | The refund pays the lender (default `false`) |
| `rollover` | The oracle can attest `updated` (default `true`) |
| `max_fee_rate_per_vb` | The fee rate is at most this |
| `[borrower]`, `[lender]` | `funding_pubkey` and `payout` (address or `0x` script) of each party |

With neither `oracle` nor `oracle_pubkeys`, the key must be one of the registry keys the profile
trusts (every `lygos-loan` oracle in the registry).

## `lygos-midnight`

The Midnight oracle names one event per loan. Its outcomes are:

| Outcome | Pays the whole collateral to |
|---|---|
| `not-minted` (first mints only; set `first_mint = false` for a successor loan) | borrower |
| `released` | borrower |
| `liquidated-by-0x<liquidator>`, one per liquidator, ascending | that liquidator's Bitcoin payout |

A liquidation pays the liquidator through a payout-script override (TLV 65005, the only unknown
TLV allowed); a liquidator whose payout is the lender's own script needs no override. The CETs
have no locktime. The refund pays the lender (contract flag `0x01`) and unlocks at least 14 days
after the market matures.

| Term | Checks |
|---|---|
| `network`, `collateral_sat`, `max_fee_rate_per_vb`, `[borrower]`, `[lender]` | As for `lygos-loan` |
| `maturity` | The market's maturity, which is the oracle event's maturity |
| `first_mint` | The event has a `not-minted` outcome (default `true`) |
| `oracle`, `oracle_pubkeys` | The oracle's key, as for `lygos-loan` |
| `[[liquidators]]` | `address` (EVM) and `payout` (Bitcoin address or `0x` script) of each liquidator |
| `[event]` | The terms the event id commits to (below) |

With liquidators listed, every CET must be one of the outcomes above, so a liquidator the terms
do not name fails `policy.cet-coverage`. Without them, the liquidation CETs are not checked.

With neither `oracle` nor `oracle_pubkeys`, the key must be the registry's Midnight key for the UTC
quarter of `maturity`. Midnight keys are not in the registry yet; until they are, give the key
with `oracle_pubkeys`.

### Event ids

A Midnight event id is `midnight-<DDMMMYY>-<sha256>`: the maturity as a UTC date (`25DEC26`), then
the SHA-256 of the loan's terms joined with `//`:

```text
lygos-midnight-v1 // chain id // originator // market id // request id
                  // liquidators, ascending, joined with "," // controller
                  // mint deadline // announced at
```

Integers are decimal, EVM values lowercase `0x` hex (the market id padded to 32 bytes) and the
request id a lowercase hyphenated UUID. Give these under `[event]` and the profile checks the
contract's event id is the one these terms produce, so the oracle can only attest the loan you
agreed to:

```toml
maturity = 1767225600

[event]
chain_id = 8453
originator = "0x5656565656565656565656565656565656565656"
market_id = "0xabababababababababababababababababababababababababababababababab"
request_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
controller = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
mint_deadline = 1764633600
announced_at = 1767052800
```

The event id needs `maturity` and at least one liquidator. The implementation is pinned to the
Midnight oracle's golden vectors
([`crates/dlc-verify-policy/tests/data/midnight-vectors.json`](../crates/dlc-verify-policy/tests/data/midnight-vectors.json)).

## Oracle registry

The registry names the oracle keys dlc-verify knows. It is compiled in from
[`crates/dlc-verify-policy/src/registry.toml`](../crates/dlc-verify-policy/src/registry.toml):

```sh
dlc-verify oracles                 # name, key, provider, network, quarter, profiles
dlc-verify oracles --format json
```

| Field | Meaning |
|---|---|
| `name` | The name terms files use in `oracle` |
| `provider` | Who runs the oracle |
| `pubkey` | The 32-byte x-only key, lowercase hex |
| `profiles` | The profiles that trust this key when the terms name no oracle |
| `network` | The network the oracle attests for |
| `quarter` | Midnight only: the UTC quarter (`YYYYQn`) of the maturities this key signs |
| `description` | Free text |

## Library use

```rust
use dlc_verify_policy::{Profile, profile_policy};

let built = profile_policy(Profile::LygosMidnight, Some(&terms_text))?;
for note in &built.notes {
    eprintln!("{note}");
}
let report = dlc_verify_policy::report_with_policy(&built.policy, &verification);
```

`dlc_verify_policy::midnight` has the event id functions and `dlc_verify_policy::registry` the
registry.
