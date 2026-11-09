# Test vectors

Each file is a signed DLC made with `ddk::contract` by [`tools/fixture-gen`](../tools/fixture-gen).
Generation runs DDK's own `verify_signed_contract`, so every vector here verifies under DDK.

```sh
cargo run -p fixture-gen -- fixtures                        # every vector
cargo run -p fixture-gen -- fixtures midnight-liquidator    # just the named ones
```

Keys, scripts, serial ids and temporary contract ids are fixed. CET adaptor signatures use fresh
randomness, so regenerating changes their bytes and everything derived from them (the contract id
and the funding transaction's witnesses stay the same; the sign message changes).

| Vector | Shape |
|---|---|
| `enum-dual-funded` | Enum outcomes `up`/`down`/`flat`, one oracle, both parties fund half |
| `enum-single-funded` | Offerer funds everything; the accepter has no inputs. Mainnet chain hash |
| `enum-refund-to-accepter` | Contract flag `0x01`: the refund pays all collateral to the accepter. Testnet4 |
| `enum-payout-override` | TLV 65005 sends the accepter's `down` payout to a third-party script |
| `numeric-dual-funded` | 10-digit binary oracle event, piecewise-linear payout, 10,000-sat rounding |
| `numeric-payout-override` | TLV 65005 on the lowest numeric CET |
| `enum-multi-oracle` | 2-of-3 oracles |
| `disjoint-enum-numeric` | Two contract infos: an enum one and a numeric one |
| `midnight-liquidator` | A Midnight loan: the offerer funds everything, flag `0x01`, CET locktime 0, refund 14 days after maturity, a `midnight-…` event whose `liquidated-by-0x1111…` CET pays a third party through TLV 65005 |

## Fields

- `offer`, `accept`, `sign`: the messages in hex, with their type prefixes. Any tool that reads a
  JSON bundle reads these files directly.
- `network`: the network the offer's chain hash names.
- `now`: a unix time between the accept and the CET locktime, for time-dependent checks.
- `offerer_funding_pubkey`, `accepter_funding_pubkey`: the parties' funding keys.
- `funding_transaction`: the fully signed funding transaction.
- `attestations`: oracle attestations for one outcome (`hex` is the TLV-encoded attestation), for
  settlement tests and `dlc-verify settle` (see [docs/settle.md](../docs/settle.md)).
  `enum-refund-to-accepter` has none.

## Policies

`policies/enum-payout-override.toml` and `policies/numeric-payout-override.json` state every term
of those two vectors, in the two policy formats; `dlc-verify verify --policy` passes each against
its vector. See [docs/policy.md](../docs/policy.md).

## Terms

`terms/` holds [profile](../docs/profiles.md) terms files: `midnight-liquidator.toml` for the
`lygos-midnight` profile and `testnet-loan-118c9fc9.toml` for the `lygos-loan` profile against
`examples/testnet-loan-118c9fc9.json`.

## Report snapshots

`reports/<vector>.json` and `reports/<vector>.txt` are the `dlc-verify verify --format json` and
text reports of each vector at its `now`. `crates/dlc-verify-core/tests/report.rs` compares them;
after an intended change to the report, rewrite them with:

```sh
UPDATE_SNAPSHOTS=1 cargo test -p dlc-verify-core --test report
```
