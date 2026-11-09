# Test vectors

Each file is a signed DLC made with `ddk::contract` by [`tools/fixture-gen`](../tools/fixture-gen).
Generation runs DDK's own `verify_signed_contract`, so every vector here verifies under DDK.

```sh
cargo run -p fixture-gen -- fixtures
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

## Fields

- `offer`, `accept`, `sign`: the messages in hex, with their type prefixes. Any tool that reads a
  JSON bundle reads these files directly.
- `network`: the network the offer's chain hash names.
- `now`: a unix time between the accept and the CET locktime, for time-dependent checks.
- `offerer_funding_pubkey`, `accepter_funding_pubkey`: the parties' funding keys.
- `funding_transaction`: the fully signed funding transaction.
- `attestations`: oracle attestations for one outcome (`hex` is the TLV-encoded attestation), for
  settlement tests. `enum-refund-to-accepter` has none.
