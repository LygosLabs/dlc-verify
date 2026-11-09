# Policy files

`dlc-verify verify` checks that a set of DLC messages is well formed and correctly signed. It does
not know what you agreed to. A policy file states those terms, and `--policy` checks the contract
against them:

```sh
dlc-verify verify messages.json --policy terms.toml
```

The policy checks are added to the report under `Policy` (text) or `policy` (JSON). The policy's
result is folded into the overall result and the exit code: 0 if everything passes, 1 if a check
fails, 2 if the messages are not enough to run every check, 3 if the policy file is unreadable or
invalid.

Policies are TOML or JSON. A file whose first non-blank character is `{` is read as JSON;
anything else is read as TOML. Unknown fields are rejected, so a misspelt term is an error, not
a term that is silently ignored.

Every field except `schema` is optional. A policy only checks what it states: leave a field out
and its check does not run. Worked examples are in [`fixtures/policies`](../fixtures/policies).

For Lygos loans, a [profile](profiles.md) builds the policy from a short terms file.

## Example

```toml
schema = "dlc-verify.policy.v1"
name = "btc-usd-weekly"
network = "bitcoin"
total_collateral_sat = 1000000
max_fee_rate_per_vb = 25
contract_flags = []
allowed_tlvs = [65005]
require_every_cet = true

[offerer]
funding_pubkey = "02b9061abab4ad98d48f509147c5ad04e08752aaeb9c340247d61b49d11bd7bc29"
payout = "bc1q..."
collateral_sat = 500000

[accepter]
collateral_sat = 500000

[oracle]
pubkeys = ["a8ecd305fc21c765c7fec0eb645192368367f5c6d2efc794f290065d4c2d70bd"]
event_ids = ["btc-usd-2026-01-01"]
maturity = 1767225600
threshold = 1

[locktimes]
cet = 1767225600
refund_delay = 604800        # exactly 7 days after the oracle event matures

[refund]
pay = [{ party = "offerer" }, { party = "accepter" }]

[[cets]]
values = [0, 319]
pay = [{ address = "bc1q...liquidator", value_sat = 1000000 }]

[[cets]]
values = [320, 679]
pay = [{ party = "offerer", min_value_sat = 100000 }, { party = "accepter", min_value_sat = 100000 }]

[[cets]]
values = [680, 1023]
pay = [{ party = "offerer", value_sat = 1000000 }]
```

## Fields

| Field | Type | Check |
|---|---|---|
| `schema` | string | Required. Must be `dlc-verify.policy.v1`. |
| `name` | string | Shown in the report. |
| `network` | string | `policy.network`: the offer's chain hash names this network (`bitcoin` or `mainnet`, `testnet`, `testnet4`, `signet`, `regtest`). |
| `total_collateral_sat` | integer | `policy.collateral`: the offer's total collateral. |
| `offerer`, `accepter` | table | `policy.offerer`, `policy.accepter`: see [Parties](#parties). |
| `max_fee_rate_per_vb` | integer | `policy.fee-rate`: the offer's fee rate is at most this. |
| `contract_flags` | list of strings | `policy.contract-flags`: the offer sets exactly these flags. `[]` means none. The one flag DDK defines is `refund-to-accepter` (`0x01`). |
| `allowed_tlvs` | list of integers | `policy.tlvs`: every TLV record on the offer, accept and sign has one of these types. `[]` allows none. |
| `oracle` | table | `policy.oracle-*`: see [Oracles](#oracles). |
| `locktimes` | table | `policy.cet-locktime`, `policy.refund-locktime`: see [Locktimes](#locktimes). |
| `refund` | table | `policy.refund-payout`: `pay` lists the refund transaction's outputs. |
| `cets` | list of tables | `policy.cet-payouts`: see [CET rules](#cet-rules). |
| `require_every_cet` | boolean | `policy.cet-coverage`: every CET matches a rule in `cets`. |

### Parties

`offerer` and `accepter` take any of:

| Field | Meaning |
|---|---|
| `funding_pubkey` | The party's funding public key (33-byte compressed hex). |
| `payout` | The party's payout script: an address or script hex. Addresses are compared by script, so the address's network prefix is not checked here; use `network` for that. |
| `collateral_sat` | The party's collateral. |

The accepter's terms are in the accept message, so with an offer alone `policy.accepter` is
skipped.

### Oracles

| Field | Check |
|---|---|
| `pubkeys` | `policy.oracle-pubkeys`: every announcement is signed by one of these keys. Keys are 32-byte x-only hex, or 33-byte compressed hex (the parity byte is ignored). |
| `event_ids` | `policy.oracle-events`: every announcement's event id is one of these. |
| `maturity` | `policy.oracle-maturity`: every event matures at this unix time. |
| `threshold` | `policy.oracle-threshold`: every contract info needs this many oracles to attest. |

### Locktimes

| Field | Check |
|---|---|
| `cet` | `policy.cet-locktime`: the CETs' locktime is exactly this. `0` means no lock. |
| `refund` | `policy.refund-locktime`: the refund's locktime is exactly this. |
| `refund_delay` | `policy.refund-locktime`: the refund unlocks exactly this many seconds after the earliest oracle maturity. |
| `refund_delay_min` | `policy.refund-locktime`: the refund unlocks at least this many seconds after the earliest oracle maturity. |

Locktimes follow Bitcoin's rule: below 500,000,000 a locktime is a block height, otherwise a unix
time. A refund delay can only be measured when the refund locktime is a time.

## Payouts

`refund.pay` and each CET rule's `pay` list the transaction's outputs, in any order. The list
must have one entry per output: an output the policy does not list fails the check, and so does
an entry no output matches.

Each entry names exactly one destination:

| Field | Matches |
|---|---|
| `party = "offerer"` | An output to the offerer's payout script. |
| `party = "accepter"` | An output to the accepter's payout script. |
| `party = "third-party"` | An output a payout-script override (TLV `65005`) sent somewhere other than the parties' payout scripts. |
| `address = "..."` | An output to this address's script. |
| `script = "..."` | An output to this script (hex). |

and optionally an amount, either `value_sat` (exactly) or `min_value_sat` (at least). If both
parties use the same payout script, a `shared` output matches either party.

`party = "third-party"` accepts any override destination; name the `address` or `script` to pin
down who the third party is.

### CET rules

A rule picks the CETs it covers with one of:

- `outcome`: an enum outcome, such as `"up"`. It covers the CET for that outcome.
- `values = [first, last]`: an inclusive range of numeric outcomes. It covers each CET whose whole
  range of outcomes lies inside it. A CET that is partly inside the range fails the check, since
  the rule would cover some of its outcomes and not others.

and optionally `contract_info`, the index of the contract info the rule is about, for offers with
more than one.

Every CET a rule covers must pay what the rule's `pay` says. A rule that covers no CET fails, so a
misspelt outcome cannot pass silently. Rules may overlap; a CET then has to satisfy each of them.

`policy.cet-payouts` only checks the CETs some rule covers. Set `require_every_cet = true` to also
fail when a CET is not covered by any rule.

## Checks

The policy checks run in this order:

| Check | Needs |
|---|---|
| `policy.network` | offer |
| `policy.collateral` | offer |
| `policy.offerer` | offer |
| `policy.accepter` | accept |
| `policy.fee-rate` | offer |
| `policy.contract-flags` | offer |
| `policy.tlvs` | offer (and the accept and sign, if given) |
| `policy.oracle-pubkeys` | offer |
| `policy.oracle-events` | offer |
| `policy.oracle-maturity` | offer |
| `policy.oracle-threshold` | offer |
| `policy.cet-locktime` | offer |
| `policy.refund-locktime` | offer |
| `policy.refund-payout` | offer, accept and a successful rebuild |
| `policy.cet-payouts` | offer, accept and a successful rebuild |
| `policy.cet-coverage` | offer, accept and a successful rebuild |

A check whose messages are missing is skipped, and a skipped check makes the policy's result
`incomplete`. If the offer does not decode, every policy check is skipped.

## Library use

The `dlc-verify-policy` crate exposes the same checks:

```rust
let policy = dlc_verify_policy::Policy::parse(&text)?;
let verification = dlc_verify_core::verify(&input, &options);
let report = dlc_verify_policy::report_with_policy(&policy, &verification);
```
