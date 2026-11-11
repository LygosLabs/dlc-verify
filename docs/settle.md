# Settling without keys

A DLC's messages already hold everything needed to close it on chain without either party:

- the **refund**, signed by both parties in the accept and sign messages, valid after the refund
  locktime;
- every **CET**, signed by both parties as adaptor signatures that only an oracle's attestation
  can decrypt.

`dlc-verify settle` and `dlc-verify refund` complete those transactions and print them, ready to
broadcast with any Bitcoin node or block explorer. They need no private keys and send nothing
anywhere. If the platform that arranged a contract disappears, either party, or anyone holding
the messages, can still settle it.

## Settle a CET

```sh
dlc-verify settle messages.json --attestation fdd868...
```

The attestation is the oracle's signed outcome as a hex TLV record (type 55400, so the hex starts
`fdd868`), the form oracles publish. `--attestation` also takes `@FILE` or `-` for standard
input, and the file may hold JSON: an object with the hex under `hex`, a list of hex strings or
such objects, or a bundle with them under `attestations`. A contract with several oracles needs
one attestation from each of at least the threshold number; repeat `--attestation` or put them
in one list. Without `--attestation`, `settle` reads the bundle's own `attestations`.

`settle`:

1. verifies the messages as `dlc-verify verify` does, and rebuilds every transaction;
2. matches each attestation to an announcement of the contract by the oracle's key and the event
   id, and checks its signatures against that announcement's nonces;
3. finds the CET the attested outcome selects (for a numeric contract, the CET whose digit prefix
   the attested digits start with);
4. decrypts both parties' adaptor signatures for that CET with the oracle's signatures, checks
   them against the funding output, and assembles the 2-of-2 witness.

```text
Signed CET for outcome liquidated-by-0x1111111111111111111111111111111111111111  (CET 2, contract info 0)

  Contract id 36c2e6085697c811d0978575ea279cfbd815a34441b5cdaddd89e8468d3255bb
  Txid        9e5e0dc117a23d3d9fa11072367a1052a3df151bc8c3db3715f2b7f3dc77c5da
  Spends      3bc5e6e7d40a12f32bf727dbdacde350efe2a676f85a5f60671fac8192608a60:0, 100,338 sat
  Attested    oracle 0 (7fb4cc...50ee): event midnight-01JAN26-..., outcome liquidated-by-0x1111...
  Pays        100,000 sat to third-party bcrt1q3qr7lswmh25nplahuj3m474ujs6vjvpu6976ja
  Fee         338 sat, 138 vB
  Broadcast   once the funding transaction confirms

02000000000101608a...
```

`Pays` names each output the way the verification report does: the offerer, the accepter, or a
third party such as a liquidator paid through the payout-override record (TLV 65005).

## Refund

```sh
dlc-verify refund messages.json
```

prints the signed refund. It pays what the refund pays: each party's collateral back, or
everything to the accepter when the offer sets flag `0x01`. It is valid only once the chain's
median time (or height) passes the refund locktime; `Broadcast` says when, and whether that time
has passed by `--now` or the system clock.

## Output

`--format json` prints the settlement as JSON (`schema: "dlc-verify/settlement/v1"`):

| Field | Meaning |
|---|---|
| `kind` | `cet` or `refund` |
| `contract_id` | The contract id from the sign message |
| `verification` | `pass`, `fail` or `incomplete`: the verification of the messages |
| `txid`, `transaction` | The signed transaction and its id; `transaction` is the hex to broadcast |
| `vsize`, `fee_sat` | Its virtual size and fee |
| `spends` | The funding output it spends |
| `locktime` | Its nLockTime |
| `broadcast` | `{"when": "now"}`, `{"when": "after-height", "height"}` or `{"when": "after-time", "unix", "utc", "reached"}` |
| `cet` | For a CET: its global `index`, `contract_info`, `outcome`, what it `settles`, and the `attestations` used |
| `outputs` | Each output's `payee`, `value_sat`, `script` and, for a third party, its payout record |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The transaction is printed |
| 1 | No attestation is for this contract, the attested outcome settles no CET (too few oracles, for example), or a signature does not verify |
| 2 | The messages are not all there: settling needs the offer, the accept and the sign |
| 3 | Bad arguments or unreadable input, including an attestation that is not one |

## What it does not check

A transaction from `settle` or `refund` is valid against the funding output the messages
describe: its signatures verify, and libbitcoinconsensus accepts it in the tests. It does not
look at the chain, so it cannot tell whether the funding transaction confirmed or is already
spent.

`settle` produces a transaction even when the messages do not pass verification, because a party
may need to close a contract whose terms they dislike. The text output then starts with a
warning, and the JSON output's `verification` says so (with the warning on stderr). Run
`dlc-verify verify` and read the report first.
