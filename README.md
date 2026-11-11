# dlc-verify

Check a Discreet Log Contract before you sign or fund it.

dlc-verify reads a DLC's offer, accept and sign messages, rebuilds the funding transaction, every
CET and the refund with [dlcdevkit](https://github.com/bennyhodl/dlcdevkit) (DDK), and checks
every signature in them. It shows who each transaction pays, checks the terms you expected, and
can complete a CET or the refund from the messages alone, without keys.

It runs on your machine, as a command-line tool or as a static web page. It sends nothing
anywhere.

```console
$ dlc-verify verify fixtures/enum-payout-override.json --now 1767139200
dlc-verify 2.0.0 (DDK 2.0.0-rc.10)
Result: PASS  (27 passed, 0 warned, 0 failed, 0 skipped)

Contract
  Network           regtest
  Contract id       bab1e6746a92540cb879cadcad6d64b88d83dddc4186664ff9d29c28acc038a9
  Collateral        100,000 sat: offerer 50,000, accepter 50,000
  Oracle maturity   2026-01-01T00:00:00Z
  Refund locktime   2026-01-08T00:00:00Z
  Third party       bcrt1q3qr7lswmh25nplahuj3m474ujs6vjvpu6976ja for outcome "down"
  ...

Checks
  pass  decode.offer                   571 bytes, canonical encoding
  pass  oracle.announcement-signature  1 announcement signature(s) from 1 oracle(s) verify
  pass  sig.accept.cet-adaptors        3 adaptor signature(s) verify against 3 CET(s)
  ...

CET payouts (3)
  up    offerer 100,000 sat
  down  third-party 100,000 sat to bcrt1q3qr7lswmh25nplahuj3m474ujs6vjvpu6976ja
  flat  offerer 50,000 sat, accepter 50,000 sat
```

## What it checks

| Stage | What | Check ids |
|---|---|---|
| Decode | Each message decodes strictly and re-encodes to the same bytes; unknown TLVs are listed | `decode.*` |
| Structure | Protocol version, temporary contract id, contract flags, collateral, serial ids, funding inputs, fee rate, size limits | `structure.*` |
| Oracles | Every announcement signature; every outcome the oracles can attest has a payout; when the events mature | `oracle.*` |
| Locktimes | CETs unlock by the oracle maturity, the refund after it, both in the same units | `locktime.*` |
| Transactions | The funding output is the 2-of-2 of both funding keys; the contract id is the rebuilt one | `tx.*` |
| Signatures | Both parties' CET adaptor and refund signatures, the offerer's funding witnesses, the contract id in the sign message | `sig.*` |

The result is `pass`, `fail`, or `incomplete` when the messages cannot show everything: with no
sign message, for example, the offerer's signatures cannot be checked.

It handles every contract shape DDK builds:

- enumerated and numeric outcomes, one oracle or a threshold of several, and contracts with
  several contract infos;
- contract flag `0x01`, which refunds all the collateral to the accepter;
- DDK's payout-script override (TLV 65005), which pays a CET's accepter share to another script,
  a liquidator for example. dlc-verify lists that payee as `third-party`.

### What a pass does not tell you

- **That these are the terms you agreed to.** A pass says the messages are consistent and signed.
  To check amounts, keys, payout addresses, oracles and dates, give dlc-verify a
  [policy](docs/policy.md) or a [profile](docs/profiles.md) with the terms you expect.
- **Who the oracle is.** The oracle's key is in the offer. Compare it with one you trust, in a
  policy; `dlc-verify oracles` lists the keys dlc-verify knows by name.
- **Anything on chain.** dlc-verify does not look at the blockchain: whether the funding
  transaction confirmed, or its output is still unspent, is for your node or a block explorer.
- **The accepter's funding witnesses.** They are not in the messages.

## Install

**A release.** Download the archive for your platform from
[Releases](https://github.com/LygosLabs/dlc-verify/releases). Each release lists the SHA-256 of
every file in `SHA256SUMS` and has a GitHub build attestation; check one with:

```sh
gh attestation verify dlc-verify-v2.0.0-x86_64-unknown-linux-gnu.tar.gz --repo LygosLabs/dlc-verify
```

**From source**, with Rust 1.94 or later:

```sh
cargo install --locked --git https://github.com/LygosLabs/dlc-verify dlc-verify-cli
```

## Use

The messages come as a JSON bundle `{"offer": "a71a…", "accept": "a71c…", "sign": "a71e…"}`, or
one at a time in hex. Each input is a file path, `-` for standard input, or the text itself.

```sh
dlc-verify verify bundle.json
dlc-verify verify --offer @offer.hex --accept @accept.hex --sign @sign.hex
dlc-verify verify bundle.json --format json > report.json

dlc-verify verify bundle.json --policy expected.toml
dlc-verify verify bundle.json --profile lygos-loan --terms deal.toml

dlc-verify settle bundle.json --attestation fdd868…
dlc-verify refund bundle.json
```

| Command | What it does |
|---|---|
| `verify` | Rebuild the contract and check every message and signature. With `--policy` or `--profile`, also check the terms |
| `inspect` | Print what the messages say, without verifying them |
| `settle` | Complete the CET for an oracle's attestation, ready to broadcast. Needs no keys |
| `refund` | Complete the refund, ready to broadcast after the refund locktime. Needs no keys |
| `profile` | Print the policy a profile builds from deal terms, to save and edit |
| `oracles` | List the oracle keys dlc-verify knows by name |

`dlc-verify <command> --help` describes every option. `verify` exits 0 when every check passes,
1 when one fails, 2 when the result is incomplete and 3 on bad arguments or an invalid policy.
Maturity checks use the system clock; pass `--now <unix time>` or `--no-clock` to choose.

The JSON report (`--format json`) is versioned: its `schema` is `dlc-verify.report.v1`.

## The web page

[`web/`](web) is a static page that does what the command-line tool does, in the browser,
through a WebAssembly build. Messages never leave the page. See [docs/web.md](docs/web.md) to run
or host it.

## Docs

- [Policy files](docs/policy.md): state the terms you expect
- [Profiles](docs/profiles.md): ready-made policies for Lygos loans
- [Settling without keys](docs/settle.md): `settle` and `refund`
- [The WebAssembly module](docs/wasm.md) and [the web page](docs/web.md)
- [Test vectors](fixtures/README.md)

## Layout

| Path | What |
|---|---|
| `crates/dlc-verify-core` | Decode, rebuild with DDK, check, report. No I/O and no clock |
| `crates/dlc-verify-policy` | Policies, the oracle registry and profiles |
| `crates/dlc-verify-settle` | Keyless CET and refund completion |
| `crates/dlc-verify-cli` | The `dlc-verify` command |
| `crates/dlc-verify-wasm` | The WebAssembly module behind the web page |
| `web/` | The web page |
| `fixtures/` | Signed test contracts and the reports they should produce |
| `tools/fixture-gen` | Makes the test contracts with DDK |
| `examples/` | Messages from Lygos test loans |

The crates are not published to crates.io; use them as git dependencies.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
tools/build-wasm.sh    # the WebAssembly module and the web page's tests; see docs/wasm.md
```

See [CONTRIBUTING.md](CONTRIBUTING.md). To release, push a tag `vX.Y.Z` that matches the version
in `Cargo.toml`: the release workflow builds the command-line tool for Linux, macOS and Windows
and the web page, and drafts a GitHub release with them.

## The TypeScript version

dlc-verify 1.x was written in TypeScript on node-dlc, with a hosted verifier in Turnkey TVC. It
is kept at tag `v1.0.0-typescript` and branch `legacy/typescript`, and is no longer maintained.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
