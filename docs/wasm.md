# WebAssembly module

`crates/dlc-verify-wasm` compiles dlc-verify to WebAssembly, so a web page (ours in `web/`, or
yours) can verify, settle and refund in the browser. The module has no network access and no
storage: messages never leave the page.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.127 --locked   # the version Cargo.toml pins
tools/build-wasm.sh                                          # writes web/pkg
```

`tools/build-wasm.sh` also needs a clang that can target wasm32, to compile libsecp256k1. Apple's
clang cannot; on macOS, `brew install llvm` and the script finds it. Elsewhere, set
`CC_wasm32_unknown_unknown=clang` and `AR_wasm32_unknown_unknown=llvm-ar`. The script finishes by
loading the module in Node and checking it against every fixture (`tools/wasm-smoke.mjs`), so it
also needs Node 20 or later.

`web/pkg` holds `dlc_verify_wasm.js` (an ES module), `dlc_verify_wasm_bg.wasm` (about 2 MB,
650 kB compressed) and TypeScript declarations.

## Use

```js
import init, { verify, settle } from './pkg/dlc_verify_wasm.js';

await init();

const bundle = { offer: '…', accept: '…', sign: '…' };
const now = Math.floor(Date.now() / 1000);
const response = JSON.parse(verify(JSON.stringify({ input: bundle, now })));
if (!response.ok) throw new Error(response.error.message);
console.log(response.report.status, response.text);
```

Every function takes a JSON request as a string and returns a JSON response as a string:
`{"ok": true, ...}` with the result, or `{"ok": false, "error": {"kind", "message"}}`. A report
whose status is `fail` is still `ok: true`: the call worked, the contract did not pass.

| Function | Request fields | Response fields |
|---|---|---|
| `verify` | messages, `now`, and `policy` or `profile` with `terms` | `report`, `text`, `notes` |
| `inspect` | messages | `inspection` |
| `settle` | messages, `now`, `attestations` | `settlement`, `text` |
| `refund` | messages, `now` | `settlement`, `text` |
| `profilePolicy` | `profile`, `terms` | `policy`, `notes` |
| `profiles()` | (none) | `profiles`: `[{name, about}]` |
| `oracles()` | (none) | `oracles`: the registry |
| `version()` | (none) | the version, as a plain string |

The request fields:

| Field | Meaning |
|---|---|
| `input` | A bundle (`{"offer", "accept", "sign"}`) as an object or JSON text, or an offer in hex |
| `offer`, `accept`, `sign` | The messages in hex, instead of `input` |
| `now` | The current time as a Unix timestamp. Without it the maturity checks warn that they could not run |
| `policy` | A [policy file](policy.md)'s text, TOML or JSON |
| `profile`, `terms` | A [profile](profiles.md) name and its terms' text |
| `attestations` | Oracle attestations as `settle --attestation` reads them: TLV hex, a list, or JSON text; without it, the bundle's `attestations` |

A function refuses fields it does not read, and unknown fields, with kind `request`.

| Error kind | Meaning |
|---|---|
| `request` | The request is not JSON, has an unknown field, or combines fields that conflict |
| `input` | The messages are malformed or missing |
| `policy` | The policy, profile or terms are invalid |
| `attestation` | No attestation, a malformed one, or none for this contract |
| `incomplete` | Settling needs the offer, accept and sign messages |
| `no-cet` | The attested outcome settles no CET (too few oracles, for example) |
| `signature` | A signature in the messages does not verify |
| `internal` | A bug in dlc-verify |

`report` is the same JSON as `dlc-verify verify --format json` and `settlement` the same as
`dlc-verify settle --format json` (see [settle.md](settle.md)).

## Differences from the CLI

- No clock: pass `now`. The page should pass the browser's clock, and say so.
- A Rust panic cannot be caught on `wasm32`; it traps the call with a JavaScript `RuntimeError`
  instead of returning an error. That is a bug; report it, and instantiate the module again
  before the next call.
- libsecp256k1 is built with small precomputed tables (`lowmemory`) to keep the module small.
  Results are identical; verification is slightly slower.
