# DLC Verify

An open-source tool for independently verifying DLC (Discreet Log Contract) messages before signing. Paste your `DlcOffer` and `DlcAccept` hex to get a human-readable breakdown of contract terms plus cryptographic verification of the adaptor signatures.

DLC Verify is currently focused on Lygos-style enumerated loan DLCs, but it is designed to be run locally, self-hosted, and reused for similar DLCs that follow the same message and transaction structure.

---

## Why this exists

DLC contract messages are opaque binary blobs. If someone sends you a `DlcOffer` or `DlcAccept`, there is usually no easy way to inspect what it actually encodes without specialized tooling. DLC Verify closes that gap.

**This is a "don't trust, verify" tool for enumerated DLC contracts.**

- Inspect payout outcomes and collateral splits before signing
- Verify oracle identity, event IDs, locktimes, and funding data
- Confirm CET adaptor signatures are cryptographically valid
- Run it locally or self-host it without trusting a third-party backend

---

## What it verifies

### Tier 1 — Structural (pure JavaScript, no native code)

- Contract type and collateral amounts
- All outcome payouts (e.g. `repaid`, `liquidated-by-price-threshold`)
- Oracle public key and event ID
- Oracle announcement Schnorr signature validity
- CET maturity and refund locktime
- Fee rate
- Both parties' funding pubkeys and the reconstructed 2-of-2 P2WSH address
- Funding inputs from offerer and accepter
- Contract ID (computed, both RPC and internal-txid conventions)

### Tier 2 — Cryptographic (requires DDK native binary)

- Deterministically reconstructs the fund transaction and all CETs from the offer/accept parameters
- Verifies all CET ECDSA adaptor signatures against the oracle's announced nonce and pubkey
- Reports `CRYPTOGRAPHICALLY VALID (N/N)` or `INVALID` with detail

---

## Quick start

```bash
npm install
node verify.js
```

The CLI has sample offer/accept hex hardcoded in `verify.js` for testing, but you can also pass your own values:

```bash
node verify.js --offer <offer_hex> --accept <accept_hex>
node verify.js --offer <offer_hex> --accept <accept_hex> --oracle-pubkey <xonly_pubkey>
```

To use the browser UI locally:

```bash
node server.js
```

Then open `http://localhost:3456`.

**Expected output:**

```
DLC Verification Report
=======================

Contract type: Enumerated
Total collateral: 0.00020000 BTC (20000 sats)
...
Tier 2 status:
  Fund TX ID: fdc7dfe8...
  CET count: 4
  CET adaptor signatures: CRYPTOGRAPHICALLY VALID (4/4)
```

---

## Dependencies

| Package | Purpose | Notes |
|---|---|---|
| `@node-dlc/messaging` | DLC message deserialization | Tier 1 |
| `bitcoinjs-lib` | P2WSH address reconstruction | Tier 1 |
| `bitcoin-networks` | Chain hash detection (mainnet/regtest) | Tier 1 |
| `bip-schnorr` | Oracle announcement Schnorr sig verification | Tier 1 |
| `@bennyblader/ddk-ts` | ECDSA adaptor sig verification via DDK | Tier 2 |

`@bennyblader/ddk-ts` is a public MIT-licensed npm package containing pre-compiled native binaries (arm64/x64). It provides the cryptographic transaction reconstruction and adaptor-signature verification used by Tier 2.

---

## How Tier 2 verification works

The key cryptographic claim being verified: *"The accepter's adaptor signatures are valid ECDSA adaptor signatures, locked to the oracle's announced nonce, that will decrypt to valid CET signatures once the oracle attests to an outcome."*

The verification steps:

1. **Reconstruct the fund transaction** — using the exact parameters from the offer/accept messages, DDK deterministically builds the fund transaction and CET set implied by the DLC.

2. **Build tagged attestation messages** — each outcome string (e.g. `"repaid"`) is hashed as `SHA256(SHA256(tag) || SHA256(tag) || outcome_utf8)` where `tag = "DLC/oracle/attestation/v0"`. This is the DLC spec's oracle attestation message format.

3. **Verify adaptor signatures** — DDK's `verifyCetAdaptorSigsFromOracleInfo` checks that each adaptor signature in `DlcAccept.cetAdaptorSignatures` satisfies the ECDSA adaptor equation:

   ```
   VerifyAdaptor(sig, proof, adaptor_point, cet_sighash, accepter_funding_pubkey)
   ```

   where `adaptor_point = R + H(R, P, msg) * G` (the oracle's anticipated signature point for that outcome).

4. **Report VALID/INVALID** — if all N adaptor signatures pass, the contract is cryptographically sound.

**Why this matters:** A valid adaptor signature means funds can only be claimed by the party who receives the oracle's attestation signature for that specific outcome. The guarantee comes from the cryptography, not from the application that produced the DLC.

---

## Architecture

```
verify.js
├── Tier 1: @node-dlc/messaging deserialization
│   ├── DlcOffer.deserialize(hex)
│   ├── DlcAccept.deserialize(hex)
│   ├── Oracle announcement Schnorr sig check (bip-schnorr)
│   └── P2WSH address reconstruction (bitcoinjs-lib)
│
└── Tier 2: DDK native binary (@bennyblader/ddk-ts)
    ├── createDlcTransactions() → fund TX + CETs
    └── verifyCetAdaptorSigsFromOracleInfo() → true/false
```

No backend. No wallet. No private keys. Stateless.

---

## Security model

- **No private keys handled.** The tool only reads message hex and computes public verification.
- **No server trust required.** You can run the verifier entirely locally or self-host it yourself.
- **Oracle pubkeys are visible in the DlcOffer.** The oracle's identity and nonce commitment are embedded in the offer. You can compare that pubkey against one you obtained independently, or against a known oracle registry in your own deployment.
- **DDK is open source.** The native binary is built from [dlcdevkit](https://github.com/bennyblader/ddk-ffi), source-available under MIT.

---

## Roadmap

- [ ] Accept hex via stdin in addition to CLI args
- [ ] DlcSign verification (fund TX signatures)
- [ ] Refund signature verification
- [ ] Broader DLC shape support beyond the current enumerated focus
- [ ] Oracle pubkey registry / known-oracle presets for hosted deployments
- [ ] Optional hosted instance

---

## License

MIT
