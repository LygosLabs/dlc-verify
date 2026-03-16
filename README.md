# DLC Verify

A trustless, open-source tool for independently verifying DLC (Discreet Log Contract) messages before signing. Paste your `DlcOffer` and `DlcAccept` hex — get a human-readable breakdown of every loan term plus full cryptographic verification of the adaptor signatures, with no server required.

---

## Why this exists

DLC contract messages are opaque binary blobs. A borrower or lender receiving a `DlcOffer` has no way to know what it encodes without a tool like this. DLC Verify closes that gap.

**This is the "don't trust, verify" tool for Lygos loans.**

- Borrowers can confirm CET payouts match the loan terms they were quoted
- Lenders can confirm adaptor signatures are cryptographically valid before broadcasting
- Both parties can verify oracle identity, maturity dates, and collateral amounts
- Everything runs locally — no private keys handled, no server trust required

---

## What it verifies

### Tier 1 — Structural (pure JavaScript, no native code)

- Contract type and collateral amounts
- All outcome payouts (e.g. `repaid`, `liquidated-by-price-threshold`)
- Oracle public key and event ID
- Oracle announcement Schnorr signature validity
- Loan maturity date and refund locktime
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

The sample offer/accept hex is hardcoded in `verify.js` for testing. Replace `OFFER_HEX` and `ACCEPT_HEX` with your own messages.

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

`@bennyblader/ddk-ts` is a public MIT-licensed npm package containing pre-compiled native binaries (arm64/x64). It is the same crypto engine used by the Lygos app itself, so verification is apples-to-apples.

---

## How Tier 2 verification works

The key cryptographic claim being verified: *"The accepter's adaptor signatures are valid ECDSA adaptor signatures, locked to the oracle's announced nonce, that will decrypt to valid CET signatures once the oracle attests to an outcome."*

The verification steps:

1. **Reconstruct the fund transaction** — using the exact same parameters from the offer/accept messages, DDK deterministically builds the fund TX and all 4 CETs. This is the same computation the Lygos app performs.

2. **Build tagged attestation messages** — each outcome string (e.g. `"repaid"`) is hashed as `SHA256(SHA256(tag) || SHA256(tag) || outcome_utf8)` where `tag = "DLC/oracle/attestation/v0"`. This is the DLC spec's oracle attestation message format.

3. **Verify adaptor signatures** — DDK's `verifyCetAdaptorSigsFromOracleInfo` checks that each adaptor signature in `DlcAccept.cetAdaptorSignatures` satisfies the ECDSA adaptor equation:

   ```
   VerifyAdaptor(sig, proof, adaptor_point, cet_sighash, accepter_funding_pubkey)
   ```

   where `adaptor_point = R + H(R, P, msg) * G` (the oracle's anticipated signature point for that outcome).

4. **Report VALID/INVALID** — if all N adaptor signatures pass, the contract is cryptographically sound.

**Why this matters:** A valid adaptor signature means the accepter's funds can only be claimed by the party who receives the oracle's attestation signature for that specific outcome. The math guarantees it, not Lygos.

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
- **No server trust required.** Runs entirely locally. The hosted version is a convenience; anyone can `npm install && node verify.js`.
- **Oracle pubkeys are visible in the DlcOffer.** The oracle's identity and nonce commitment are embedded in the offer — you can verify them against Lygos's published oracle pubkey independently.
- **DDK is open source.** The native binary is built from [dlcdevkit](https://github.com/bennyblader/ddk-ffi), source-available under MIT.

---

## Roadmap

- [ ] Accept hex via CLI args or stdin (not just hardcoded)
- [ ] DlcSign verification (fund TX signatures)
- [ ] Refund signature verification
- [ ] Web UI (paste hex, see results in browser)
- [ ] Hosted instance at verify.lygos.finance
- [ ] Oracle pubkey registry (verify oracle matches Lygos's published keys)

---

## License

MIT
