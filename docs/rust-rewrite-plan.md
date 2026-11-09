# dlc-verify Rust rewrite — implementation plan

dlc-verify is being rewritten in Rust on [dlcdevkit](https://github.com/bennyhodl/dlcdevkit) (DDK).
The goal is a general, open-source verifier for DLC offer/accept/sign messages that anyone can run
against the messages they receive from an app.

## Scope decisions

- This repo is standalone. `dlc-verify-tvc` (the Lygos Turnkey TVC enclave build) and
  `dlc-verify-zk` are not changed by this work. Code is copied from `dlc-verify-tvc`'s
  `verifier-core` where useful.
- Broader than `dlc-verify-tvc`: every contract shape DDK supports (enum and numeric outcomes,
  single and multi-oracle, multiple contract infos). Lygos-specific rules live in profiles.
- Refunds: only DDK's `REFUND_TO_ACCEPTER` contract flag (`0x01`) for now. Payouts are read off
  the rebuilt transactions, so new DDK refund records work after a DDK version bump.
- Third-party CET payouts (liquidators): DDK payout-script-override TLV `65005`, which replaces the
  accepter's CET output script.
- No compatibility goal with older loans; dlc-verify fell behind DDK and app changes.
- The hosted TVC proxy is dropped from this repo's web UI. The UI verifies in the browser via WASM.

## Design

1. Rust replaces the TypeScript implementation in `LygosLabs/dlc-verify`. The TS code is kept at
   tag `v1.0.0-typescript` and branch `legacy/typescript`.
2. Transaction rebuilding is delegated to DDK (`ddk_manager::contract::execution_contract_infos`
   and `ddk_manager::contract::transactions::build_contract_transactions`), the same path DDK's own
   `verify_signed_contract` uses.
3. Payouts are labelled from the rebuilt transactions: every CET and refund output is `offerer`,
   `accepter`, `third-party` (with the 65005 record that caused it) or `unknown`.
4. The core is pure: no I/O, no clock (`now` is passed in), only offerer/accepter roles.
   Borrower, lender, liquidator, Magnolia and Midnight exist only in profiles.
5. All DDK crates are pinned to the same exact version (`=2.0.0-rc.10`).

## Layout

```
Cargo.toml                 workspace; DDK pins live here only
rust-toolchain.toml
crates/
  dlc-verify-core/         decode → structure → oracle → rebuild → signatures → report
  dlc-verify-policy/       policy schema, evaluation, oracle registry, profiles
  dlc-verify-settle/       keyless CET (from an oracle attestation) and refund completion
  dlc-verify-cli/          the `dlc-verify` binary
  dlc-verify-wasm/         wasm-bindgen wrapper used by web/
fixtures/                  hex test vectors and expected report snapshots
tools/fixture-gen/         generates real contracts with ddk::contract (dev only)
web/                       static page that verifies in the browser
```

## Check catalogue

| Stage | Check IDs |
|---|---|
| Decode | `decode.offer`, `decode.accept`, `decode.sign`, `decode.unknown-tlvs` |
| Structure | `structure.protocol-version`, `structure.temp-id`, `structure.contract-flags`, `structure.collateral`, `structure.serial-ids`, `structure.funding-inputs`, `structure.fee-rate`, `structure.limits` |
| Oracle | `oracle.announcement-signature`, `oracle.outcome-coverage`, `oracle.maturity` |
| Locktimes | `locktime.cet`, `locktime.refund`, `locktime.units` |
| Rebuild | `tx.build`, `tx.funding-output`, `tx.contract-id` |
| Accept signatures | `sig.accept.cet-adaptors`, `sig.accept.refund` |
| Sign signatures | `sig.offer.cet-adaptors`, `sig.offer.refund`, `sig.offer.funding`, `sig.contract-id` |

Overall status: `fail` if any check fails; `incomplete` if there is no sign message or a funding
witness could not be checked; otherwise `pass`.

## Progress (one PR each, stacked)

- [x] 1. Workspace scaffold, toolchain, Rust CI
- [x] 2. Input parsing (hex, file, stdin, bundles), strict decode, `inspect`
- [x] 3. `fixture-gen` and the first vectors (enum, `0x01`, 65005, numeric, multi-oracle)
- [x] 4. Rebuild and all structure, oracle, locktime and signature checks
- [x] 5. Report with payee table, text and JSON output, `verify` command
- [x] 6. Policy engine and policy files
- [x] 7. Oracle registry, `lygos-loan` and `lygos-midnight` profiles
- [x] 8. Keyless `settle` and `refund`
- [x] 9. WASM build
- [ ] 10. Web UI verifying in the browser
- [ ] 11. Cutover: remove TS, new README, release workflow, Vercel serves the static site
