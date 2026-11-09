# Contributing to dlc-verify

Thanks for helping. Bug reports, new test vectors and fixes are all welcome; open an issue to
discuss anything larger first.

## Set up

- Rust: `rust-toolchain.toml` pins the version, and rustup installs it on first use.
- For the WebAssembly module and the web page: the `wasm32-unknown-unknown` target,
  `wasm-bindgen-cli` at the version `Cargo.toml` pins, a clang that can target wasm32 (on macOS,
  Homebrew's `llvm`) and Node 20 or later. [docs/wasm.md](docs/wasm.md) has the details.

```sh
git clone https://github.com/LygosLabs/dlc-verify.git
cd dlc-verify
cargo test --workspace --locked
```

## Before you open a pull request

CI runs these; run them first:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
tools/build-wasm.sh    # if you changed the core, the WebAssembly crate or web/
```

## Guidelines

- **The core stays pure.** `dlc-verify-core` does no I/O and never reads the clock; the time is
  passed in. It knows only the offerer and the accepter. Lender, borrower, liquidator and other
  roles belong in profiles (`dlc-verify-policy`).
- **DDK rebuilds the transactions.** Use DDK's own builders rather than reimplementing them, so
  dlc-verify checks what DDK will sign. The DDK crates are pinned to one exact version in the
  workspace `Cargo.toml`; bump them together.
- **No panics.** Clippy denies `unwrap`, `expect` and `panic!`, in tests too: return a `Result`.
  A panic in the browser traps the WebAssembly module.
- **A new check gets an id and a test.** Check ids are `stage.name` (see the table in the
  README). If a change alters a report, rerun `UPDATE_SNAPSHOTS=1 cargo test -p dlc-verify-core
  --test report` and review the diff in `fixtures/reports/`.
- **New contract shapes get a vector.** `tools/fixture-gen` makes signed contracts with DDK; see
  [fixtures/README.md](fixtures/README.md).
- **The web page writes what messages say as text, never as HTML,** and loads nothing from other
  origins. `tools/web.test.mjs` checks the second.

## Pull requests

Branch from `main`, keep each pull request to one change, and say what it does and why.
Describe any change to the JSON report or the exit codes, since scripts depend on them.

## Security

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in an issue.
