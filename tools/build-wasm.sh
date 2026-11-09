#!/usr/bin/env bash
# Builds the WebAssembly module into web/pkg, then checks it in Node against the fixtures.
#
# Needs the wasm32-unknown-unknown Rust target, wasm-bindgen-cli at the version Cargo.toml pins,
# a clang that can target wasm32 (to compile libsecp256k1; Apple's cannot, Homebrew's llvm can)
# and Node 20 or later. See docs/wasm.md.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
out="${1:-web/pkg}"

if [[ -z "${CC_wasm32_unknown_unknown:-}" ]]; then
  for llvm in /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin; do
    if [[ -x "$llvm/clang" ]]; then
      export CC_wasm32_unknown_unknown="$llvm/clang"
      export AR_wasm32_unknown_unknown="$llvm/llvm-ar"
      break
    fi
  done
fi

want="$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' Cargo.toml)"
have="$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2 || true)"
if [[ "$have" != "$want" ]]; then
  echo "build-wasm: need wasm-bindgen-cli $want (found: ${have:-none})." >&2
  echo "  cargo install wasm-bindgen-cli --version $want --locked" >&2
  exit 1
fi

cargo build -p dlc-verify-wasm --target wasm32-unknown-unknown --release --locked
rm -rf "$out"
wasm-bindgen --target web --out-dir "$out" \
  target/wasm32-unknown-unknown/release/dlc_verify_wasm.wasm
node tools/wasm-smoke.mjs "$out"
