#!/usr/bin/env bash
# Build the browser client: the MLS library compiled to WebAssembly, into web/pkg.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$(dirname "$0")/.."
cargo build --release --target wasm32-unknown-unknown -p web
wasm-bindgen --target web --no-typescript --out-dir web/pkg "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/web.wasm"
ls -la web/pkg
