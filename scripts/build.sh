#!/usr/bin/env bash
# NETRA Project-Local Build Script (Linux / macOS)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Building NETRA workspace (Release)..."
cd "$PROJECT_ROOT/rust"
cargo build --release --workspace

echo "Build complete. Artifacts in rust/target/release/"
