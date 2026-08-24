#!/usr/bin/env bash
# NETRA Project-Local Test Script (Linux / macOS)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Running Rust Unit and Integration Tests..."
cd "$PROJECT_ROOT/rust"
cargo test --workspace

if [ -f "$PROJECT_ROOT/python/.venv/bin/pytest" ]; then
    echo "Running Python Research Extension Tests..."
    "$PROJECT_ROOT/python/.venv/bin/pytest" "$PROJECT_ROOT/python/tests"
fi
