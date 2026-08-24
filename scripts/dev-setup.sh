#!/usr/bin/env bash
# NETRA Local Development Environment Setup Script (Linux / macOS)
set -euo pipefail

echo "============================================================"
echo "   NETRA - Network & Endpoint Threat Reconnaissance         "
echo "   Phase 01: Project-Local Development Environment Setup    "
echo "============================================================"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[1/5] Verified Project Root: $PROJECT_ROOT"

# 1. Check Rust Toolchain
echo "[2/5] Checking Rust Systems Toolchain..."
if command -v cargo >/dev/null 2>&1; then
    echo "      Found: $(cargo --version)"
else
    echo "      [!] Rust/Cargo not found. Please install Rust via 'curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh'"
fi

# 2. Setup Project-Local Python Environment
echo "[3/5] Setting up Project-Local Python Environment..."
PYTHON_DIR="$PROJECT_ROOT/python"
VENV_DIR="$PYTHON_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "      Creating project-local virtualenv at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    echo "      Virtualenv created successfully."
else
    echo "      Project-local virtualenv already exists at $VENV_DIR."
fi

# 3. Create required project-local runtime directories
echo "[4/5] Ensuring Project-Local Runtime Folders Exist..."
mkdir -p "$PROJECT_ROOT/artifacts" "$PROJECT_ROOT/logs" "$PROJECT_ROOT/tmp" "$PROJECT_ROOT/cache" "$PROJECT_ROOT/build"

# 4. Build and test Rust workspace
echo "[5/5] Building NETRA Rust Workspace..."
cd "$PROJECT_ROOT/rust"
cargo test --workspace

echo "============================================================"
echo "   NETRA Phase 01 Foundation Ready for Development!         "
echo "============================================================"
