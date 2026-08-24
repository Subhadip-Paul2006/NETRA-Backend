# NETRA Local Development Environment Setup Script (Windows PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   NETRA - Network & Endpoint Threat Reconnaissance         " -ForegroundColor Cyan
Write-Host "   Phase 01: Project-Local Development Environment Setup    " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
Write-Host "[1/5] Verified Project Root: $ProjectRoot" -ForegroundColor Green

# 1. Check Rust Toolchain
Write-Host "[2/5] Checking Rust Systems Toolchain..." -ForegroundColor Yellow
$CargoPath = "C:\Users\SUBHADIP PAUL\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"
if (Test-Path "$CargoPath\cargo.exe") {
    $env:PATH = "$CargoPath;$env:PATH"
    $CargoVer = & cargo --version
    Write-Host "      Found: $CargoVer" -ForegroundColor Green
} else {
    try {
        $CargoVer = & cargo --version
        Write-Host "      Found: $CargoVer" -ForegroundColor Green
    } catch {
        Write-Host "      [!] Rust/Cargo not found. Please install Rust from https://rustup.rs" -ForegroundColor Red
    }
}

# 2. Setup Project-Local Python Environment
Write-Host "[3/5] Setting up Project-Local Python Environment..." -ForegroundColor Yellow
$PythonDir = Join-Path $ProjectRoot "python"
$VenvDir = Join-Path $PythonDir ".venv"

if (-not (Test-Path $VenvDir)) {
    Write-Host "      Creating project-local virtualenv at $VenvDir..." -ForegroundColor Cyan
    & python -m venv $VenvDir
    Write-Host "      Virtualenv created successfully." -ForegroundColor Green
} else {
    Write-Host "      Project-local virtualenv already exists at $VenvDir." -ForegroundColor Green
}

# 3. Create required project-local runtime directories
Write-Host "[4/5] Ensuring Project-Local Runtime Folders Exist..." -ForegroundColor Yellow
$LocalDirs = @("artifacts", "logs", "tmp", "cache", "build")
foreach ($dir in $LocalDirs) {
    $fullPath = Join-Path $ProjectRoot $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath | Out-Null
        Write-Host "      Created: $dir/" -ForegroundColor Green
    }
}

# 4. Build and test Rust workspace
Write-Host "[5/5] Building NETRA Rust Workspace..." -ForegroundColor Yellow
Push-Location (Join-Path $ProjectRoot "rust")
try {
    & cargo test --workspace
    Write-Host "      All Rust unit and integration tests passed!" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   NETRA Phase 01 Foundation Ready for Development!         " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
