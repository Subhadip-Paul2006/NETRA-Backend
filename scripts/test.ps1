# NETRA Project-Local Test Script (PowerShell)
$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
$CargoPath = "C:\Users\SUBHADIP PAUL\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"
if (Test-Path "$CargoPath\cargo.exe") {
    $env:PATH = "$CargoPath;$env:PATH"
}

Write-Host "Running Rust Unit and Integration Tests..." -ForegroundColor Cyan
Push-Location (Join-Path $ProjectRoot "rust")
try {
    & cargo test --workspace
} finally {
    Pop-Location
}

$PytestPath = Join-Path $ProjectRoot "python\.venv\Scripts\pytest.exe"
if (Test-Path $PytestPath) {
    Write-Host "Running Python Research Extension Tests..." -ForegroundColor Cyan
    & $PytestPath (Join-Path $ProjectRoot "python\tests")
}
