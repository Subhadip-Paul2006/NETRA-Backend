# NETRA Project-Local Test Script (PowerShell)
$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
$GnuPath = "C:\Users\SUBHADIP PAUL\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin"
$GnuSelfContained = "C:\Users\SUBHADIP PAUL\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"
$MsvcPath = "C:\Users\SUBHADIP PAUL\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"

if (Test-Path "$GnuPath\cargo.exe") {
    $cleanPath = ($env:PATH -split ';' | Where-Object { $_ -notlike '*C:\MinGW*' }) -join ';'
    $env:PATH = "C:\Git\cmd;C:\Users\SUBHADIP PAUL\.cargo\bin;$GnuSelfContained;$GnuPath;D:\tools\w64devkit\bin;$cleanPath"
    $env:CC = "D:\tools\w64devkit\bin\gcc.exe"
} elseif (Test-Path "$MsvcPath\cargo.exe") {
    $env:PATH = "$MsvcPath;$env:PATH"
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
