# NETRA Project-Local Build Script (PowerShell)
$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName
$CargoPath = "C:\Users\SUBHADIP PAUL\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin"
if (Test-Path "$CargoPath\cargo.exe") {
    $env:PATH = "$CargoPath;$env:PATH"
}

Push-Location (Join-Path $ProjectRoot "rust")
try {
    Write-Host "Building NETRA workspace (Release)..." -ForegroundColor Cyan
    & cargo build --release --workspace
    Write-Host "Build complete. Artifacts in rust/target/release/" -ForegroundColor Green
} finally {
    Pop-Location
}
