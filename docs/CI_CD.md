# NETRA — CI/CD Automation & Supply Chain Security Framework

> **Overview**
>
> This document details the continuous integration, reproducible build pipelines, static security analysis, Software Bill of Materials (SBOM) generation, and cryptographic release signing workflows for NETRA (Network & Endpoint Threat Reconnaissance Architecture).

**Status:** Specified / Designed  
**Audience:** DevOps Engineers, Security Maintainers, Release Engineers, Academic Auditors  
**Purpose:** Establishes the automated verification framework ensuring that all released binaries maintain verified supply chain integrity (SLSA Level 3).

---

## Contents

1. [CI/CD Philosophy & Supply Chain Posture](#1-cicd-philosophy--supply-chain-posture)
2. [Pull Request Quality Gates & Automated Scans](#2-pull-request-quality-gates--automated-scans)
3. [Hermetic Build & Multi-Architecture Compilation](#3-hermetic-build--multi-architecture-compilation)
4. [Automated Security Scanners (SAST, Secrets, Vulnerabilities)](#4-automated-security-scanners-sast-secrets-vulnerabilities)
5. [Software Bill of Materials (SBOM) Generation](#5-software-bill-of-materials-sbom-generation)
6. [Cryptographic Artifact Signing (Cosign / Sigstore)](#6-cryptographic-artifact-signing-cosign--sigstore)
7. [GitHub Actions Release Pipeline Architecture](#7-github-actions-release-pipeline-architecture)
8. [Release Verification & Automated Smoke Testing](#8-release-verification--automated-smoke-testing)

---

## 1. CI/CD Philosophy & Supply Chain Posture

NETRA enforces strict **Supply-chain Levels for Software Artifacts (SLSA Level 3)** compliance:

```mermaid
flowchart LR
    subgraph SupplyChain["SLSA Level 3 Pipeline"]
        direction LR
        Build["1. Hermetic Build<br/>(`CGO_ENABLED=0`)"] --> Scan["2. Security Checks<br/>(Govulncheck, CodeQL)"]
        Scan --> SBOM["3. Generate SBOM<br/>(Syft SPDX / CycloneDX)"]
        SBOM --> Sign["4. Sign Artifacts<br/>(Cosign Keyless OIDC)"]
        Sign --> Publish["5. Publish Release<br/>(GitHub Releases + TUF)"]
    end
```

---

## 2. Pull Request Quality Gates & Automated Scans

Every Pull Request must pass mandatory automated checks before merging into `main`:

```mermaid
flowchart TD
    PR["Pull Request Opened"] --> Matrix{"Automated CI Quality Matrix"}

    Matrix --> L1["1. Linting (`golangci-lint`, `ruff`)"]
    Matrix --> L2["2. Unit & Integration Tests (100% Pass)"]
    Matrix --> L3["3. Secret Scanning (`gitleaks`)"]
    Matrix --> L4["4. Vulnerability Audit (`govulncheck`)"]
    Matrix --> L5["5. SAST Analysis (GitHub CodeQL)"]

    L1 --> Merge["All Checks Green ──> Approved for Merge"]
    L2 --> Merge
    L3 --> Merge
    L4 --> Merge
    L5 --> Merge
```

---

## 3. Hermetic Build & Multi-Architecture Compilation

```bash
# Matrix Build Targets:
# Linux AMD64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/netra-linux-amd64 ./cmd/netra

# Linux ARM64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/netra-linux-arm64 ./cmd/netra

# Windows AMD64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/netra-windows-amd64.exe ./cmd/netra

# macOS Universal (Apple Silicon + Intel)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/netra-darwin-arm64 ./cmd/netra
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/netra-darwin-amd64 ./cmd/netra
lipo -create -output dist/netra-darwin-universal dist/netra-darwin-arm64 dist/netra-darwin-amd64
```

---

## 4. Automated Security Scanners

1. **`govulncheck`**: Audits transitive Go dependencies against the official Go vulnerability database.
2. **`gitleaks`**: Scans the git commit history to prevent accidental leakage of private keys or credentials.
3. **`codeql`**: Performs semantic static application security testing (SAST) to detect injection or logic flaws.

---

## 5. Software Bill of Materials (SBOM) Generation

During each release build, an authoritative SBOM is generated using `syft`:

```bash
# Generate SBOM in CycloneDX and SPDX formats
syft packages dir:dist/ -o cyclonedx-json=dist/netra-sbom.cyclonedx.json
syft packages dir:dist/ -o spdx-json=dist/netra-sbom.spdx.json
```

---

## 6. Cryptographic Artifact Signing (Cosign / Sigstore)

Release artifacts and container images are cryptographically signed using **Cosign** via GitHub Actions OIDC:

```bash
cosign sign-blob \
  --yes \
  --output-signature dist/netra-linux-amd64.sig \
  --output-certificate dist/netra-linux-amd64.pem \
  dist/netra-linux-amd64
```

---

## 7. GitHub Actions Release Pipeline Architecture

```yaml
name: Release Pipeline
on:
  push:
    tags:
      - 'v*'

jobs:
  build-and-release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Build Static Binaries
        run: make release-build
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          path: dist/
      - name: Sign Binaries with Cosign
        uses: sigstore/cosign-installer@v3
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: dist/*
```

---

## 8. Release Verification & Automated Smoke Testing

```mermaid
flowchart TD
    BuildDone["Binaries Compiled & Signed"] --> Provision["Provision Clean Smoke Test VMs (Ubuntu / Windows)"]
    Provision --> TestInstall["Install Release Binary & Run `netra --self-test`"]
    TestInstall --> TestPass{"Self-Test Passed?"}
    TestPass -- Yes --> Promote["Promote Tag to `latest` & Update Manifest"]
    TestPass -- No --> Rollback["Flag Release as BROKEN & Abort Release"]
```
