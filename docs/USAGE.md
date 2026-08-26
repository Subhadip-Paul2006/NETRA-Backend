# NETRA — Practical Operations & Developer Usage Handbook

> **Overview**
>
> This document serves as the hands-on operations manual and developer guide for NETRA (Network & Endpoint Threat Reconnaissance Architecture). It covers Rust agent installation, device enrollment, running posture audits, inspecting network topology, scripting CI/CD gates, and diagnostic troubleshooting.

**Status:** Specified / Designed  
**Audience:** Developers, DevOps Engineers, Lab Administrators, Students, Security Researchers  
**Purpose:** Provides step-by-step instructions and operational commands for deploying, managing, and automating NETRA across diverse endpoint environments.

---

## Contents

1. [Operational Lifecycle Overview](#1-operational-lifecycle-overview)
2. [Prerequisites & System Requirements](#2-prerequisites--system-requirements)
3. [Agent Installation & Verification](#3-agent-installation--verification)
4. [Device Enrollment & Registration](#4-device-enrollment--registration)
5. [Running On-Demand Posture & Network Scans](#5-running-on-demand-posture--network-scans)
6. [Investigating Findings & Cryptographic Evidence](#6-investigating-findings--cryptographic-evidence)
7. [Inspecting Local Network Topology](#7-inspecting-local-network-topology)
8. [Automating CI/CD Security Policy Gates](#8-automating-cicd-security-policy-gates)
9. [Configuration Files & Environment Variables](#9-configuration-files--environment-variables)
10. [Diagnostic Bundles & Troubleshooting Decision Tree](#10-diagnostic-bundles--troubleshooting-decision-tree)

---

## 1. Operational Lifecycle Overview

```mermaid
flowchart TD
    Install["1. Install Binary<br/>(curl -sSL https://get.netra.io | sudo sh)"] --> Enroll["2. Enroll Device<br/>(netra enroll --token [token])"]
    Enroll --> Verify["3. Check Status<br/>(netra status)"]
    Verify --> Scan["4. Run Posture Scan<br/>(netra scan --all)"]
    Scan --> Findings["5. Inspect Findings<br/>(netra findings list)"]
    Findings --> Remediate["6. Apply Remediation<br/>(Safe, approved fix)"]
    Remediate --> Validate["7. Re-scan & Validate<br/>(Post-validation loop)"]
```

---

## 2. Prerequisites & System Requirements

* **Windows**: Windows 10/11 (`x86_64`, `aarch64`) or Windows Server 2016+.
* **Linux**: Linux Kernel 4.19+ (Ubuntu, Debian, RHEL, Fedora, Arch; systemd recommended).
* **macOS**: macOS 12 (Monterey) or newer (Apple Silicon M1/M2/M3 or Intel).
* **Network**: Outbound access over TCP port 443 (HTTPS/WSS). Zero open inbound listening ports required.

---

## 3. Agent Installation & Verification

### Linux (Ubuntu / Debian / RHEL / Arch)
```bash
# Download and install single static Rust binary
curl -sSL https://get.netra.io | sudo sh

# Verify installation
netra --version
# Output: netra version 1.0.0 (x86_64-unknown-linux-musl)
```

### Windows (PowerShell as Administrator)
```powershell
# PowerShell automated installer
iwr -useb https://get.netra.io/install.ps1 | iex

# Verify installation
netra.exe --version
```

---

## 4. Device Enrollment & Registration

```bash
$ sudo netra enroll --token enroll_sec_99a8b7c6d5e4f3a2

✔ Generating Ed25519 cryptographic keypair in RAM...
✔ Storing private key in OS protected storage (DPAPI / SecretService)...
✔ Registering device with NETRA Control Gateway (https://api.netra.io)...
✔ Device enrolled successfully! (Device ID: dev_01h8a9b2c3d4e5f6)
✔ Background supervisor service started.
```

---

## 5. Running On-Demand Posture & Network Scans

```bash
# 5.1 Run all 6 security posture audits (Sockets, Processes, Firewall, Users, Services, OS Config)
$ netra scan

# 5.2 Run with optional executable binary SHA-256 hashing (50MB cap)
$ netra scan --hash-binaries

# 5.3 Run single domain reconnaissance only
$ netra scan sockets
$ netra scan process
$ netra scan firewall
$ netra scan users
$ netra scan services
$ netra scan os

# 5.4 Emit machine-readable JSON envelope
$ netra scan --json
```

---

## 6. Investigating Findings & Cryptographic Evidence

```bash
# 6.1 List all deduplicated findings
$ netra findings list

# 6.2 Filter findings by severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
$ netra findings list --severity CRITICAL

# 6.3 Filter findings by status (OPEN, RESOLVED, SUPPRESSED)
$ netra findings list --status OPEN

# 6.4 Stream findings into jq or CI automation
$ netra findings list --json | jq '.data[] | {rule: .rule_id, title: .title, occurrences: .occurrence_count}'
```

---

## 7. Inspecting Local Network Topology

```bash
$ netra topology

Subnet: 192.168.1.0/24 (Interface: eth0)
Default Gateway: 192.168.1.1 (Gateway-Router - 00:1A:2B:3C:4D:5E)

Discovered Adjacent Neighbors (ARP Table):
  • 192.168.1.15  [00:11:22:33:44:55]  (dev-laptop-02)
  • 192.168.1.60  [00:AA:BB:CC:DD:EE]  (srv-database-01)
```

---

## 8. Automating CI/CD Security Policy Gates

```yaml
name: Security Posture Gate
on: [push, pull_request]

jobs:
  netra-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install NETRA Agent
        run: curl -sSL https://get.netra.io | sudo sh
      - name: Run Host Posture Audit
        run: |
          netra scan --all --fail-on=HIGH --json > netra-report.json
      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: netra-security-report
          path: netra-report.json
```

---

## 9. Configuration Files & Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `NETRA_SERVER_URL` | `https://api.netra.io` | Central Control API base URL |
| `NETRA_LOG_LEVEL` | `info` | Logging verbosity (`trace`, `debug`, `info`, `warn`, `error`) |
| `NETRA_LOG_FORMAT` | `human` | Log output format (`human`, `json`) |
| `NETRA_LOCAL_DB_PATH` | `tmp/agent.db` | Path to local SQLite database |
| `NETRA_SHUTDOWN_TIMEOUT_MS` | `5000` | Graceful shutdown timeout in milliseconds |
| `NETRA_WORKER_MEMORY_LIMIT_BYTES` | `104857600` | Low-privilege worker process memory limit (100MB) |
| `NETRA_RESTART_DELAY_MS` | `2000` | Supervisor watchdog restart backoff base (2000ms) |
| `NETRA_MAX_CONSECUTIVE_CRASHES` | `5` | Maximum worker crashes before circuit breaker trips |
| `NO_COLOR` | `0` | Set to `1` or `true` to disable ANSI colors across all output |

---

## 10. Diagnostic Bundles & Troubleshooting Decision Tree

```mermaid
flowchart TD
    Issue["Agent Status: OFFLINE or State Error"] --> D1["Run netra diagnostics"]
    D1 --> D2{"Check Runtime Coordinator State"}
    D2 -- Failed --> D3["Verify configuration TOML and environment variables"]
    D2 -- Success --> D4{"Check Local SQLite Storage"}
    D4 -- Corrupted --> D5["Run netra storage check --deep"]
    D5 --> D6["Recover via netra storage recover --force-reinit"]
    D4 -- Clean --> D7["Review runtime logs"]
```

---

## 11. Storage Diagnostics, Quota & Quarantine Management

```bash
# Check local SQLite storage health and quota utilization
netra storage status

# Run Tier 2 quick check or Tier 3 deep integrity verification
netra storage check
netra storage check --deep

# Inspect quarantined corrupted databases (forensic preservation directory)
ls -la /var/lib/netra/quarantine_*/
cat /var/lib/netra/quarantine_*/quarantine_meta.json

# Explicit operator recovery (quarantines active files and re-initializes clean store)
# In interactive terminal: prompts for confirmation
# In scripts/CI: requires explicit --force-reinit
netra storage recover --force-reinit
```

---

## 12. Control-Plane REST API Gateway Interactions (Phase 5)

When the NETRA agent is running with the REST API enabled, endpoints can be queried via standard HTTP clients on `http://127.0.0.1:8443`:

```bash
# Check service liveness and component health
curl -s http://127.0.0.1:8443/api/v1/health

# Query version metadata
curl -s http://127.0.0.1:8443/api/v1/version

# Query runtime state and host platform details
curl -s http://127.0.0.1:8443/api/v1/status

# Generate environmental diagnostic bundle
curl -s http://127.0.0.1:8443/api/v1/diagnostics

# Fetch compile-time OpenAPI 3.1 schema
curl -s http://127.0.0.1:8443/api/v1/openapi.json

# Check local SQLite database disk footprint and table record counts
curl -s http://127.0.0.1:8443/api/v1/storage/status

# Execute Tier 2 quick_check (default) or Tier 3 deep integrity verification
# Returns 200 OK with "passed": true (healthy) or "passed": false (corruption details)
# Returns 409 Conflict if a deep check is already in flight
curl -s http://127.0.0.1:8443/api/v1/storage/check
curl -s "http://127.0.0.1:8443/api/v1/storage/check?deep=true"
```

---

## 13. Device Identity & Enrollment CLI Operations (Phase 6)

```bash
# Enroll agent host with upstream control plane using single-use bootstrap token
netra enroll --token <BOOTSTRAP_TOKEN> --gateway wss://control.netra.local/api/v1/agent/stream

# Query cryptographic device identity, active public key, and KeyStore status
netra identity status

# Query identity status with structured JSON output
netra identity status --json

# Trigger manual policy-driven key rotation
netra identity rotate

# Trigger emergency key rotation / revocation
netra identity rotate --emergency
```

### 13.1 Production vs Development KeyStore Policy

> [!IMPORTANT]
> **Production KeyStore Requirement & Fail-Safe Behavior**:
> - In standard production deployments, private keys are strictly managed by native OS key storage (`Windows DPAPI` on Windows, `Freedesktop Secret Service` on Linux desktop, `Apple Keychain` on macOS).
> - On headless Linux servers without a configured secret provider (e.g. D-Bus Secret Service), identity operations intentionally **fail closed** with `ERR_KEYSTORE_UNAVAILABLE`.
> - **Insecure Development Backend (`--insecure-dev-keystore`)**:
>   - Exclusively available in development/test builds compiled with `--features insecure-dev-keystore`.
>   - **Completely absent and rejected** in standard release binaries.
>   - MUST NOT be enabled, configured, or relied upon in production environments.
>   - Phase 7 and future production capabilities strictly require production OS key storage.



