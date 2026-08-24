# NETRA — Runtime System Design & Behavioral Specification

> **Overview**
>
> This document provides the authoritative runtime behavioral specification of NETRA (Network & Endpoint Threat Reconnaissance Architecture). It details process lifecycles, execution modes, cryptographic handshakes, local SQLite state storage, scanning subsystems, browser exposure awareness, vulnerability correlation, finding reasoning pipelines, and resilient offline synchronization.

**Status:** Specified / Designed  
**Audience:** Core Developers, Security Researchers, Systems Engineers, Contributors  
**Purpose:** Serves as the primary behavioral blueprint for implementing the NETRA runtime core, background daemon, CLI interface, and data processing engines.

---

## Contents

1. [Runtime Architectural Foundations](#1-runtime-architectural-foundations)
2. [Process Models & Dual Execution Modes](#2-process-models--dual-execution-modes)
3. [System Startup, Initialization & Identity Bootstrap](#3-system-startup-initialization--identity-bootstrap)
4. [Device Identity, Attestation & Keyring Storage](#4-device-identity-attestation--keyring-storage)
5. [Agent ↔ Control API Transport Protocol](#5-agent--control-api-transport-protocol)
6. [Local-First State Architecture (SQLite WAL)](#6-local-first-state-architecture-sqlite-wal)
7. [Task Orchestration & State Machine](#7-task-orchestration--state-machine)
8. [Security Scanning Subsystems & OS Sandboxing](#8-security-scanning-subsystems--os-sandboxing)
9. [Network Intelligence & Topology Discovery Engine](#9-network-intelligence--topology-discovery-engine)
10. [Browser & Web Exposure Observation Layer](#10-browser--web-exposure-observation-layer)
11. [Vulnerability Intelligence & CVE Correlation](#11-vulnerability-intelligence--cve-correlation)
12. [The 10-Stage Deterministic Data Pipeline](#12-the-10-stage-deterministic-data-pipeline)
13. [Risk Scoring & Policy Evaluation Model](#13-risk-scoring--policy-evaluation-model)
14. [Controlled Remediation & Verification Loops](#14-controlled-remediation--verification-loops)
15. [Offline State Machine & Resilient Cloud Sync](#15-offline-state-machine--resilient-cloud-sync)
16. [Failure Handling, Watchdogs & Crash Recovery](#16-failure-handling-watchdogs--crash-recovery)
17. [Comprehensive Sequence Diagram Catalog](#17-comprehensive-sequence-diagram-catalog)

---

## 1. Runtime Architectural Foundations

NETRA is engineered as an open-source, academic defensive security framework. At runtime, it prioritizes:
1. **Zero External Runtime Dependencies**: Single statically compiled binary (`CGO_ENABLED=0`) written in Go with optional native Rust extensions for high-performance syscall probing.
2. **Local-First Determinism**: Security findings, observations, and telemetry queues are committed to an encrypted local SQLite database before any remote network transmission.
3. **Outbound-Only Communication**: All network connections to the Control API are outbound over TLS 1.3. Endpoints listen on zero inbound TCP/UDP ports.
4. **Privacy-Preserving Inspection**: Telemetry focuses on host configuration posture, network reachability, and process socket bindings. User file contents, keystrokes, browser history, and session payloads are strictly out of scope.

---

## 2. Process Models & Dual Execution Modes

NETRA operates in two distinct operational modes using the same unified binary:

```mermaid
flowchart TD
    Binary["netra (Single Binary Entry Point)"]
    
    Binary --> CheckMode{"Invocation Context"}
    
    CheckMode -- "CLI Command (e.g., `netra scan`)" --> CLIMode["Interactive / Scripting CLI Mode<br/>• Short-lived userspace process<br/>• Direct OS probing or Local Daemon IPC<br/>• stdout/stderr stream separation<br/>• Pure JSON / ANSI table outputs"]
    
    CheckMode -- "Service Daemon (systemd / Windows SCM)" --> DaemonMode["Two-Tier Background Service Mode"]
    
    subgraph DaemonMode["Two-Tier Background Service Mode"]
        direction TB
        Supervisor["Tier 1: OS Supervisor Daemon (Root / SYSTEM)<br/>• Watchdog monitoring & auto-restart<br/>• Keyring access & atomic binary updates<br/>• System-level firewall / route probing"]
        Worker["Tier 2: Sandboxed Worker Process (Low-Privilege)<br/>• WSS stream gateway connection<br/>• Task execution & rule evaluation<br/>• Local SQLite FIFO buffering"]
        
        Supervisor <-->|Local Domain Socket / Named Pipe (DACL 0600)| Worker
    end
```

---

## 3. System Startup, Initialization & Identity Bootstrap

When the system boots or the NETRA daemon is initiated, the startup sequence progresses through five deterministic phases:

```mermaid
sequenceDiagram
    autonumber
    participant OS as OS Service Manager
    participant Sup as NETRA Supervisor
    participant Keyring as OS Secure Keyring
    participant DB as Local SQLite DB
    participant Worker as NETRA Worker

    OS->>Sup: Start Service (`netra service start`)
    Sup->>DB: Open/Migrate `netra_local.db` (Enable WAL Mode)
    Sup->>Keyring: Retrieve Ed25519 Device Private Key
    alt Key Missing (First Run)
        Sup->>Sup: Generate Ed25519 Keypair (RFC 8032)
        Sup->>Keyring: Store Private Key in DPAPI / SecretService
        Sup->>DB: Record Key Metadata & Device UUIDv7
    end
    Sup->>Worker: Fork & Sandbox Worker Process (Apply cgroups / Job Objects)
    Sup->>Worker: Establish Authenticated Local IPC
    Worker->>Worker: Start In-Memory State & Scan Schedulers
    Worker-->>Sup: Heartbeat OK (Daemon Operational)
```

---

## 4. Device Identity, Attestation & Keyring Storage

Every enrolled host possesses a unique **Ed25519 (RFC 8032)** asymmetric cryptographic identity:
* **Private Key Security**: Generated strictly in memory and saved to OS-level secure storage:
  - **Windows**: Windows Data Protection API (DPAPI) via `CryptProtectData` with machine/user scope.
  - **Linux**: Kernel Keyring / Freedesktop SecretService API or `0400` root-owned key store.
  - **macOS**: Apple Keychain Services (`SecItemAdd` with access control).
* **Public Key Representation**: Exported as a 64-character hexadecimal string (`32 bytes`) and transmitted during enrollment to the Control API.
* **Canonical Request Signing**: Every outgoing frame or HTTP request includes cryptographic headers:
  $$\text{Headers: } \text{X-NETRA-Device-ID}, \text{X-NETRA-Timestamp}, \text{X-NETRA-Nonce}, \text{X-NETRA-Signature}$$
  $$\text{StringToSign} = \text{METHOD} \parallel \text{"\textbackslash n"} \parallel \text{PATH} \parallel \text{"\textbackslash n"} \parallel \text{TIMESTAMP} \parallel \text{"\textbackslash n"} \parallel \text{NONCE} \parallel \text{"\textbackslash n"} \parallel \text{SHA256}(\text{BODY})$$

```mermaid
stateDiagram-v2
    [*] --> Unenrolled: Binary Installed
    Unenrolled --> GeneratingKeys: `netra enroll --token <token>`
    GeneratingKeys --> StoringKeyring: Ed25519 Keypair Generated
    StoringKeyring --> AwaitingAttestation: Key Saved to DPAPI / SecretService
    AwaitingAttestation --> Enrolled: Control API Validates Token & Stores Public Key
    Enrolled --> Active: Persistent WSS Stream Connected
    Active --> Revoked: Admin Revocation / Cryptographic Tamper
    Revoked --> [*]: Keys Purged & Execution Halted
```

---

## 5. Agent ↔ Control API Transport Protocol

NETRA agents communicate with the central Control API via a persistent **WebSocket over TLS 1.3 (WSS)** connection, using **Protocol Buffers (Protobuf v3)** for ultra-low serialization overhead:

* **Primary Transport**: `wss://api.netra.io/v1/agent/stream`
* **Fallback Transport**: Authenticated HTTPS Long Polling (`POST /v1/agent/poll`) for restrictive proxies.
* **Heartbeat Cadence**: Ping/Pong frame sent every 15 seconds. If missed for 45 seconds, the connection is marked `DISCONNECTED` and offline caching begins.
* **Reconnection Algorithm**: Exponential backoff with jitter:
  $$t_{\text{backoff}} = \min(t_{\text{max}}, t_{\text{base}} \times 2^{\text{attempt}}) \pm \text{jitter}$$
  where $t_{\text{base}} = 1\text{s}$, $t_{\text{max}} = 300\text{s}$, and $\text{jitter} \in [0, 500\text{ms}]$.

---

## 6. Local-First State Architecture (SQLite WAL)

All local operations persist in a local SQLite database (`/var/lib/netra/agent.db` or `%ProgramData%\NETRA\agent.db`).

### SQLite Configuration & Pruning:
* **Journal Mode**: `PRAGMA journal_mode = WAL;` (Concurrent readers with single writer).
* **Synchronous**: `PRAGMA synchronous = NORMAL;` (Crash safety with optimal SSD/NVMe throughput).
* **Encryption at Rest**: Optional SQLCipher integration with DPAPI/Keyring-derived key.
* **Storage Cap**: Strict 500MB database limit with LRU pruning of resolved findings and synced raw observations.

```mermaid
erDiagram
    LOCAL_CONFIG {
        string key PK
        string value
        datetime updated_at
    }
    OBSERVATION_QUEUE {
        string id PK
        string observation_type
        text payload_json
        string sha256_hash
        string status
        datetime created_at
        integer retry_count
    }
    LOCAL_FINDINGS {
        string fingerprint PK
        string rule_id
        string severity
        string status
        text evidence_json
        datetime first_seen
        datetime last_seen
    }
    SCAN_HISTORY {
        string scan_id PK
        string capability
        string trigger_mode
        integer findings_count
        datetime executed_at
        integer duration_ms
    }

    LOCAL_FINDINGS ||--o{ OBSERVATION_QUEUE : backs
    SCAN_HISTORY ||--o{ LOCAL_FINDINGS : generates
```

---

## 7. Task Orchestration & State Machine

Scan tasks are dispatched asynchronously from the Control API or triggered locally via the CLI:

```mermaid
stateDiagram-v2
    [*] --> PENDING: Created via API or CLI Trigger
    PENDING --> DISPATCHED: Routed over Agent WSS Stream
    DISPATCHED --> LEASED: Agent Confirms Receipt (Task Lease: 60s)
    LEASED --> RUNNING: Sandboxed Worker Begins Syscall Probing
    RUNNING --> COMPLETED: Execution Passed & Evidence Hashed
    RUNNING --> FAILED: Syscall Timeout or OS Permission Denied
    RUNNING --> CANCELLED: Operator Revocation Received
    COMPLETED --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
```

---

## 8. Security Scanning Subsystems & OS Sandboxing

Scanning capabilities execute inside isolated goroutines bounded by OS-level resource sandboxes:

1. **`SCAN_NETWORK`**: Native OS socket inspection (`GetExtendedTcpTable` on Windows, Netlink `rtnetlink` / `/proc/net/tcp` on Linux, `sysctl KERN_PROC` on macOS). Maps listening ports, bound IPs, and associated process binaries.
2. **`SCAN_PROCESSES`**: Enumerates running processes, parent PIDs, executable paths, SHA-256 binary hashes, and active CLI parameters.
3. **`SCAN_FIREWALL`**: Queries kernel packet filters (Windows `INetFwPolicy2`, Linux `nftables`/`iptables`, macOS `pfctl`). Detects disabled profiles or overly permissive `0.0.0.0/0` inbound rules.
4. **`SCAN_USERS`**: Audits local user accounts, active sudoers, and dormant administrative profiles.

### OS Sandboxing Constraints:
* **Linux**: Managed via `cgroups v2` (`CPUQuota=20%`, `MemoryMax=100M`).
* **Windows**: Bound to a Windows **Job Object** with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (100MB) and `JOB_OBJECT_CPU_RATE_CONTROL` (20%).
* **Execution Timeout**: Hard 30-second context timeout per scanner run.

---

## 9. Network Intelligence & Topology Discovery Engine

NETRA constructs a deterministic Layer-2/Layer-3 local reachability graph through a non-intrusive 3-tier methodology:

```mermaid
flowchart TD
    subgraph Discovery["3-Tier Topology Discovery Engine"]
        T1["Tier 1: Passive Extraction (Zero Traffic)<br/>• Kernel Routing Tables (Default Gateways & Interface Metrics)<br/>• OS Neighbor & ARP Cache (`GetIpNetTable2` / `ip neigh`)"]
        T2["Tier 2: Directed Unicast Inferences<br/>• Gateway ICMP / UDP Traceroute probes<br/>• Reverse DNS (PTR) lookups for local LAN nodes"]
        T3["Tier 3: Policy-Controlled Micro-Probing<br/>• Targeted TCP Connect probes to standard ports (22, 80, 445, 3389)"]
    end

    T1 --> Correlator["Topology Correlation Engine"]
    T2 --> Correlator
    T3 --> Correlator

    Correlator --> GraphOutput["Synthesized Network Reachability Graph<br/>• Identifies Multi-Homed Devices (Dual NICs)<br/>• Uncovers Unmanaged Adjacent Devices on Subnet<br/>• Computes Lateral Movement Blast Radius"]
```

---

## 10. Browser & Web Exposure Observation Layer

NETRA provides web exposure awareness by correlating OS socket connections with web browser processes, strictly maintaining academic privacy standards:

* **What Is Monitored**:
  - Web browser process binaries (`chrome.exe`, `firefox`, `msedge`, `brave`, `safari`).
  - Active outbound socket destinations (Remote IP, Remote Port 443/80, Protocol).
  - Reverse DNS hostname mappings and TLS SNI domain headers observed at socket establishment.
  - Active listening ports opened by background web extensions or developer local servers (`localhost:3000`, `localhost:8080`).
* **What Is STRICTLY OUT OF SCOPE (Privacy Guard)**:
  - ✕ No inspection of HTTP request/response payloads or headers.
  - ✕ No reading of browser cookies, local storage, or session tokens.
  - ✕ No access to browser tabs, DOM trees, or web page content.
  - ✕ No keystroke logging, form data capture, or password field interception.

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Web Browser Process
    participant SocketProbe as NETRA Socket Observer
    participant DNSEngine as Local DNS Resolver Cache
    participant Corr as Web Exposure Correlator
    participant DB as SQLite / Finding Engine

    Browser->>Browser: Establishes Outbound Connection to Remote Endpoint
    SocketProbe->>SocketProbe: Read Kernel TCP Table (PID 4082 -> 198.51.100.24:443)
    SocketProbe->>DNSEngine: Match Remote IP against Local DNS Cache
    DNSEngine-->>SocketProbe: Resolved Domain: `suspicious-c2-domain.test`
    SocketProbe->>Corr: Aggregate (PID, ProcessName: `chrome.exe`, Domain, Port: 443)
    Corr->>Corr: Check against Known Insecure / Malicious Exposure Rules
    Corr->>DB: Record `OBSERVATION_WEB_EXPOSURE` & Generate Finding if flagged
```

---

## 11. Vulnerability Intelligence & CVE Correlation

NETRA correlates local software inventories against standardized vulnerability feeds (NVD / OSV / GitHub Security Advisories) using offline-capable cached catalogs:

1. **Inventory Collection**: Collects package metadata from OS package managers (`dpkg`, `rpm`, `pacman`, Windows Registry Uninstall Keys, macOS Homebrew).
2. **CPE Normalization**: Converts raw application strings into Common Platform Enumeration (CPE 2.3) identifiers.
3. **Deterministic Matcher**: Compares version strings against semver and version-range specifications stored in local SQLite CVE cache.

```mermaid
flowchart LR
    HostApp["Installed Application<br/>(e.g., `OpenSSL 1.1.1k`)"] --> CPE["CPE 2.3 Normalizer"]
    CPE --> Matcher["Deterministic Match Engine"]
    CVECache[("Local SQLite CVE Cache<br/>(OSV / NVD Weekly Delta)")] --> Matcher
    Matcher --> Result{"Known CVE Match?"}
    Result -- Yes --> GenFinding["Generate Finding<br/>• CVE-2021-3711 (CVSS 9.8)<br/>• Fixed in: 1.1.1l"]
    Result -- No --> Clean["Mark Package CLEAN"]
```

---

## 12. The 10-Stage Deterministic Data Pipeline

Every security defect in NETRA traverses an immutable 10-stage processing pipeline:

```mermaid
flowchart TD
    S1["1. Observation<br/>(Raw Syscall Data)"] --> S2["2. Normalization<br/>(Structured Schema)"]
    S2 --> S3["3. Correlation<br/>(Process + Socket + DNS)"]
    S3 --> S4["4. Evidence<br/>(Hashed JSON Proof)"]
    S4 --> S5["5. Finding<br/>(Deterministic Rule Match)"]
    S5 --> S6["6. Risk Evaluation<br/>(CVSS + Host Exposure)"]
    S6 --> S7["7. Policy Evaluation<br/>(Alert / Warn / Remediate)"]
    S7 --> S8["8. Controlled Action<br/>(Human-Approved Fix)"]
    S8 --> S9["9. Verification<br/>(Post-Remediation Probe)"]
    S9 --> S10["10. Audit Log<br/>(Immutable Local & Remote Record)"]
```

### Deterministic Fingerprinting Formula:
$$\text{Fingerprint} = \text{SHA-256}(\text{TenantID} \parallel \text{DeviceID} \parallel \text{Capability} \parallel \text{RuleID} \parallel \text{ResourceKey})$$

---

## 13. Risk Scoring & Policy Evaluation Model

NETRA calculates contextual risk by multiplying intrinsic vulnerability severity with environmental exposure:

$$\text{Composite Risk Score} = \text{Base Severity (1–10)} \times \text{Exposure Multiplier} \times \text{Asset Weight}$$

| Exposure Multiplier | Condition |
| :--- | :--- |
| **`1.0`** | Service listening only on `127.0.0.1` (Local loopback only) |
| **`1.5`** | Service listening on private RFC 1918 subnet (`192.168.x.x`, `10.x.x.x`) |
| **`2.0`** | Service listening on `0.0.0.0` with no active host firewall rule |
| **`3.0`** | Service bound to a public IP with known unpatched remote code execution CVE |

---

## 14. Controlled Remediation & Verification Loops

NETRA strictly avoids uncontrolled, destructive automated changes. Every remediation follows a closed verification loop:

```mermaid
stateDiagram-v2
    [*] --> Detected: Finding Identified
    Detected --> AwaitingApproval: Remediation Proposed (CLI / Slack)
    AwaitingApproval --> PreFlight: Operator Approves Action
    PreFlight --> Executing: Pre-Flight Safety Checks Pass
    PreFlight --> Aborted: Pre-Flight Constraint Failed (e.g. Critical System Service)
    Executing --> PostValidation: Native OS Change Applied
    PostValidation --> VerifiedResolved: Post-Probe Confirms Port Closed / Rule Applied
    PostValidation --> RollingBack: Post-Probe Fails (Defect Still Present)
    RollingBack --> RestoredOriginal: Original State Restored & Alert Dispatched
    VerifiedResolved --> [*]
    Aborted --> [*]
    RestoredOriginal --> [*]
```

---

## 15. Offline State Machine & Resilient Cloud Sync

When network connectivity is interrupted, the NETRA agent transitions into offline buffering mode:

```mermaid
stateDiagram-v2
    [*] --> OnlineStreaming: WSS Stream Active
    OnlineStreaming --> OfflineBuffering: Heartbeat Timeout (45s) / Connection Drop
    
    state OfflineBuffering {
        [*] --> SQLiteQueue
        SQLiteQueue --> LocalRuleEval: Run Scheduled Local Audits
        LocalRuleEval --> WriteQueue: Insert Encrypted Evidence
        WriteQueue --> CheckQuota: Enforce 500MB DB Limit
        CheckQuota --> SQLiteQueue
    }
    
    OfflineBuffering --> Reconnecting: Network Connectivity Restored
    Reconnecting --> CloudReconciliation: WSS Authenticated & Handshake Verified
    CloudReconciliation --> OnlineStreaming: Idempotent Batch Sync Complete
```

---

## 16. Failure Handling, Watchdogs & Crash Recovery

1. **Supervisor Process Watchdog**: The Supervisor daemon continuously monitors the Worker process PID. If the Worker terminates unexpectedly, the Supervisor logs the crash stack, delays for 2 seconds, and restarts the Worker with clean memory bounds.
2. **Resource Throttling Watchdog**: If the Worker process exceeds 150MB RSS memory or 25% CPU for >60 continuous seconds, the Supervisor triggers a `SIGTERM` followed by a fresh restart.
3. **Database Corruption Recovery**: If `netra_local.db` experiences header corruption, SQLite WAL recovery is executed automatically. If unrecoverable, the database is rotated to `.corrupt.<timestamp>` and reinitialized from the secure keyring credentials.

---

## 17. Comprehensive Sequence Diagram Catalog

### 17.1 Device Enrollment & Registration Flow

```mermaid
sequenceDiagram
    autonumber
    participant CLI as Operator / CLI
    participant Agent as NETRA Agent Core
    participant Keyring as OS Keyring (DPAPI/SecretService)
    participant Gateway as Control API Gateway
    participant Supabase as Supabase / PostgreSQL Core

    CLI->>Agent: `netra enroll --token <enroll_token>`
    Agent->>Keyring: Generate & Store Ed25519 Private Key
    Agent->>Gateway: POST /v1/agent/enroll (Token, Hex PublicKey, OS Info)
    Gateway->>Supabase: Validate Enrollment Token (Check Expiry & Uses)
    Supabase->>Supabase: Create `devices` Record & Assign `tenant_id`
    Gateway-->>Agent: Return 201 Created (Device ID: `dev_01h8...`)
    Agent->>Agent: Save Device ID to Local SQLite
    Agent->>Gateway: Establish Persistent WSS Stream
    Gateway-->>Agent: Stream Established (Status: ONLINE)
    Agent-->>CLI: "Device enrolled and operational!"
```

### 17.2 Finding Detection, Evidence Ingestion & Deduplication

```mermaid
sequenceDiagram
    autonumber
    participant Scanner as Sandboxed Scanner
    participant Engine as Finding Engine
    participant SQLite as Local SQLite DB
    participant Gateway as WSS Control Gateway
    participant Postgres as Central DB (PostgreSQL 16)

    Scanner->>Engine: Raw Observation (Port 445 Listening, No Firewall)
    Engine->>Engine: Compute SHA-256 Fingerprint
    Engine->>SQLite: Query `LOCAL_FINDINGS` by Fingerprint
    alt Finding Exists in DB (Duplicate)
        Engine->>SQLite: Update `last_seen = NOW()`, Increment Occurrence Count
    else New Finding
        Engine->>SQLite: Insert `LOCAL_FINDINGS` (Status: OPEN, Severity: HIGH)
        Engine->>SQLite: Enqueue to `OBSERVATION_QUEUE`
        Engine->>Gateway: WSS Frame: `INGEST_FINDING` (Payload + Ed25519 Sig)
        Gateway->>Postgres: Execute Upsert via RLS Session
        Gateway-->>Engine: Frame: `ACK_FINDING` (Ingested)
        Engine->>SQLite: Mark Queue Status `SYNCED`
    end
```
