# NETRA — System Design & Runtime Lifecycles

> **Document Status:** Approved Specification  
> **Target Version:** v1.0.0-MVP  
> **Authoritative Scope:** Runtime workflows, state machines, sequence diagrams, failure recovery loops, and concurrency models for NETRA.  
> **Related Documents:** [ARCHITECTURE.md](./ARCHITECTURE.md), [API.md](./API.md), [SECURITY_CHECK.md](./SECURITY_CHECK.md)

---

## Contents

1. [Runtime Architectural Components](#1-runtime-architectural-components)
2. [Device Enrollment Lifecycle](#2-device-enrollment-lifecycle)
3. [Agent Connection & Authentication Flow](#3-agent-connection--authentication-flow)
4. [Task Orchestration & State Machine](#4-task-orchestration--state-machine)
5. [Scanner Execution & Sandboxing Model](#5-scanner-execution--sandboxing-model)
6. [Finding, Evidence & Risk Pipeline](#6-finding-evidence--risk-pipeline)
7. [Network Discovery & Topology Synthesis Engine](#7-network-discovery--topology-synthesis-engine)
8. [Offline Buffering & Synchronization Lifecycle](#8-offline-buffering--synchronization-lifecycle)
9. [Concurrency & Resource Control Model](#9-concurrency--resource-control-model)

---

## 1. Runtime Architectural Components

```mermaid
flowchart TD
    subgraph ClientHost["Managed Endpoint Host"]
        subgraph SupervisorDaemon["Supervisor Daemon (SYSTEM/root)"]
            Watchdog["Watchdog Monitor"]
            KeyBroker["OS Keyring Broker (DPAPI)"]
            TUFUpdater["TUF Auto-Updater"]
        end
        subgraph WorkerAgent["Worker Process (`netra` Go Binary)"]
            WSSLoop["WSS Client Loop (TLS 1.3)"]
            Dispatcher["Task Dispatcher & Sandbox"]
            Registry["Scanner Registry (`SCAN_NETWORK`, `SCAN_FIREWALL`)"]
            SQLiteBuffer[("Encrypted SQLite Store")]
        end
        SupervisorDaemon <-- Local IPC (Named Pipe / Domain Socket) --> WorkerAgent
    end

    subgraph BackendGateway["NETRA Backend Gateway"]
        AuthVal["Auth & Nonce Validator"]
        WSSHub["WSS Connection Hub"]
        TaskOrch["Task Orchestrator"]
        DedupEngine["Finding Deduplication Engine"]
        TopSynth["Topology Graph Synthesizer"]
    end

    subgraph DatabaseCore["Database Core"]
        Postgres[("PostgreSQL 16 Core<br/>Row-Level Security Scoped")]
    end

    WSSLoop -->|Outbound WSS Stream| WSSHub
    AuthVal <--> Postgres
    TaskOrch <--> Postgres
    DedupEngine <--> Postgres
    TopSynth <--> Postgres
```

---

## 2. Device Enrollment Lifecycle

Device enrollment establishes a cryptographically secure, permanent binding between an endpoint host and a tenant organization without transmitting private keys over the wire.

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Administrator / Console
    participant Backend as NETRA Backend API
    participant Agent as Agent CLI (`netra`)
    participant Keyring as OS Protected Keyring (DPAPI)
    participant DB as PostgreSQL 16 Core

    Admin->>Backend: Request Enrollment Token (POST /v1/enrollment-tokens)
    Backend->>DB: Store Token Hash (TTL: 15 minutes)
    Backend-->>Admin: Return Token String (`enroll_sec_99a8b...`)

    Admin->>Agent: Run Command (`netra enroll --token enroll_sec_99a8b...`)
    Note over Agent: Generate Ed25519 Keypair in RAM
    Agent->>Keyring: Store Private Key Securely (CryptProtectData)
    Keyring-->>Agent: Key Stored Successfully

    Agent->>Backend: POST /v1/agent/enroll (Token + Ed25519 Public Key + OS Info)
    Backend->>DB: Validate Token & Check Expiry
    Backend->>DB: Invalidate Token (Single-Use Guarantee)
    Backend->>DB: Insert `devices` & `device_credentials` Records
    DB-->>Backend: Enrollment Committed
    Backend-->>Agent: HTTP 201 Created (Device ID: `dev_01h8a9b2c...`)
    Note over Agent: Start Worker Daemon & Initiate WSS Stream
```

---

## 3. Agent Connection & Authentication Flow

Once enrolled, the agent connects exclusively over outbound persistent WebSocket (WSS):

```mermaid
sequenceDiagram
    autonumber
    participant Agent as NETRA Worker Agent
    participant WSS as WSS Stream Gateway
    participant Cache as Sliding Window Nonce Cache
    participant DB as PostgreSQL 16 Core

    Agent->>WSS: Outbound TCP/TLS 1.3 Handshake (`/v1/agent/stream`)
    Agent->>WSS: Send `AGENT_HELLO` Frame + Ed25519 Headers
    WSS->>DB: Query `device_credentials` for `device_id` Public Key
    DB-->>WSS: Return Public Key
    WSS->>WSS: Verify Ed25519 Signature over Handshake Frame
    WSS->>Cache: Verify Nonce (5-minute sliding window TTL)
    Cache-->>WSS: Nonce Valid (Not Replayed)
    WSS->>DB: Update `devices.status = 'ONLINE'`, `last_seen_at = NOW()`
    WSS-->>Agent: Send Connection Acknowledged (Frame Code: 1000)

    loop Heartbeat Loop (Every 15 Seconds)
        Agent->>WSS: Send PING Frame
        WSS-->>Agent: Return PONG Frame
    end
```

---

## 4. Task Orchestration & State Machine

The following state machine governs the complete lifecycle of tasks dispatched from the control plane to endpoints.

```mermaid
stateDiagram-v2
    [*] --> PENDING: Task Created via API / Scheduler
    PENDING --> DISPATCHED: Pushed over Active WSS Stream (60s lease started)
    DISPATCHED --> RUNNING: Agent Acknowledges Receipt & Spawns Task Goroutine
    DISPATCHED --> QUEUED: Lease Expired / Agent Disconnected (Auto-Requeue)
    QUEUED --> DISPATCHED: Re-dispatched on Reconnection
    RUNNING --> COMPLETED: Signed Result Ingested & Verified
    RUNNING --> FAILED: Scanner Error / Timeout (>30s)
    PENDING --> CANCELLED: Aborted by User
    DISPATCHED --> CANCELLED: Aborted by User
    RUNNING --> CANCELLED: Aborted by User (Go context cancelled)
    COMPLETED --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
```

---

## 5. Scanner Execution & Sandboxing Model

Every capability execution on the agent is strictly isolated:

```mermaid
sequenceDiagram
    autonumber
    participant Worker as Agent Task Dispatcher
    participant Sandbox as OS Resource Sandbox
    participant Scanner as Native Scanner Engine
    participant OS as OS Kernel & Syscall API

    Worker->>Worker: Create Go `context.WithTimeout(30s)`
    Worker->>Sandbox: Apply OS Limits (Windows Job Object / Linux cgroups)
    Worker->>Scanner: Invoke Scanner (`SCAN_NETWORK`)
    Scanner->>OS: Direct Syscall / COM API (`GetExtendedTcpTable`, Netlink)
    OS-->>Scanner: Return Raw OS Sockets & Routing State
    Scanner->>Scanner: Compute SHA-256 Hashes & Structure Data
    Scanner-->>Worker: Return Structured Observation & Evidence Artifact
    Worker->>Worker: Sign Payload with Ed25519 Private Key
    Worker->>Worker: Transmit Result Frame over Outbound WSS
```

---

## 6. Finding, Evidence & Risk Pipeline

The following state machine defines the lifecycle of security findings:

```mermaid
stateDiagram-v2
    [*] --> OPEN: Ingested & Hashed (SHA-256 Fingerprint Generated)
    OPEN --> ACKNOWLEDGED: Reviewed by Security Operator
    OPEN --> MUTED: Suppressed by Operator Policy
    ACKNOWLEDGED --> RESOLVED: Verified Fixed by Re-scan
    OPEN --> RESOLVED: Verified Fixed by Re-scan
    RESOLVED --> REOPENED: Re-scan Detects Defect Reappeared
    REOPENED --> ACKNOWLEDGED: Operator Review
    REOPENED --> RESOLVED: Re-verified Fixed
    MUTED --> OPEN: Un-muted by Operator
```

---

## 7. Network Discovery & Topology Synthesis Engine

```mermaid
sequenceDiagram
    autonumber
    participant AgentA as Agent PC-01 (192.168.1.10)
    participant AgentB as Agent PC-02 (192.168.1.20)
    participant Gateway as NETRA WSS Ingress
    participant TopEngine as Topology Synthesis Engine
    participant DB as PostgreSQL 16 (Recursive CTEs)

    AgentA->>Gateway: Report ARP Cache (Gateway: 192.168.1.1, MAC: 00:1A:...)
    Gateway->>TopEngine: Forward Telemetry
    AgentB->>Gateway: Report ARP Cache (Gateway: 192.168.1.1, MAC: 00:1A:...)
    Gateway->>TopEngine: Forward Telemetry

    TopEngine->>TopEngine: Correlate Shared Gateway IP/MAC & Subnet Mask
    TopEngine->>DB: Upsert Node `Subnet: 192.168.1.0/24`
    TopEngine->>DB: Upsert Node `Router: 192.168.1.1`
    TopEngine->>DB: Upsert Link `PC-01 ──> Subnet: 192.168.1.0/24`
    TopEngine->>DB: Upsert Link `PC-02 ──> Subnet: 192.168.1.0/24`
    DB-->>TopEngine: Topology Graph Synced (Available for Recursive CTE Queries)
```

---

## 8. Offline Buffering & Synchronization Lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant Worker as Agent Worker
    participant SQLite as Local Encrypted SQLite Store
    participant WSS as WSS Stream Gateway
    participant DB as PostgreSQL Core

    Note over Worker: Network Partition Occurs (WSS Drops)
    Worker->>Worker: Scheduled Scan Generates Finding
    Worker->>SQLite: Write Row to Encrypted `offline_queue` (AES-256)
    SQLite-->>Worker: Row Persisted (FIFO Index Created)

    Note over Worker: Network Connection Restored
    Worker->>WSS: Re-establish WSS Stream (Ed25519 Handshake)
    WSS-->>Worker: Handshake Succeeded (Code 1000)

    loop Drain Buffer (FIFO Order)
        Worker->>SQLite: Read Oldest Batch (Limit 50)
        Worker->>WSS: Transmit Buffered Finding Frame
        WSS->>DB: Deduplicate & Ingest Finding
        WSS-->>Worker: Acknowledge Batch Ingested
        Worker->>SQLite: Delete Processed Rows
    end
```

---

## 9. Concurrency & Resource Control Model

```mermaid
flowchart TD
    subgraph ConcurrencyControls["Agent Resource & Concurrency Controls"]
        T1["Incoming Task Queue"] --> T2{"Active Task Count < 2?"}
        T2 -- Yes --> T3["Spawn Goroutine & Apply Cgroup/JobObject (20% CPU)"]
        T2 -- No --> T4["Buffer in Local Queue"]
        T3 --> T5["Check Heap Allocation (`ReadMemStats`)"]
        T5 -- Heap < 80MB --> T6["Execute Scanner"]
        T5 -- Heap >= 80MB --> T7["Pause Non-Critical Scans & Trigger GC"]
    end
```
