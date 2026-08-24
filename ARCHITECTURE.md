# NETRA — System Architecture & Architectural Decision Records (ADRs)

> **Document Status:** Approved Architecture  
> **Target Version:** v1.0.0-MVP  
> **Authoritative Scope:** Comprehensive system architecture, component boundaries, data flow topologies, and Architectural Decision Records (ADRs) for NETRA.  
> **Related Documents:** [SYSTEM_DESIGN.md](./SYSTEM_DESIGN.md), [SECURITY_CHECK.md](./SECURITY_CHECK.md), [TRD.md](./TRD.md)

---

## Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Architectural Principles](#2-architectural-principles)
3. [System Boundaries & Trust Domains](#3-system-boundaries--trust-domains)
4. [Component Architecture](#4-component-architecture)
5. [Network Topology & Data Flow](#5-network-topology--data-flow)
6. [Architectural Decision Records (ADRs)](#6-architectural-decision-records-adrs)
7. [Scalability & Evolution Strategy](#7-scalability--evolution-strategy)
8. [Failure Domains & Fault Isolation](#8-failure-domains--fault-isolation)

---

## 1. Architectural Overview

NETRA is designed as a **decoupled, multi-tenant security reconnaissance and posture management platform**. It combines a lightweight, single-binary Go endpoint agent with a stateless, streaming backend and an event-driven PostgreSQL relational core.

```mermaid
flowchart TD
    subgraph ClientHost["Managed Endpoint Host (Client PC / Server)"]
        subgraph Supervisor["Supervisor Service (SYSTEM / root Daemon)"]
            Watchdog["Watchdog Process Monitor"]
            KeyBroker["Secure OS Keyring Broker"]
            Updater["TUF Signed Auto-Updater"]
        end
        subgraph Worker["Worker Agent (`netra` Go Binary)"]
            WSSClient["WSS Stream Engine (TLS 1.3)"]
            Sandbox["Task Execution Sandbox (cgroups / Job Objects)"]
            LocalCache[("Offline SQLite DB (AES-256)")]
            Scanners["Scanners: Network, Processes, Firewall, Users"]
        end
        Supervisor <-- Local IPC (Named Pipe / Domain Socket) --> Worker
    end

    subgraph ControlPlane["NETRA Control Plane (Cloud / On-Prem)"]
        APIGateway["Stateless REST API Gateway"]
        WSSGateway["Persistent WSS Stream Gateway"]
        TaskEngine["Durable Task Orchestrator"]
        IntelEngine["Security Finding & Deduplication Engine"]
        AILayer["Advisory AI Explanation Engine"]
        Postgres[("PostgreSQL 16 Relational Core<br/>Row-Level Security + Recursive Graph CTEs")]

        APIGateway <--> Postgres
        WSSGateway <--> Postgres
        TaskEngine <--> Postgres
        IntelEngine <--> Postgres
        AILayer -. Advisory Queries .-> Postgres
    end

    subgraph Management["Management & External Integrations"]
        CLI["CLI Tool (`netra`)"]
        WebUI["Web Console (Next.js)"]
        Slack["Slack Webhook Gateway"]
    end

    CLI -->|HTTPS REST| APIGateway
    WebUI -->|HTTPS REST| APIGateway
    APIGateway -->|Outbound Webhook| Slack
    Worker -->|Outbound WSS / Ed25519 Signed| WSSGateway
```

---

## 2. Architectural Principles

1. **Evidence Precedes Finding**: No security finding exists without an immutable, cryptographically verifiable evidence artifact.
2. **Deterministic Core, Advisory AI**: Security rules, finding transitions, and remediation commands are 100% deterministic; AI is strictly restricted to explanations and queries.
3. **Least Privilege by Default**: Agents run with bounded OS privileges; high-privilege scans are isolated.
4. **Zero Inbound Ports**: Agent hosts never open inbound listening ports. All communication is outbound persistent TLS 1.3 over WebSocket.
5. **Asymmetric Cryptographic Identity**: Every device is uniquely identified via an Ed25519 keypair; shared secrets are prohibited across the wire.
6. **Strict Capability Model**: Remote arbitrary code evaluation (`exec`/`eval`) is structurally forbidden.
7. **Database-Enforced Multi-Tenancy**: Logical isolation is guaranteed by PostgreSQL Row-Level Security (RLS).
8. **Fail-Safe & Offline-Tolerant**: Network partitions never crash the agent; data is buffered locally in encrypted SQLite storage.
9. **Single Static Binaries**: The endpoint agent is compiled in Go with zero external runtime dependencies (`CGO_ENABLED=0`).

---

## 3. System Boundaries & Trust Domains

```mermaid
flowchart TD
    subgraph TD1["TRUST DOMAIN 1: Host Userspace"]
        Worker["Worker Agent (`netra` Go Binary)<br/>Runs unprivileged / Sandboxed with cgroups"]
    end

    subgraph TD2["TRUST DOMAIN 2: Host Privileged Supervisor"]
        Sup["Supervisor Daemon<br/>Runs as SYSTEM / root<br/>Accesses OS DPAPI Keyring"]
    end

    subgraph TD3["TRUST DOMAIN 3: NETRA Control Plane"]
        Gateway["API Gateway & WSS Ingress<br/>Stateless Application Tier"]
        DB[("PostgreSQL 16 Core<br/>Engine-Enforced RLS Isolation")]
        Gateway <--> DB
    end

    subgraph TD4["TRUST DOMAIN 4: Management & Clients"]
        CLI["CLI (`netra`) & Web UI<br/>Authenticated via JWT / OIDC"]
    end

    Worker <-- "Local IPC Boundary (0600 / DACL)" --> Sup
    Worker <-- "TLS 1.3 WSS Boundary (Ed25519 Signed)" --> Gateway
    CLI <-- "HTTPS REST Boundary" --> Gateway
```

---

## 4. Component Architecture

```mermaid
flowchart TD
    subgraph AgentSubsystem["Endpoint Agent Subsystem"]
        S1["Supervisor Daemon"] -->|Monitors| S2["Worker Engine"]
        S2 --> S3["WSS Comm Loop"]
        S2 --> S4["Task Dispatcher"]
        S2 --> S5["Encrypted SQLite Store"]
        S4 --> S6["Native OS Scanners"]
    end

    subgraph BackendSubsystem["Control Plane Subsystem"]
        B1["Stateless REST Gateway"] --> B3["PostgreSQL 16 Core"]
        B2["WSS Ingress Gateway"] --> B3
        B4["Task State Machine"] --> B3
        B5["Finding Deduplicator"] --> B3
        B6["Topology Synthesizer"] --> B3
    end
```

---

## 5. Network Topology & Data Flow

The following sequence details the complete communication flow from device connection to task execution and finding ingestion.

```mermaid
sequenceDiagram
    autonumber
    participant Agent as NETRA Agent (Host)
    participant WSS as WSS Stream Gateway
    participant Backend as Backend Engine
    participant DB as PostgreSQL 16 Core

    Agent->>WSS: Outbound WSS Handshake (TLS 1.3)
    Agent->>WSS: Send Auth Frame (Ed25519 Signature + Device ID)
    WSS->>DB: Fetch Stored Public Key for Device ID
    DB-->>WSS: Return Public Key
    WSS->>WSS: Verify Ed25519 Signature & Timestamp Window
    WSS->>DB: Mark Device State: ONLINE
    WSS-->>Agent: Connection Established (Code 1000)

    Note over Backend,DB: Operator schedules task via CLI
    Backend->>DB: Create Task (Status: PENDING)
    Backend->>WSS: Push Task Dispatch Frame
    WSS->>Agent: Deliver Task Frame over WSS (Capability: SCAN_NETWORK)
    
    Note over Agent: Execute Native OS Syscalls (Sandboxed)
    Agent->>WSS: Send Signed Task Result + Evidence Hash
    WSS->>Backend: Forward Task Execution Result
    Backend->>DB: Compute SHA-256 Finding Fingerprint & Ingest (RLS Scoped)
    Backend->>DB: Update Task State: COMPLETED
    WSS-->>Agent: Acknowledge Result Ingestion
```

---

## 6. Architectural Decision Records (ADRs)

### ADR-01: Go (Golang) as the Endpoint Agent Language
* **Decision**: Build the endpoint agent exclusively in Go (Golang 1.22+).
* **Reason**: Single static binary compilation (`CGO_ENABLED=0`), low idle memory footprint ($<20\text{MB}$ RAM), high concurrency safety (goroutines/channels), fast cold-start ($<50\text{ms}$), and first-class native OS system call packages (`golang.org/x/sys`).
* **Alternatives Considered**: Python 3.11 (PyInstaller), Rust, C++20.
* **Why Rejected**: Python was rejected due to heavy runtime packaging ($>60\text{MB}$), slow startup, and high memory usage. Rust was rejected for slower developer velocity during rapid prototyping. C++ was rejected due to manual memory management and vulnerability risks.
* **Security Implications**: Eliminates buffer overflows and memory corruption vulnerabilities while ensuring high operational stability.

### ADR-02: Outbound WSS (WebSocket over TLS 1.3) with REST Polling Fallback
* **Decision**: Adopt Outbound Persistent WSS as the primary transport protocol, with HTTPS REST Long Polling as a fallback.
* **Reason**: Traverses corporate NATs and firewalls without requiring inbound listening ports; supports instant bidirectional dispatch with minimal overhead.
* **Alternatives Considered**: Inbound REST agent listener, gRPC, MQTT.
* **Why Rejected**: Inbound REST creates an unacceptable security risk (open host ports). MQTT adds unnecessary broker infrastructure (Mosquitto/RabbitMQ).
* **Security Implications**: All streams are encrypted with TLS 1.3 and authenticated per-frame with Ed25519 signatures.

### ADR-03: PostgreSQL 16 with Row-Level Security (RLS) and Recursive CTE Topology Graphing
* **Decision**: Standardize on PostgreSQL 16 as the unified datastore for relational entities, multi-tenancy (RLS), and network topology graphing (Recursive CTEs).
* **Reason**: Unifies data operations in a single ACID-compliant database; eliminates the operational overhead and dual-write sync bugs of a separate graph database (e.g., Neo4j).
* **Alternatives Considered**: MongoDB, Neo4j, Apache AGE, MySQL.
* **Why Rejected**: Neo4j introduces severe operational complexity and lacks unified ACID transaction support with relational tables. MongoDB lacks strict relational integrity.
* **Security Implications**: Database-enforced RLS ensures zero possibility of cross-tenant data leaks even in the event of application-layer authorization bugs.

### ADR-04: Asymmetric Device Identity via Ed25519 Cryptography
* **Decision**: Implement Ed25519 public-key authentication for all agent communication.
* **Reason**: Eliminates shared-secret leakage risks; private keys remain permanently in client OS-protected keystores (DPAPI/SecretService/Keychain).
* **Alternatives Considered**: Shared-secret HMAC-SHA256, X.509 mTLS.
* **Why Rejected**: Shared secrets present server-side database exposure risks. X.509 mTLS introduces heavy PKI/CA certificate management and expiration failure modes.
* **Security Implications**: High cryptographic strength (128-bit security level) with compact 64-byte signatures and constant-time verification.

### ADR-05: Strict Pre-Compiled Capability Whitelist vs. Remote Shell
* **Decision**: Structurally prohibit arbitrary remote command execution (`exec`/`eval`); restrict tasks strictly to pre-compiled enums (`SCAN_NETWORK`, `SCAN_FIREWALL`, etc.).
* **Reason**: Eliminates the risk of the security agent being hijacked as a remote execution backdoor.
* **Alternatives Considered**: Arbitrary remote shell over WSS / SSH wrapper.
* **Why Rejected**: High risk of catastrophic organization-wide compromise if control plane credentials are breached.

---

## 7. Scalability & Evolution Strategy

```mermaid
flowchart TD
    subgraph Scaling["Scalability Progression Model"]
        L1["Level 1 (1–5 Nodes)<br/>Single VM (2 vCPU, 4GB RAM) + PostgreSQL 16"] --> L2["Level 2 (10–100 Nodes)<br/>Standard VM + Managed PostgreSQL"]
        L2 --> L3["Level 3 (100–1,000 Nodes)<br/>Autoscaled API Gateway + Redis 7 WSS Session Hub"]
        L3 --> L4["Level 4 (1,000–10,000+ Nodes)<br/>Kubernetes Cluster + TimescaleDB Telemetry Tier"]
    end
```

---

## 8. Failure Domains & Fault Isolation

```mermaid
flowchart TD
    subgraph FaultIsolation["Fault Isolation Domains"]
        F1["Scanner Panic<br/>Isolated in goroutine; supervisor auto-restarts worker"]
        F2["Network Partition<br/>Agent switches to local encrypted SQLite; flushes on reconnect"]
        F3["Control Plane Restart<br/>Stateless gateways reload; persistent state safe in PostgreSQL"]
    end
```
