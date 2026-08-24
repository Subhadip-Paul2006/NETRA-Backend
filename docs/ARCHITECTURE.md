# NETRA — Comprehensive System Architecture & Design Principles

> **Overview**
>
> This document provides the master technical architecture for NETRA (Network & Endpoint Threat Reconnaissance Architecture). It establishes the core design principles, runtime component subsystems, local-first storage models, cloud coordination layers, browser exposure abstractions, and architectural decision records (ADRs) governing the platform.

**Status:** Specified / Designed  
**Audience:** System Architects, Core Developers, Security Researchers, Technical Contributors  
**Purpose:** Serves as the authoritative architectural reference for all NETRA engineering implementations and component interactions.

---

## Contents

1. [Architectural Principles & Academic Identity](#1-architectural-principles--academic-identity)
2. [High-Level System Topology](#2-high-level-system-topology)
3. [Dual Runtime Architecture (Daemon vs. CLI)](#3-dual-runtime-architecture-daemon-vs-cli)
4. [Endpoint Agent Internal Subsystems](#4-endpoint-agent-internal-subsystems)
5. [Local-First Data Architecture (SQLite Core)](#5-local-first-data-architecture-sqlite-core)
6. [Network Intelligence & Topology Architecture](#6-network-intelligence--topology-architecture)
7. [Browser & Web Exposure Observation Subsystem](#7-browser--web-exposure-observation-subsystem)
8. [Vulnerability Intelligence Subsystem](#8-vulnerability-intelligence-subsystem)
9. [Policy & Controlled Remediation Architecture](#9-policy--controlled-remediation-architecture)
10. [Control API & Supabase Coordination Layer](#10-control-api--supabase-coordination-layer)
11. [Cross-Platform OS Abstraction Layer](#11-cross-platform-os-abstraction-layer)
12. [Supply Chain Security & TUF Update Model](#12-supply-chain-security--tuf-update-model)
13. [Security Trust, Data & Failure Boundaries](#13-security-trust-data--failure-boundaries)
14. [Architectural Decision Records (ADRs)](#14-architectural-decision-records-adrs)

---

## 1. Architectural Principles & Academic Identity

NETRA is an open-source academic research project developed to demonstrate robust defensive security engineering:

```mermaid
flowchart LR
    subgraph Principles["Core Architecture Principles"]
        P1["1. Local-First Determinism<br/>(SQLite State & Hashed Evidence)"]
        P2["2. Zero Inbound Exposure<br/>(100% Outbound TLS 1.3 Streams)"]
        P3["3. Strict Capability Whitelisting<br/>(Zero Arbitrary Remote Shells)"]
        P4["4. Privacy-Preserving Telemetry<br/>(Configuration & Reachability Only)"]
    end
```

---

## 2. High-Level System Topology

```mermaid
flowchart TD
    subgraph Host["Monitored Endpoint Host (Windows / Linux / macOS)"]
        Supervisor["NETRA Supervisor Daemon (OS Service)"]
        Worker["NETRA Sandboxed Worker Process"]
        SQLite[("Local SQLite WAL DB<br/>(Encrypted State & FIFO Queue)")]
        CLI["netra CLI Tool (Operator / CI)"]
        
        Supervisor <-->|IPC Socket| Worker
        Worker <--> SQLite
        CLI <-->|Local Query / IPC| Worker
    end

    subgraph Cloud["Central Control Plane (Optional Cloud Coordination)"]
        WSS["Stream Gateway (WSS TLS 1.3 / Protobuf)"]
        API["Control API (Go / REST / OpenAPI 3.1)"]
        Supa[("Supabase / PostgreSQL 16 Core<br/>(Row-Level Security / CTE Graph Engine)")]
        
        WSS <--> API
        API <--> Supa
    end

    subgraph Integrations["Integration Layer"]
        Slack["Slack Bot (Approval Gateway)"]
        Discord["Discord Webhook (Homelab Notifier)"]
    end

    Worker -->|Outbound WSS / Ed25519 Signed| WSS
    API --> Slack
    API --> Discord
```

---

## 3. Dual Runtime Architecture (Daemon vs. CLI)

NETRA decouples interactive analysis from continuous monitoring using a unified binary:

```mermaid
flowchart TD
    subgraph RuntimeModes["Runtime Execution Modes"]
        direction TB
        subgraph Mode1["1. Interactive CLI Mode (`netra scan`)"]
            CLIExec["User executes CLI command"] --> LocalEngine["Run in-process scanner OR query local daemon"]
            LocalEngine --> StreamSplit["Split Streams: stdout (JSON data) / stderr (ANSI UI)"]
        end
        
        subgraph Mode2["2. Continuous Daemon Mode (`netra service`)"]
            ServiceExec["OS starts background unit (systemd / Windows SCM)"] --> SupDaemon["Supervisor manages watchdog & sandboxed worker"]
            SupDaemon --> StreamOut["Maintain persistent WSS stream to Control API"]
        end
    end
```

---

## 4. Endpoint Agent Internal Subsystems

```mermaid
flowchart TD
    subgraph AgentSubsystems["NETRA Agent Core Subsystems"]
        CoreLoop["Event Loop & Scheduler"]
        
        CoreLoop --> SockProbe["Socket & Network Observer"]
        CoreLoop --> ProcProbe["Process & Binary Auditor"]
        CoreLoop --> FWProbe["OS Firewall & Filter Inspector"]
        CoreLoop --> UserProbe["User & Privilege Auditor"]
        CoreLoop --> WebProbe["Browser Exposure Observer"]
        
        SockProbe --> Dedupe["Deduplication Engine (SHA-256)"]
        ProcProbe --> Dedupe
        FWProbe --> Dedupe
        UserProbe --> Dedupe
        WebProbe --> Dedupe
        
        Dedupe --> LocalStore[("Local SQLite Queue")]
        LocalStore --> Transport["WSS Protocol Buffer Client"]
    end
```

---

## 5. Local-First Data Architecture (SQLite Core)

To guarantee resilience during network partitions, the agent stores configuration, evidence, and pending sync batches locally in SQLite:

* **WAL Mode**: `PRAGMA journal_mode = WAL;` enables concurrent reads by the CLI while the worker daemon writes.
* **Bounded FIFO Queue**: If the host is offline, observations are queued locally up to 500MB, pruning resolved or low-priority items first.

---

## 6. Network Intelligence & Topology Architecture

NETRA correlates local network configuration across all enrolled endpoints without invasive port scanning:

```mermaid
flowchart LR
    AgentA["Host A (192.168.1.10)"] -->|Report ARP Table| ControlAPI["Control API Graph Synthesizer"]
    AgentB["Host B (192.168.1.20)"] -->|Report ARP Table| ControlAPI
    
    ControlAPI --> PostgresCTE[("PostgreSQL 16 Recursive CTEs<br/>(Reachability & Path Traversal)")]
    PostgresCTE --> TopologyMap["Synthesized Network Topology Map<br/>• Gateway: 192.168.1.1<br/>• Common Subnet: /24<br/>• Unmanaged Nodes Flagged"]
```

---

## 7. Browser & Web Exposure Observation Subsystem

Correlates OS network sockets with browser binaries to identify unauthorized external exposures:
* **Passive Correlation**: Reads OS socket tables (`GetExtendedTcpTable` / Netlink) and matches PID to known browser binaries.
* **Domain Resolution**: Uses OS DNS cache and TLS SNI headers observed at TCP connect time.
* **Academic Privacy Boundary**: Never inspects web page DOM, cookies, HTTP bodies, or user keystrokes.

---

## 8. Vulnerability Intelligence Subsystem

Correlates installed software inventories with cached CVE catalogs:
* **Local Parsing**: Queries OS package managers and registry keys.
* **CPE Normalization**: Maps software to CPE 2.3 identifiers.
* **Offline Matching**: Matches versions against cached NVD/OSV feeds stored in local SQLite or PostgreSQL.

---

## 9. Policy & Controlled Remediation Architecture

```mermaid
flowchart TD
    Finding["Security Finding (e.g., Port 445 Open on 0.0.0.0)"] --> PolicyEngine["Deterministic Policy Engine"]
    PolicyEngine --> HumanGate{"Remediation Approved?<br/>(CLI / Slack Interactive)"}
    
    HumanGate -- Approved --> PreCheck["1. Pre-Flight Safety Verification"]
    PreCheck -- Pass --> ApplyFix["2. Apply Native OS Change (e.g. Add Firewall Rule)"]
    ApplyFix --> PostCheck["3. Post-Remediation Verification Probe"]
    
    PostCheck -- Verified --> Resolved["4. Mark Finding RESOLVED"]
    PostCheck -- Failed --> Rollback["5. Rollback to Original State & Alert"]
```

---

## 10. Control API & Supabase Coordination Layer

* **Supabase / PostgreSQL Core**: Serves as the central data store enforcing multi-tenant isolation via Row-Level Security (`SET LOCAL app.current_tenant_id`).
* **Architectural Decoupling**: Endpoints never connect directly to the database; all traffic routes through the authenticated Control API / WSS Gateway.

---

## 11. Cross-Platform OS Abstraction Layer

```mermaid
flowchart TD
    Core["NETRA Common Core (Go)"]
    
    Core --> WinAdapter["Windows Adapter<br/>• `Iphlpapi.dll` (Sockets & ARP)<br/>• `INetFwPolicy2` (Firewall COM)<br/>• DPAPI Key Storage<br/>• Job Objects Limits"]
    Core --> LinuxAdapter["Linux Adapter<br/>• Netlink `rtnetlink` (Sockets)<br/>• `nftables` / `iptables`<br/>• SecretService Key Storage<br/>• cgroups v2 Limits"]
    Core --> MacAdapter["macOS Adapter<br/>• `sysctl` / `getifaddrs`<br/>• `pfctl` Packet Filter<br/>• Apple Keychain Storage<br/>• POSIX Resource Limits"]
```

---

## 12. Supply Chain Security & TUF Update Model

* **Hermetic Compilation**: `CGO_ENABLED=0` static Go binaries.
* **Artifact Provenance**: Syft generates CycloneDX/SPDX SBOMs; Cosign signs release binaries via GitHub OIDC.
* **Atomic Binary Updates**: Downloaded updates are verified against TUF signed manifests and swapped atomically on disk.

---

## 13. Security Trust, Data & Failure Boundaries

```mermaid
flowchart TD
    subgraph Unauthenticated["Untrusted Zone"]
        UnenrolledHost["Unenrolled Machine"]
    end

    subgraph HostDACL["Host Trust Boundary (DACL 0600)"]
        Supervisor["Supervisor (Elevated)"]
        Worker["Worker (Sandboxed)"]
    end

    subgraph CloudBoundary["Control Plane Trust Boundary"]
        WSS["WSS Stream Ingress"]
        API["Control API (JWT Validated)"]
        DB[("PostgreSQL 16 (RLS Isolated)")]
    end

    UnenrolledHost -->|Single-Use Enrollment Token| WSS
    Worker -->|Ed25519 Signed Frames| WSS
    WSS --> API
    API --> DB
```

---

## 14. Architectural Decision Records (ADRs)

| ADR ID | Decision | Chosen Approach | Rejected Alternative | Core Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **ADR-001** | Agent Implementation Language | **Go (Golang 1.22+)** | Python / PyInstaller | Single static binary (<20MB), low memory (<25MB RAM), sub-millisecond cold start, native Win32/Netlink syscall bindings. |
| **ADR-002** | Device Transport Protocol | **Outbound WebSocket over TLS 1.3 (Protobuf)** | Inbound REST / gRPC | Traverses NAT gateways with zero open client firewall ports. Protobuf ensures minimal bandwidth. |
| **ADR-003** | Local State Management | **Local SQLite (WAL Mode)** | JSON files / Raw memory | ACID safety, WAL non-blocking concurrent reads, resilient offline buffering up to 500MB. |
| **ADR-004** | Topology & Reachability Graph | **PostgreSQL 16 Recursive CTEs** | Dedicated Neo4j Cluster | Sub-10ms graph path queries for <50k nodes within existing ACID transaction boundary; zero dual-write operational overhead. |
| **ADR-005** | Third-Party Integrations | **Slack (Async Gateway) / Discord (Outbound Webhook)** | Discord as Primary Control Plane | Discord lacks enterprise RBAC and SSO. Positioned strictly as optional notification plugins. |
