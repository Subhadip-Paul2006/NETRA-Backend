# NETRA — Product Requirements Document (PRD)

> **Document Status:** Approved Specification  
> **Target Version:** v1.0.0-MVP  
> **Authoritative Scope:** Defines product vision, target personas, functional requirements, MVP boundaries, non-goals, and success metrics for NETRA.  
> **Related Documents:** [TRD.md](./TRD.md), [ARCHITECTURE.md](./ARCHITECTURE.md), [PHASES.md](./PHASES.md)

---

## Contents

1. [Product Overview & Vision](#1-product-overview--vision)
2. [Problem Statement & Product Thesis](#2-problem-statement--product-thesis)
3. [Target Users & User Personas](#3-target-users--user-personas)
4. [User Problems & Core Value Propositions](#4-user-problems--core-value-propositions)
5. [Product Goals & Non-Goals](#5-product-goals--non-goals)
6. [Core Product Capabilities](#6-core-product-capabilities)
7. [Functional Requirements](#7-functional-requirements)
8. [Non-Functional Requirements](#8-non-functional-requirements)
9. [User Journeys](#9-user-journeys)
10. [Minimum Viable Product (MVP) Scope](#10-minimum-viable-product-mvp-scope)
11. [Future Product Roadmap](#11-future-product-roadmap)
12. [Success Metrics & Acceptance Criteria](#12-success-metrics--acceptance-criteria)
13. [Constraints, Assumptions & Product Risks](#13-constraints-assumptions--product-risks)

---

## 1. Product Overview & Vision

**NETRA** (Network & Endpoint Threat Reconnaissance Architecture) is an open-source, topology-aware security reasoning platform and host posture management engine. It enables small-to-medium enterprises, infrastructure engineers, and security teams to gain continuous, explainable visibility into endpoint vulnerabilities, configuration drift, and local network reachability without deploying heavy, expensive enterprise EDR suites.

### Vision Statement
To become the global open-source standard for **topology-aware security posture reasoning**, empowering every engineering team to understand, visualize, and secure their computing environment through transparent, deterministic evidence.

### Mission Statement
Deliver a single, ultra-lightweight Go binary and a resilient control plane that automatically correlates endpoint configurations with local network topology, providing instant, verifiable risk insights.

```mermaid
flowchart TD
    subgraph Mission["NETRA Core Mission"]
        P1["Ultra-Lightweight Go Agent<br/>(<20MB, <25MB RAM, No Kernel Drivers)"]
        P2["Deterministic Evidence Chain<br/>(SHA-256 Fingerprinting, 0% Duplicates)"]
        P3["Environmental Topology Context<br/>(Local Subnet Reachability & Routes)"]
    end
    P1 --> Solution["Explainable Security Posture & Verifiable Remediation"]
    P2 --> Solution
    P3 --> Solution
```

---

## 2. Problem Statement & Product Thesis

### 2.1 Problem Statement
Engineering and security teams face a critical dilemma:
* **Enterprise EDRs** (CrowdStrike, Defender, SentinelOne) are opaque, cost-prohibitive ($150+/node), require dedicated SOC analysts, and operate as cloud black-boxes that ignore local network topology.
* **Open-Source Tools** (osquery, Wazuh) output overwhelming streams of disconnected event logs without synthesizing relational context (e.g., *Is this open port reachable from an adjacent unmanaged subnet?*).

```mermaid
flowchart TD
    subgraph ProblemSpace["The Security Dilemma"]
        EDR["Enterprise EDR Platforms<br/>• $150k+/year contracts<br/>• Opaque cloud black-box<br/>• Heavy kernel drivers<br/>• Zero local network topology context"]
        OSS["Open-Source Event Collectors<br/>• Uncurated log firehose<br/>• Manual correlation required<br/>• Complex multi-node cluster ops<br/>• No built-in remediation validation"]
    end
    EDR --> Void["THE CONTEXTUAL VOID<br/>No single tool connects endpoint posture with local network reachability simply and deterministically."]
    OSS --> Void
    Void --> NETRA["NETRA PLATFORM<br/>Lightweight, Open, Topology-Aware & Explainable"]
```

### 2.2 Product Thesis
> **"NETRA exists to provide engineering and security teams with an open, topology-aware security reasoning platform that bridges the gap between endpoint posture and network reachability through a single, ultra-lightweight agent and an explainable, deterministic evidence pipeline."**

---

## 3. Target Users & User Personas

```mermaid
flowchart LR
    subgraph Personas["Target User Personas"]
        Alex["Alex (SME Security Lead)<br/>• 300 mixed endpoints<br/>• Solo SecOps team<br/>• Needs low-noise compliance"]
        Devin["Devin (DevSecOps Engineer)<br/>• Cloud VMs & Developer laptops<br/>• Automated CI/CD pipelines<br/>• Needs CLI/JSON posture checks"]
        Sam["Sam (MSSP Security Consultant)<br/>• Multiple client networks<br/>• Rapid onboarding audits<br/>• Needs multi-tenant isolation"]
    end
```

---

## 4. User Problems & Core Value Propositions

```mermaid
flowchart TD
    subgraph ValueProp["Problem to Solution Mapping"]
        P_Alert["Alert Fatigue<br/>(Thousands of uncurated CVEs)"] --> S_Ev["Deterministic Evidence Pipeline<br/>(Flags findings only when service is reachable)"]
        P_Net["No Network Context<br/>(Host alerts don't show reachability)"] --> S_Top["Automated Topology Synthesis<br/>(Correlates ARP, gateways & subnets)"]
        P_Res["Heavy Agent Bloat<br/>(Security agents crashing dev boxes)"] --> S_Go["Ultra-Lightweight Go Agent<br/>(<20MB binary, <25MB RAM idle)"]
        P_Rem["Opaque Remediation<br/>(Automated fixes breaking production)"] --> S_Val["Validated Remediation Guidance<br/>(Human-approved with post-validation checks)"]
    end
```

---

## 5. Product Goals & Non-Goals

```mermaid
flowchart TD
    subgraph Boundaries["Product Boundary & Scope Model"]
        subgraph Goals["CORE GOALS"]
            G1["Single-command deployment in <30s"]
            G2["Deterministic 8-stage evidence reasoning"]
            G3["Cross-platform (Windows, Linux, macOS)"]
            G4["Database-enforced multi-tenant isolation"]
            G5["CLI-first Unix composability (`netra --json`)"]
        end
        subgraph NonGoals["EXPLICIT NON-GOALS"]
            NG1["NOT a Real-Time Kernel Antivirus / Driver"]
            NG2["NOT a Centralized SIEM Log Ingestion Lake"]
            NG3["NOT an Arbitrary Remote Shell Backdoor"]
            NG4["NOT an Autonomous AI Remediation Decision-Maker"]
        end
    end
```

---

## 6. Core Product Capabilities

```mermaid
flowchart TD
    subgraph Capabilities["NETRA Core Capabilities"]
        CAP1["Host Inventory (`CAP_HOST_INVENTORY`)<br/>Hardware, OS Build, CPU/RAM, Uptime"]
        CAP2["Network & Sockets (`CAP_SCAN_NETWORK`)<br/>Adapters, Routes, DNS, Listening Ports & PIDs"]
        CAP3["Process Lineage (`CAP_SCAN_PROCESSES`)<br/>Process Trees, Command Lines, SHA-256 Hashes"]
        CAP4["Firewall Posture (`CAP_SCAN_FIREWALL`)<br/>Active Profiles, Default Policies, Filter Rules"]
        CAP5["User Privileges (`CAP_SCAN_USERS`)<br/>Local Accounts, Sudoers, Admin Groups"]
        CAP6["Persistence Auditing (`CAP_SCAN_STARTUP`)<br/>Services, Systemd Units, Cron, Tasks"]
        CAP7["Topology Mapping (`CAP_RECON_TOPOLOGY`)<br/>Subnet ARP Scans, Gateway Hops"]
    end
```

---

## 7. Functional Requirements

### 7.1 Agent Lifecycle & Management
* `[PRD-FR-01]` The agent must generate a cryptographically secure Ed25519 keypair upon enrollment and persist the private key in OS-protected storage.
* `[PRD-FR-02]` The agent must establish an outbound persistent WebSocket (WSS) connection to the backend over TLS 1.3 with zero inbound listening ports.
* `[PRD-FR-03]` The agent must automatically buffer findings locally in an encrypted SQLite database during network disconnects and synchronize upon reconnection.

### 7.2 Posture & Network Reconnaissance
* `[PRD-FR-04]` The agent must enumerate listening TCP/UDP sockets and bind each socket to its owning Process ID (PID), executable binary path, and user account.
* `[PRD-FR-05]` The agent must inspect the host firewall state using native platform APIs and identify if any profile is disabled or misconfigured.
* `[PRD-FR-06]` The agent must read local ARP tables and default gateways to construct a local network reachability map.

### 7.3 Findings, Deduplication & Evidence
* `[PRD-FR-07]` The system must compute a deterministic SHA-256 fingerprint for every finding to eliminate alert duplicates across repetitive scans.
* `[PRD-FR-08]` Every finding must be linked to an immutable evidence payload containing raw technical artifacts.
* `[PRD-FR-09]` Finding states must strictly follow the lifecycle: `OPEN` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED` $\rightarrow$ `REOPENED` $\rightarrow$ `MUTED`.

### 7.4 CLI & Automation
* `[PRD-FR-10]` The `netra` CLI must provide interactive human-readable outputs on TTYs and pure, unadorned JSON when invoked with `--json`.
* `[PRD-FR-11]` The CLI must return standard exit codes: `0` (clean), `1` (system error), `2` (policy violation / high severity detected).

---

## 8. Non-Functional Requirements

* `[PRD-NFR-01]` **Agent Resource Limits**: Static binary $<20\text{MB}$, idle RAM $<25\text{MB}$, peak scan RAM $<100\text{MB}$, idle CPU $<0.1\%$.
* `[PRD-NFR-02]` **Cold-Start Time**: Agent initialization and backend handshake completed in $<500\text{ms}$.
* `[PRD-NFR-03]` **Crash Isolation**: Scanner panics or OS API failures must be caught cleanly and never crash the supervisor daemon.
* `[PRD-NFR-04]` **Backend Scalability**: Single backend node must sustain $\ge 5,000$ active concurrent agent WSS connections.
* `[PRD-NFR-05]` **Zero-Trust Multi-Tenancy**: Logical and relational data isolation enforced at the PostgreSQL database level via Row-Level Security.

---

## 9. User Journeys

The following journey diagram illustrates how a solo security lead (Alex) deploys NETRA, investigates an exposed service finding, applies a configuration fix, and verifies the resolution deterministically.

```mermaid
journey
    title Alex's Journey: Host Onboarding, Discovery, Remediation & Verification
    section Onboarding
      Generate enrollment token in Web Console: 5: Alex
      Run single-line install on Linux server: 5: Alex
      Agent registers via Ed25519 & connects over WSS: 5: NETRA Agent
    section Reconnaissance
      Automatic initial baseline posture scan: 5: NETRA Agent
      Correlate listening sockets with external IP: 5: NETRA Backend
      Synthesize local subnet reachability graph: 5: NETRA Backend
    section Investigation
      Inspect high-severity finding via CLI (`netra findings list`): 4: Alex
      Review cryptographic evidence & attack path explanation: 5: Alex
    section Remediation & Validation
      Apply recommended firewall isolation: 4: Alex
      Run post-remediation validation scan (`netra scan --firewall`): 5: Alex
      Finding automatically transitions to RESOLVED state: 5: NETRA Backend
```

---

## 10. Minimum Viable Product (MVP) Scope

```mermaid
flowchart TD
    subgraph MVPScope["NETRA MVP Scope Boundaries"]
        subgraph MustHave["MUST HAVE (Phase 1 MVP)"]
            M1["Go Agent for Windows & Linux (x86_64/ARM64)"]
            M2["Outbound WSS with Ed25519 Device Auth"]
            M3["4 Core Scanners: Network, Processes, Firewall, Users"]
            M4["PostgreSQL 16 Multi-Tenant RLS Backend"]
            M5["Deterministic SHA-256 Deduplication Engine"]
            M6["CLI Tool (`netra`): enroll, status, scan, findings"]
        end
        subgraph ShouldHave["SHOULD HAVE (Phase 2)"]
            S1["Local Encrypted SQLite Offline Buffer"]
            S2["Asynchronous Slack Webhook Alerts"]
            S3["Advisory AI Natural Language Explanations"]
            S4["macOS Apple Silicon Support"]
        end
        subgraph MustNotHave["MUST NOT HAVE (Out of Scope)"]
            N1["Kernel Anti-Malware File Interceptors"]
            N2["Arbitrary Remote Shell Execution"]
            N3["Discord Interactive Control Plane"]
            N4["Dedicated Neo4j Graph DB Clusters"]
        end
    end
```

---

## 11. Future Product Roadmap

* **Phase 2 (Topology & AI Reasoning)**: Cross-agent ARP/routing graph correlation; macOS Apple Silicon support; advisory AI risk explanations.
* **Phase 3 (Validated Remediation)**: Controlled, safe remediation playbooks with automatic pre/post validation probes; TUF-compliant auto-updates.
* **Phase 4 (Enterprise Scale & Compliance)**: TimescaleDB telemetry offload for 10,000+ nodes; CIS Benchmark compliance reporting; Linux eBPF telemetry.

---

## 12. Success Metrics & Acceptance Criteria

1. **Deployment Friction**: New agent deployed and enrolled in $<30$ seconds.
2. **Resource Footprint**: Agent idle memory verified $\le 25\text{MB}$ across all supported platforms.
3. **Alert Noise Reduction**: $0\%$ duplicate finding creation across continuous 60-second scan intervals.
4. **Offline Resilience**: Agent retains $100\%$ of offline findings during a 24-hour network outage and flushes upon reconnection.
5. **Security Verification**: $0$ arbitrary command execution vulnerabilities in penetration testing.

---

## 13. Constraints, Assumptions & Product Risks

* **Constraint**: Must operate entirely in user-space without custom signed kernel drivers.
* **Assumption**: Client environments permit outbound TCP traffic on port 443 (HTTPS/WSS).
* **Product Risk**: Overzealous automated remediation causing system instability $\longrightarrow$ *Mitigated by requiring human approval and strict validation checks*.
