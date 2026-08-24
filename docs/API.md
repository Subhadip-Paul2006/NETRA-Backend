# NETRA — Official API Reference & Stream Protocol Specification

> **Overview**
>
> This document provides the complete, authoritative API reference and network communication contracts for NETRA (Network & Endpoint Threat Reconnaissance Architecture). It defines REST endpoints, WebSocket streaming frames, Protocol Buffer schemas, cryptographic authentication headers, error models, and entity data relationships.

**Status:** Specified / Designed  
**Audience:** Backend Engineers, Agent Developers, Security Architects, API Integrators  
**Purpose:** Serves as the immutable protocol specification connecting endpoint agents, central control services, CLI tools, and external notification gateways.

---

## Contents

1. [API Architecture & Actor Boundaries](#1-api-architecture--actor-boundaries)
2. [Authentication, Authorization & Device Attestation](#2-authentication-authorization--device-attestation)
3. [Standard Headers & Cryptographic Request Signing](#3-standard-headers--cryptographic-request-signing)
4. [Universal Request, Response & Error Envelopes](#4-universal-request-response--error-envelopes)
5. [Idempotency & Retry Semantics](#5-idempotency--retry-semantics)
6. [API Data Model & Entity-Relationship Schema](#6-api-data-model--entity-relationship-schema)
7. [WebSocket Agent Stream Protocol (`/v1/agent/stream`)](#7-websocket-agent-stream-protocol-v1agentstream)
8. [Agent-Facing REST Endpoints](#8-agent-facing-rest-endpoints)
9. [Control-Plane Management Endpoints](#9-control-plane-management-endpoints)
10. [Network & Vulnerability Intelligence Endpoints](#10-network--vulnerability-intelligence-endpoints)
11. [Controlled Remediation Endpoints](#11-controlled-remediation-endpoints)
12. [Integration Gateway Endpoints (Slack & Webhooks)](#12-integration-gateway-endpoints-slack--webhooks)
13. [Health, Telemetry & Diagnostics Endpoints](#13-health-telemetry--diagnostics-endpoints)

---

## 1. API Architecture & Actor Boundaries

The NETRA API cleanly separates communication pathways across three distinct actors:

```mermaid
flowchart TD
    subgraph Actors["API Calling Actors"]
        AgentHost["Endpoint Agent Host (Go Binary)"]
        Operator["Human Operator / CLI / Web Console"]
        Integration["Third-Party Webhooks (Slack / CI)"]
    end

    subgraph Boundaries["API Architectural Boundaries"]
        AgentAPI["Agent-Facing API & WSS Gateway<br/>• Outbound WSS (`/v1/agent/stream`)<br/>• Fallback REST (`/v1/agent/poll`, `/v1/agent/enroll`)<br/>• Auth: Ed25519 Request Signing"]
        ControlAPI["Control-Plane Management API<br/>• REST Endpoints (`/v1/devices`, `/v1/findings`, etc.)<br/>• Auth: Bearer JWT / Scoped API Key<br/>• RBAC: Admin / Operator / Auditor"]
        IntegrationAPI["Integration Gateway API<br/>• Webhook Handlers (`/v1/integrations/*`)<br/>• Auth: HMAC Signatures (Slack HMAC-SHA256)"]
    end

    AgentHost --> AgentAPI
    Operator --> ControlAPI
    Integration --> IntegrationAPI
```

---

## 2. Authentication, Authorization & Device Attestation

* **Agent Authentication**: Uses asymmetric **Ed25519 (RFC 8032)** public-key signatures. Endpoints have no shared secrets or passwords.
* **Control-Plane Authentication**: Uses standard JSON Web Tokens (**JWT**) signed by the Supabase / PostgreSQL auth service (RS256/ES256).
* **Role-Based Access Control (RBAC)**:
  - `ROLE_ADMIN`: Full administrative control (Enrollment token generation, device revocation, policy configuration).
  - `ROLE_OPERATOR`: Can trigger scans, view findings, and approve remediation actions.
  - `ROLE_AUDITOR`: Read-only access to findings, topology graphs, and immutable audit logs.

---

## 3. Standard Headers & Cryptographic Request Signing

### 3.1 Agent Cryptographic Headers
Every HTTP request and WebSocket initialization frame dispatched by an enrolled agent must include:

```http
X-NETRA-Device-ID: dev_01h8a9b2c3d4e5f6
X-NETRA-Timestamp: 1776189500
X-NETRA-Nonce: a9f8e7d6-c5b4-4a3b-2a1f-0e9d8c7b6a5f
X-NETRA-Request-ID: req_1122334455667788
X-NETRA-Signature: 6f8b9e... (128-character hex-encoded Ed25519 signature)
```

$$\text{Canonical String} = \text{METHOD} \parallel \text{"\textbackslash n"} \parallel \text{PATH} \parallel \text{"\textbackslash n"} \parallel \text{TIMESTAMP} \parallel \text{"\textbackslash n"} \parallel \text{NONCE} \parallel \text{"\textbackslash n"} \parallel \text{REQUEST\_ID} \parallel \text{"\textbackslash n"} \parallel \text{SHA256}(\text{BODY})$$

---

## 4. Universal Request, Response & Error Envelopes

### 4.1 Standard Success Envelope
```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "request_id": "req_01h8a9b2c3",
    "timestamp": "2026-08-24T12:00:00Z"
  }
}
```

### 4.2 Standard Error Envelope
```json
{
  "success": false,
  "error": {
    "code": "DEVICE_NOT_ENROLLED",
    "message": "The requested device UUID does not exist or has been revoked.",
    "details": { "device_id": "dev_01h8a9b2c3" }
  },
  "meta": {
    "request_id": "req_01h8a9b2c3",
    "timestamp": "2026-08-24T12:00:00Z"
  }
}
```

### Standard Error Codes:
* `AUTH_INVALID_SIGNATURE`: Ed25519 signature verification failed.
* `AUTH_NONCE_REPLAYED`: The provided nonce was seen within the sliding 300s window.
* `DEVICE_REVOKED`: The device has been administratively revoked.
* `CAPABILITY_NOT_WHITELISTED`: The requested task capability is not in the approved pre-compiled whitelist.
* `REMEDIATION_PREFLIGHT_FAILED`: Pre-flight safety checks prevented remediation execution.

---

## 5. Idempotency & Retry Semantics

* **Idempotency Key**: Endpoints supporting state creation (`POST /v1/tasks`, `POST /v1/remediation/apply`) accept an `Idempotency-Key: <UUIDv7>` header. If re-sent with the same key within 24 hours, the server returns the cached response without re-executing.
* **Finding Deduplication**: Findings are ingested via deterministic SHA-256 fingerprints. Ingesting an existing fingerprint updates `last_seen` rather than creating duplicate records.

---

## 6. API Data Model & Entity-Relationship Schema

```mermaid
erDiagram
    TENANT {
        string id PK
        string name
        datetime created_at
    }
    DEVICE {
        string id PK
        string tenant_id FK
        string hostname
        string os_type
        string public_key
        string status
        datetime last_seen
    }
    TASK {
        string id PK
        string device_id FK
        string capability
        string status
        text parameters_json
        datetime created_at
    }
    OBSERVATION {
        string id PK
        string device_id FK
        string task_id FK
        string observation_type
        string sha256_hash
        text raw_payload_json
    }
    FINDING {
        string id PK
        string fingerprint PK
        string device_id FK
        string rule_id
        string severity
        string status
        string evidence_sha256
        datetime first_seen
        datetime last_seen
    }
    VULNERABILITY {
        string cve_id PK
        string cpe_pattern
        float cvss_score
        string severity
        text description
    }
    REMEDIATION_ACTION {
        string id PK
        string finding_id FK
        string action_type
        string status
        string approved_by
        datetime executed_at
    }
    AUDIT_EVENT {
        string id PK
        string tenant_id FK
        string actor
        string action
        text payload_json
        datetime created_at
    }

    TENANT ||--o{ DEVICE : owns
    DEVICE ||--o{ TASK : receives
    TASK ||--o{ OBSERVATION : produces
    DEVICE ||--o{ FINDING : reports
    FINDING ||--o{ REMEDIATION_ACTION : triggers
    FINDING }o--o{ VULNERABILITY : maps_to
    TENANT ||--o{ AUDIT_EVENT : records
```

---

## 7. WebSocket Agent Stream Protocol (`/v1/agent/stream`)

Persistent bidirectional connection between the endpoint agent and control gateway.

### Protobuf Frame Definitions:
```protobuf
syntax = "proto3";
package netra.agent.v1;

message Frame {
  string frame_id = 1;
  int64 timestamp = 2;
  oneof payload {
    AgentHello hello = 3;
    TaskDispatch task_dispatch = 4;
    TaskResult task_result = 5;
    FindingIngest finding_ingest = 6;
    Heartbeat heartbeat = 7;
    Ack ack = 8;
  }
}

message AgentHello {
  string device_id = 1;
  string os_name = 2;
  string arch = 3;
  string agent_version = 4;
}

message TaskDispatch {
  string task_id = 1;
  string capability = 2;
  string parameters_json = 3;
  int32 timeout_seconds = 4;
}

message TaskResult {
  string task_id = 1;
  string status = 2;
  string evidence_sha256 = 3;
  bytes raw_evidence_gz = 4;
  string error_message = 5;
}
```

---

## 8. Agent-Facing REST Endpoints

### 8.1 `POST /v1/agent/enroll`
Enrolls a newly installed agent host.
* **Status**: `Specified`
* **Actor**: Unenrolled Agent Host
* **Auth**: Single-use Enrollment Token
* **Request**:
```json
{
  "enrollment_token": "enroll_sec_99a8b7c6d5e4f3a2",
  "public_key": "3d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f",
  "hostname": "workstation-01",
  "os_type": "linux",
  "os_release": "Ubuntu 24.04 LTS",
  "arch": "amd64"
}
```
* **Response (201 Created)**:
```json
{
  "success": true,
  "data": {
    "device_id": "dev_01h8a9b2c3d4e5f6",
    "tenant_id": "ten_01h8a1b2c3d4",
    "heartbeat_interval_seconds": 15,
    "enrolled_at": "2026-08-24T12:00:00Z"
  }
}
```

---

## 9. Control-Plane Management Endpoints

### 9.1 `GET /v1/devices`
Lists all registered endpoint devices in the active tenant.
* **Status**: `Specified`
* **Actor**: Operator / Web Console / CLI
* **Auth**: Bearer JWT (`ROLE_OPERATOR`, `ROLE_ADMIN`, `ROLE_AUDITOR`)
* **Query Params**: `status` (`ONLINE`, `OFFLINE`, `REVOKED`), `os_type`, `limit`, `offset`
* **Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "total": 1,
    "devices": [
      {
        "id": "dev_01h8a9b2c3d4e5f6",
        "hostname": "workstation-01",
        "os_type": "linux",
        "status": "ONLINE",
        "last_seen": "2026-08-24T12:05:00Z"
      }
    ]
  }
}
```

### 9.2 `POST /v1/tasks`
Creates and dispatches an asynchronous scan task to an enrolled device.
* **Status**: `Specified`
* **Actor**: Operator / Automated CI Gate
* **Auth**: Bearer JWT (`ROLE_OPERATOR`, `ROLE_ADMIN`)
* **Request**:
```json
{
  "device_id": "dev_01h8a9b2c3d4e5f6",
  "capability": "SCAN_FIREWALL",
  "parameters": {}
}
```
* **Response (202 Accepted)**:
```json
{
  "success": true,
  "data": {
    "task_id": "tsk_01h8b3c4d5e6",
    "status": "PENDING",
    "device_id": "dev_01h8a9b2c3d4e5f6",
    "created_at": "2026-08-24T12:06:00Z"
  }
}
```

---

## 10. Network & Vulnerability Intelligence Endpoints

### 10.1 `GET /v1/topology/graph`
Returns the synthesized network topology and reachability graph.
* **Status**: `Specified`
* **Actor**: Operator / Web Console
* **Auth**: Bearer JWT
* **Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "nodes": [
      { "id": "node_dev_01", "type": "DEVICE", "label": "workstation-01", "ip": "192.168.1.50" },
      { "id": "node_gw_01", "type": "GATEWAY", "label": "Default-Gateway", "ip": "192.168.1.1" }
    ],
    "links": [
      { "source": "node_dev_01", "target": "node_gw_01", "type": "DEFAULT_GATEWAY" }
    ]
  }
}
```

### 10.2 `GET /v1/vulnerabilities`
Queries the cached CVE vulnerability intelligence catalog.
* **Status**: `Specified`
* **Actor**: Operator / CLI

---

## 11. Controlled Remediation Endpoints

### 11.1 `POST /v1/remediation/apply`
Applies an approved, controlled remediation action with mandatory post-validation.
* **Status**: `Specified`
* **Actor**: Human Operator / Approved Slack Action
* **Auth**: Bearer JWT (`ROLE_ADMIN`, `ROLE_OPERATOR`)
* **Request**:
```json
{
  "finding_id": "fnd_01h8c4d5e6",
  "action_type": "FIREWALL_ENABLE_PROFILE",
  "dry_run": false
}
```
* **Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "remediation_id": "rem_01h8d5e6f7",
    "status": "VERIFIED_RESOLVED",
    "finding_id": "fnd_01h8c4d5e6",
    "post_validation_passed": true,
    "executed_at": "2026-08-24T12:10:00Z"
  }
}
```

---

## 12. Integration Gateway Endpoints (Slack & Webhooks)

### 12.1 `POST /v1/integrations/slack/interactivity`
Handles Slack Block Kit interactive buttons (`[Approve Remediation]`).
* **Status**: `Specified`
* **Actor**: Slack API Servers
* **Auth**: HMAC-SHA256 Signature (`X-Slack-Signature`, `X-Slack-Request-Timestamp`)

---

## 13. Health, Telemetry & Diagnostics Endpoints

* `GET /v1/health`: System health check (`{"status": "HEALTHY", "db": "CONNECTED", "version": "1.0.0"}`).
* `GET /metrics`: Standard Prometheus metrics format.
