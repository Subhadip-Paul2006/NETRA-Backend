# NETRA — Official API Reference & Stream Protocol Specification

> **Overview**
>
> This document provides the complete, authoritative API reference and network communication contracts for NETRA (Network & Endpoint Threat Reconnaissance Architecture). It defines REST endpoints, WebSocket streaming frames, Protocol Buffer schemas, cryptographic authentication headers, error models, and entity data relationships.

**Status:** Specified / Designed  
**Audience:** Backend Engineers, Rust Systems Developers, Security Architects, API Integrators  
**Purpose:** Serves as the immutable protocol specification connecting endpoint Rust agents, central control services, CLI tools, and external notification gateways.

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
14. [Internal Local IPC Protocol Specification (Phase 2.3)](#14-internal-local-ipc-protocol-specification-phase-23)

---

## 1. API Architecture & Actor Boundaries

The NETRA API cleanly separates communication pathways across three distinct actors:

```mermaid
flowchart TD
    subgraph Actors["API Calling Actors"]
        AgentHost["Endpoint Agent Host (Rust Binary)"]
        Operator["Human Operator / CLI / Web Console"]
        Integration["Third-Party Webhooks (Slack / CI)"]
    end

    subgraph Boundaries["API Architectural Boundaries"]
        AgentAPI["Agent-Facing API & WSS Gateway<br/>• Outbound WSS (/v1/agent/stream)<br/>• Fallback REST (/v1/agent/poll, /v1/agent/enroll)<br/>• Auth: Ed25519 Request Signing"]
        ControlAPI["Control-Plane Management API<br/>• REST Endpoints (/v1/devices, /v1/findings, etc.)<br/>• Auth: Bearer JWT / Scoped API Key<br/>• RBAC: Admin / Operator / Auditor"]
        IntegrationAPI["Integration Gateway API<br/>• Webhook Handlers (/v1/integrations/*)<br/>• Auth: HMAC Signatures (Slack HMAC-SHA256)"]
    end

    AgentHost --> AgentAPI
    Operator --> ControlAPI
    Integration --> IntegrationAPI
```

---

## 2. Authentication, Authorization & Device Attestation

* **Phase 5 Local Trust Boundary**: In Phase 5, the REST API is bound to localhost (`127.0.0.1:8443`) and operates as an unauthenticated local diagnostic interface with capability-minimized read-only scope (health, version, status, diagnostics, storage checks). Destructive operations are strictly excluded.
* **Phase 6+ Authentication Extension Point**: Asymmetric **Ed25519 (RFC 8032)** request signing (for agent telemetry) and **JWT Bearer Authentication** (for control-plane management) will be inserted into the Axum Tower middleware pipeline in Phase 6.
* **Phase 6+ Role-Based Access Control (RBAC)**: Fine-grained tenant claims (`ROLE_ADMIN`, `ROLE_OPERATOR`, `ROLE_AUDITOR`) represent future architectural extension points enforced once remote multi-tenant control endpoints are activated.
* **Database Isolation Rule**: Distributed agents **must never** receive or store direct database credentials. All data is routed strictly through the authenticated Control API or local in-process repository contracts.

---

## 3. Standard Headers & Cryptographic Request Signing

### 3.1 Agent Cryptographic Headers
Every HTTP request and WebSocket initialization frame dispatched by an enrolled Rust agent must include:

```http
X-NETRA-Device-ID: dev_01h8a9b2c3d4e5f6
X-NETRA-Timestamp: 1776189500
X-NETRA-Nonce: a9f8e7d6-c5b4-4a3b-2a1f-0e9d8c7b6a5f
X-NETRA-Request-ID: req_1122334455667788
X-NETRA-Signature: 6f8b9e... (128-character hex-encoded Ed25519 signature)
```

```text
StringToSign = METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + REQUEST_ID + "\n" + SHA256(BODY)
```

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

Persistent bidirectional connection between the endpoint Rust agent and control gateway.

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

## 13. Health, Diagnostics & Control-Plane REST Gateway Endpoints (Phase 5)

> [!NOTE]
> **Single Source of Truth**: The canonical, machine-readable contract for all Phase 5 REST API endpoints is compiled directly from Rust models via `utoipa` into OpenAPI 3.1 (`/api/v1/openapi.json`).

### 13.1 Phase 5 REST Route Taxonomy

| Method | Route | Description | Query Parameters | Cache-Control Header | Response Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| `GET` | `/api/v1/health` | Overall system liveness & component health probe | None | `no-store, no-cache, must-revalidate` | `200 OK` |
| `GET` | `/api/v1/version` | Application version, build profile, and schema contract | None | `public, max-age=3600` | `200 OK` |
| `GET` | `/api/v1/status` | Runtime coordinator state, platform info, and storage health | None | `no-store, no-cache, must-revalidate` | `200 OK` |
| `GET` | `/api/v1/diagnostics` | Host environment diagnostic bundle & config validation | None | `no-store, no-cache, must-revalidate` | `200 OK` |
| `GET` | `/api/v1/openapi.json` | Machine-readable OpenAPI 3.1 specification | None | `public, max-age=3600` | `200 OK` |
| `GET` | `/api/v1/storage/status` | SQLite database disk footprint, WAL size, saturation, row counts | None | `no-store, no-cache, must-revalidate` | `200 OK` |
| `GET` | `/api/v1/storage/check` | Execute database integrity verification (Tier 2/3) | `deep=true\|false` | `no-store, no-cache, must-revalidate` | `200 OK` / `409 Conflict` |

### 13.2 Diagnostics Data Classification Boundary (`GET /api/v1/diagnostics`)

Under the unauthenticated host-local trust assumption, the diagnostics endpoint enforces a strict data classification boundary:

| Category | Permitted in Diagnostics Payload | Explicitly Prohibited (Redacted / Excluded) |
| :--- | :--- | :--- |
| **System Identity** | NETRA version, build profile, target triple, OS family, CPU arch. | Hostname IP mapping, user account lists, hardware UUIDs. |
| **Runtime State** | State machine enum (`Running`, `Degraded`), uptime seconds. | Stack traces, raw thread IDs, internal memory pointers. |
| **Configuration** | Boolean validity flags, sanitized safe setting keys (`db_path`). | Plaintext tokens, API secrets, private keys, environment variables. |
| **Storage Diagnostics** | SQLite saturation %, WAL footprint, migration count, integrity status. | Raw database table rows, record payloads, observation contents. |
| **Component Health** | Subsystem health enums (`Healthy`, `Degraded: reason`). | Unsanitized OS error logs containing filesystem trees or secrets. |

### 13.3 Storage Integrity Verification & Abuse Protection (`GET /api/v1/storage/check`)
* **Path**: `GET /api/v1/storage/check`
* **Semantics**: Pure read-only diagnostic operation (idempotent, side-effect-free).
* **Query Parameters**:
  - `deep` (`boolean`, optional, default: `false`): When `false`, executes Tier 2 `PRAGMA quick_check;`. When `true`, executes Tier 3 `PRAGMA integrity_check;` and `PRAGMA foreign_key_check;`.
* **Execution & Response Contract**:
  - **`200 OK` (Operation Executed Successfully)**: The HTTP check probe executed cleanly to completion against the SQLite engine. The verification result is reported inside `data.passed`:
    - `passed: true`: Database is structurally healthy.
    - `passed: false`: Structural corruption was detected; detailed error messages and corrupted page/index diagnostics are returned in `data.details`.
  - **`409 Conflict` (Concurrency Guard)**: A deep integrity check (`deep=true`) is currently running. Single-flight lock rejected the duplicate request (`ERR_INTEGRITY_CHECK_IN_PROGRESS`).
  - **`500 Internal Server Error` / `503 Service Unavailable` (Operational Failure)**: The check probe could not be executed (e.g. database file locked exclusively by external OS process, I/O hardware failure, or storage engine uninitialized).
* **Success Response — Clean Database (`200 OK`)**:
```json
{
  "success": true,
  "data": {
    "db_path": "tmp/agent.db",
    "tier": 2,
    "check_type": "quick_check",
    "duration_ms": 1,
    "passed": true,
    "details": "Tier 2 quick_check passed cleanly in 1 ms"
  },
  "meta": {
    "request_id": "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b",
    "timestamp": "2026-08-26T08:30:00.000000Z"
  }
}
```
* **Success Response — Corruption Detected (`200 OK`)**:
```json
{
  "success": true,
  "data": {
    "db_path": "tmp/agent.db",
    "tier": 2,
    "check_type": "quick_check",
    "duration_ms": 2,
    "passed": false,
    "details": "quick_check failure: page 42 b-tree corruption detected: rowid out of order"
  },
  "meta": {
    "request_id": "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b",
    "timestamp": "2026-08-26T08:30:00.000000Z"
  }
}
```

---

## 14. Internal Local IPC Protocol Specification (Phase 2.3)

> [!NOTE]
> **Internal Trust Boundary Contract**: This section specifies the host-local communication protocol connecting the **Tier-1 Supervisor Daemon**, **Tier-2 Worker Process**, and **CLI Query Launcher**. It operates strictly over local OS abstractions (Named Pipes / Unix Domain Sockets) and is completely decoupled from the external HTTP / WSS API.

### 14.1 Transport & Wire Framing
* **Windows Transport**: Named Pipe (`\\.\pipe\netra-supervisor-ipc`) with strict SDDL DACL.
* **Unix Transport**: Unix Domain Socket (`/run/netra/supervisor.sock` or `$XDG_RUNTIME_DIR/netra/supervisor.sock`) with mode `0600`.
* **Framing Format**: 4-byte unsigned big-endian length prefix followed by UTF-8 encoded JSON payload:
  ```text
  +-------------------------+----------------------------------------------------+
  | Length Prefix (4-byte)  |             JSON Payload (UTF-8)                   |
  | Big-Endian uint32       |  {"protocol_version":1,"message_type":"Heartbeat"...} |
  +-------------------------+----------------------------------------------------+
  ```
* **Maximum Frame Size Guard**: `1,048,576` bytes (1MB). Frames exceeding this limit trigger immediate connection termination.

### 14.2 Universal IPC Envelope Schema

```json
{
  "protocol_version": 1,
  "message_type": "CommandRequest",
  "request_id": "req_01h8a9b2c3d4",
  "correlation_id": "corr_01h8a9b2c3d4",
  "session_id": "sess_01h8a9b2c3d4",
  "timestamp": 1776189500,
  "payload": { ... }
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `protocol_version` | `uint32` | Protocol version integer (Current: `1`). Mismatched versions receive `INCOMPATIBLE_VERSION`. |
| `message_type` | `string` | Enum identifying the payload schema type. |
| `request_id` | `string` | Unique UUIDv7 identifier for the specific request. |
| `correlation_id` | `string?` | Optional UUIDv7 linking a response or event to an initial request. |
| `session_id` | `string?` | Cryptographic session identifier assigned upon successful handshake. |
| `timestamp` | `int64` | Unix epoch timestamp in seconds. |
| `payload` | `object` | Type-specific JSON payload body. |

### 14.3 IPC Message Catalog

#### 1. `HandshakeRequest` (Client $\to$ Server)
```json
{
  "protocol_version": 1,
  "message_type": "HandshakeRequest",
  "request_id": "req_01h8a9b2c3d4",
  "timestamp": 1776189500,
  "payload": {
    "token": "a1b2c3d4e5f6...",
    "client_pid": 10482,
    "client_role": "WORKER",
    "version": "1.0.0-foundation"
  }
}
```

#### 2. `HandshakeResponse` (Server $\to$ Client)
```json
{
  "protocol_version": 1,
  "message_type": "HandshakeResponse",
  "correlation_id": "req_01h8a9b2c3d4",
  "timestamp": 1776189501,
  "payload": {
    "success": true,
    "session_id": "sess_01h8b1c2d3e4",
    "heartbeat_interval_ms": 5000,
    "error": null
  }
}
```

#### 3. `Heartbeat` (Worker $\to$ Supervisor)
```json
{
  "protocol_version": 1,
  "message_type": "Heartbeat",
  "session_id": "sess_01h8b1c2d3e4",
  "timestamp": 1776189505,
  "payload": {
    "memory_rss_bytes": 14680064,
    "cpu_usage_pct": 0.4,
    "runtime_state": "RUNNING",
    "active_tasks": 0
  }
}
```

#### 4. `HeartbeatAck` (Supervisor $\to$ Worker)
```json
{
  "protocol_version": 1,
  "message_type": "HeartbeatAck",
  "session_id": "sess_01h8b1c2d3e4",
  "timestamp": 1776189505,
  "payload": {
    "acknowledged": true
  }
}
```

#### 5. `CommandRequest` (Supervisor / CLI $\to$ Worker)
```json
{
  "protocol_version": 1,
  "message_type": "CommandRequest",
  "request_id": "req_01h8c2d3e4f5",
  "session_id": "sess_01h8b1c2d3e4",
  "timestamp": 1776189510,
  "payload": {
    "action": "STATUS_QUERY",
    "parameters": {}
  }
}
```

#### 6. `CommandResponse` (Worker $\to$ Supervisor / CLI)
```json
{
  "protocol_version": 1,
  "message_type": "CommandResponse",
  "correlation_id": "req_01h8c2d3e4f5",
  "session_id": "sess_01h8b1c2d3e4",
  "timestamp": 1776189510,
  "payload": {
    "success": true,
    "data": {
      "state": "RUNNING",
      "health": "HEALTHY",
      "uptime_seconds": 120
    },
    "error": null
  }
}
```

#### 7. `ShutdownNotice` (Supervisor $\to$ Worker)
```json
{
  "protocol_version": 1,
  "message_type": "ShutdownNotice",
  "request_id": "req_01h8d3e4f5a6",
  "timestamp": 1776189520,
  "payload": {
    "reason": "OS_TERMINATION_SIGNAL",
    "grace_period_ms": 5000
  }
}
```

#### 8. `ErrorResponse` (Server $\to$ Client)
```json
{
  "protocol_version": 1,
  "message_type": "ErrorResponse",
  "correlation_id": "req_01h8a9b2c3d4",
  "timestamp": 1776189501,
  "payload": {
    "error_code": "UNAUTHORIZED_TOKEN",
    "message": "The provided ephemeral handshake token is invalid or expired."
  }
}
```

### 14.4 Error Codes & Behavior Table
| Error Code | Trigger Condition | Server Action |
| :--- | :--- | :--- |
| `UNAUTHORIZED_TOKEN` | Token mismatch in `HandshakeRequest` | Drops session and terminates connection |
| `PEER_PID_MISMATCH` | Kernel peer PID != claimed client PID | Disconnects immediately; logs security audit alert |
| `HANDSHAKE_TIMEOUT` | No handshake received within 3.0s | Drops unauthenticated socket |
| `FRAME_OVERFLOW` | Frame size header exceeds 1MB | Closes socket without allocating buffer |
| `MALFORMED_JSON` | Payload cannot be parsed as JSON envelope | Returns `ErrorResponse` and drops connection |
| `INCOMPATIBLE_VERSION` | Client protocol version != server version | Rejects connection with supported version range |
| `SESSION_EXPIRED` | Worker restarted; old session ID used | Rejects request; client must perform fresh handshake |

---

## 15. CLI Machine-Readable JSON Output Specification (Phase 4)

When `netra` is executed with the `--json` flag, it emits **strictly valid JSON** on `stdout` adhering to the following schema contract. The contract separates the CLI output specification version (`schema_version`) from the underlying application release version (`netra_version`).

### 15.1 CLI Success Envelope
```json
{
  "schema_version": "1.0",
  "netra_version": "1.0.0-foundation",
  "command": "storage status",
  "status": "success",
  "data": {
    "db_path": "tmp/agent.db",
    "total_size_bytes": 1048576,
    "wal_size_bytes": 32768,
    "max_storage_bytes": 524288000,
    "saturation_percent": 0.20,
    "records": {
      "migrations": 1,
      "config": 2,
      "queued_observations": 0,
      "findings": 0
    }
  },
  "timestamp": "2026-08-26T07:30:00.000000Z"
}
```

### 15.2 CLI Error Envelope
```json
{
  "schema_version": "1.0",
  "netra_version": "1.0.0-foundation",
  "command": "storage check",
  "status": "error",
  "error": {
    "code": "ERR_STORAGE_CORRUPTION",
    "message": "Database quick_check failed: file is not a database",
    "context": {
      "db_path": "tmp/agent.db",
      "tier": 2
    }
  },
  "timestamp": "2026-08-26T07:30:00.000000Z"
}
```

---

## 16. Control-Plane REST API Gateway Specification (Phase 5)

The Control-Plane REST API Gateway (`netra-api`) exposes an asynchronous HTTP REST interface built on **Axum v0.8**. It provides local diagnostic probes, health monitoring, and SQLite database footprint inspection under a host-local trust assumption.

### 16.1 Binding & Security Invariants
1. **Loopback-Only Binding**: The HTTP listener strictly accepts IPv4 loopback (`127.0.0.1`) or IPv6 loopback (`::1`). Binding to `0.0.0.0`, LAN interfaces, or public IP addresses is explicitly rejected during initialization.
2. **Capability Minimization**: Phase 5 REST API is unauthenticated and strictly read-only. Destructive operations (such as `netra storage recover`) are strictly prohibited and never exposed over HTTP.
3. **Envelope Semantics**: All responses utilize the **NETRA Universal JSON Envelope, semantically aligned with RFC 9457**.
4. **Single-Flight Concurrency Lock**: `GET /api/v1/storage/check?deep=true` enforces an in-memory atomic single-flight lock, rejecting concurrent deep checks with `409 Conflict` (`ERR_INTEGRITY_CHECK_IN_PROGRESS`).

### 16.2 Route Taxonomy & Status Code Semantics

| Method | Path | Cache Header | Success Status | Concurrency / Error Status | Description |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `GET` | `/api/v1/health` | `no-store` | `200 OK` | `503 Service Unavailable` | Service liveness probe & component health |
| `GET` | `/api/v1/version` | `public, max-age=3600` | `200 OK` | `500 Internal Error` | Version metadata (`schema_version: "1.0"`, build profile) |
| `GET` | `/api/v1/status` | `no-store` | `200 OK` | `503 Service Unavailable` | Coordinator state machine, platform info & storage state |
| `GET` | `/api/v1/diagnostics` | `no-store` | `200 OK` | `500 Internal Error` | Sanitized diagnostic bundle (secrets redacted) |
| `GET` | `/api/v1/openapi.json` | `public, max-age=3600` | `200 OK` | `500 Internal Error` | Compile-time OpenAPI 3.1 schema document |
| `GET` | `/api/v1/storage/status` | `no-store` | `200 OK` | `404 Not Found` | SQLite database file sizes, WAL size & record counts |
| `GET` | `/api/v1/storage/check` | `no-store` | `200 OK` (`passed: true\|false`) | `409 Conflict` (deep check active) | Tier 2 quick_check or Tier 3 deep integrity probe |

### 16.3 Storage Check Response Semantics (`GET /api/v1/storage/check`)
- `200 OK` + `passed: true`: Integrity check executed successfully; database is clean and structurally sound.
- `200 OK` + `passed: false`: Integrity check executed successfully; corruption detected and reported in `details`.
- `409 Conflict`: A deep integrity check (`?deep=true`) is already in-flight.
- `503 Service Unavailable`: Storage engine uninitialized or probe cannot be executed.


