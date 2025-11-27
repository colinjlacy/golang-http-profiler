
# Local Omnitrace Engine — Summary & Architecture

## 1. Project Goal

Build a **unified, zero-instrumentation profiler** that automatically observes and reconstructs:

- **Network interactions**  
  (TCP, HTTP, gRPC, Postgres, MySQL, Redis, etc.)
- **Database queries**  
  (SQL text, parameters, responses)
- **Filesystem interactions**  
  (paths, reads/writes, contents)
- **Across any language or runtime** without modifying the application.

The profiler should work **locally on developer machines**, including macOS and Linux containers (Docker/Kind), and provide a **semantic timeline** of everything a program does “on the wire” and “on disk.”

This is part of an overarching initiative to create **Application-Driven Infrastructure**, where systems adapt based on real application behavior observed automatically.

---

## 2. Profiling Environment Assumptions

The environment is intentionally simplified to maximize observability:

- Runs on **developer laptops** (macOS)
- Or inside **local containers** (Docker, Kind clusters)
- **TLS is disabled** for local integrations  
  (or encrypted calls can be safely ignored)
- Applications and services are **trusted**  
  (not adversarial)
- Traffic is local or intra-container  
  (no cross-network production traffic)
- Profiling is **not** for security; it’s for understanding behavior

These assumptions remove major eBPF/DTrace limitations and allow full plaintext reconstruction of protocols.

---

## 3. High-Level Capability Overview

Under these assumptions, syscall-level instrumentation can capture:

### 3.1 Network

- Full TCP/UDP payloads (plaintext)
- Connection metadata (IP/ports, PID, container)
- Directionality (inbound/outbound)
- Timing (duration, latency breakdown)
- Two-way stream reconstruction

Supports decoding of:

- HTTP/1.x (method, URL, headers, body)
- gRPC (HTTP/2 cleartext)
- Postgres protocol
- MySQL protocol
- Redis (RESP)
- MongoDB wire protocol
- Any plaintext TCP protocol

### 3.2 Database

- SQL queries
- Prepared statement flows
- Parameters (bind values)
- Row descriptions and data rows
- Server responses
- Transaction boundaries

### 3.3 Filesystem

- Open, read, write, close
- File paths, file descriptors
- File contents (sampled)
- Metadata (mode, UID/GID)
- Deletes, renames

### 3.4 Process Context

- PID/TID, command name
- Container/cgroup identity (Linux)
- Execution timeline

---

## 4. Cross-Platform Architecture: “Local Omnitrace Engine”

The system is structured into **three layers**, with only the lowest being OS-specific.

```text
              ┌───────────────────────────┐
              │    Output Layer (UI/API)  │
              │  CLI · JSON · Web UI      │
              └──────────────┬────────────┘
                             │
              ┌──────────────┴────────────┐
              │     Core Engine (Shared)   │
              │  Event normalization        │
              │  Stream reassembly          │
              │  Protocol classification    │
              │  Protocol parsing           │
              │  Timeline construction      │
              └──────────────┬────────────┘
                             │
        ┌────────────────────┴────────────────────┐
        │                 Capture Layer            │
        │                                          │
        │  macOS (DTrace)        Linux (eBPF)       │
        │  syscall::: probes     kprobes/tracepts   │
        │  tcp:::sendmsg         tcp_sendmsg        │
        │  tcp:::recvmsg         tcp_recvmsg        │
        │  io:::start            fs tracepoints     │
        └──────────────────────────────────────────┘
```

---

## 5. Capture Layer Details

### 5.1 macOS Capture (DTrace)

Use DTrace providers:

- **Networking:**
  - `syscall::socket*:entry/return`
  - `syscall::connect*:entry/return`
  - `syscall::accept*:entry/return`
  - `syscall::read*:entry/return`, `syscall::write*:entry/return`
  - `syscall::sendto*`, `syscall::recvfrom*`
  - Or higher-level `tcp::sendmsg` / `tcp::recvmsg` if available

- **Filesystem:**
  - `syscall::open*`, `syscall::openat*`
  - `syscall::read*`, `syscall::write*`
  - `syscall::close*`
  - `syscall::unlink*`, `syscall::rename*`

Workflow:

- Track `(PID, FD)` → socket/file metadata.
- Copy buffer contents out of syscalls.
- Emit normalized events to user-space via stdout or libdtrace bindings.

### 5.2 Linux Capture (eBPF)

Use eBPF programs (via BCC or libbpf):

- **Networking (kprobes or tracepoints):**
  - `tcp_sendmsg`
  - `tcp_recvmsg`
  - `udp_sendmsg`
  - `udp_recvmsg`
  - `inet_csk_accept`
  - `sock:inet_sock_set_state`

- **Filesystem:**
  - `sys_enter_openat`, `sys_exit_openat`
  - `sys_enter_read`, `sys_exit_read`
  - `sys_enter_write`, `sys_exit_write`
  - Or VFS hooks (`vfs_read`, `vfs_open`, etc.)

- **Containers:**
  - Use `bpf_get_current_cgroup_id()` for cgroup/container ID.
  - Resolve container → metadata in user-space.

---

## 6. Shared Event Model

Both macOS and Linux emit a unified structure:

```go
type RawIOEvent struct {
    PID, TID    int
    CgroupID    uint64
    ContainerID string
    Cmd         string

    Fd       int
    IsSocket bool
    IsFile   bool

    Transport              Transport   // TCP, UDP, Unix
    LocalIP, RemoteIP      string
    LocalPort, RemotePort  int
    UnixPath               string

    Direction Direction   // in or out
    Timestamp time.Time
    Data      []byte
    Error     string
    EOF       bool
}
```

This normalization is the key abstraction that makes the engine OS-agnostic.

---

## 7. Core Engine: Stream and Protocol Processing

### 7.1 Connection Tracker

Maintains:

- Socket identity.
- Reassembled inbound/outbound streams.
- Timestamps.
- Transport metadata.

### 7.2 Protocol Classifier

Inspects first bytes to detect:

- HTTP/1.x.
- gRPC (HTTP/2 cleartext).
- Postgres protocol.
- MySQL protocol.
- Redis RESP.
- MongoDB wire protocol.
- Generic TCP (fallback).

### 7.3 Protocol Parsers

Each parser is a small state machine that emits **semantic events**:

- `HTTPRequest`
- `HTTPResponse`
- `SQLQuery`
- `DBRow`
- `FileRead`
- `FileWrite`
- `TCPMessage`
- etc.

---

## 8. Output Layer

### 8.1 CLI (Developer-Friendly)

Example:

```text
[PID 4213 server] HTTP GET /users
    → Response 200 (18ms, 1.2KB)

[PID 4213 server] SQL Postgres
    → SELECT * FROM users WHERE id = $1  [42]
    → 1 row (1.0ms)

[PID 4213 server] FS READ  config.yaml  (2.1KB)
```

### 8.2 Structured Output

Emit JSON/Protobuf for UI dashboards or further processing:

```json
{
  "kind": "sql_query",
  "pid": 4213,
  "sql": "SELECT * FROM users WHERE id = $1",
  "params": ["42"],
  "duration_ms": 1.0,
  "timestamp": "2025-11-27T17:31:45.123Z"
}
```

---

## 9. Developer Workflow

### On macOS

```bash
adi-profiler run -- go test ./...
```

### On Linux

```bash
adi-profiler attach --pid 12345
```

### On Docker/Kind

```bash
adi-profiler attach --container app-api
```

The profiler attaches, captures only that process/container’s syscalls, and generates an end-to-end behavioral timeline.

---

## 10. Summary

The “Local Omnitrace Engine” provides:

- Full network, DB, and filesystem visibility.
- Zero modifications to application code.
- Zero proxies or shims.
- Full plaintext protocol reconstruction.
- Developer-friendly insights.
- A unified cross-platform core engine.
- DTrace backend for macOS, eBPF backend for Linux.

This architecture enables deep, automatic understanding of real application behavior — forming the foundation for **Application-Driven Infrastructure**.
