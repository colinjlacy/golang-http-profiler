# Implementation Summary

This document summarizes the MVP implementation of the HTTP Profiler for macOS.

## What Was Built

A minimal viable profiler that:
- Captures HTTP/1.x network traffic from any process
- Uses DTrace for zero-instrumentation profiling
- Parses and reconstructs complete HTTP transactions
- Outputs human-readable trace files

## Project Structure

```
.
├── cmd/
│   └── adi-profiler/
│       └── main.go              # CLI entry point and orchestration
├── internal/
│   ├── capture/
│   │   └── events.go            # DTrace event types and parsing
│   ├── stream/
│   │   └── tracker.go           # TCP stream reassembly
│   ├── http/
│   │   └── parser.go            # HTTP/1.x protocol parser
│   └── output/
│       └── writer.go            # Text file output formatter
├── scripts/
│   └── capture.d                # DTrace capture script
├── test/
│   ├── server.go                # Test HTTP server
│   ├── client.go                # Test HTTP client
│   └── README.md                # Test instructions
├── go.mod                       # Go module definition
├── .gitignore                   # Git ignore patterns
├── README.md                    # Main documentation
├── QUICKSTART.md                # Quick start guide
└── IMPLEMENTATION.md            # This file
```

## Components

### 1. DTrace Capture Script (`scripts/capture.d`)

**Purpose**: Captures raw syscall data from the kernel

**Key features**:
- Hooks socket(), connect(), accept() for FD tracking
- Hooks read()/write() for data capture
- Captures up to 16KB per syscall
- Outputs tab-delimited events to stdout

**Output format**: `TYPE\tTIMESTAMP\tPID\tFD\t[SIZE\tDATA]`

### 2. Event Model (`internal/capture/events.go`)

**Purpose**: Defines and parses DTrace output

**Types**:
- `RawEvent` - normalized syscall event
- `EventType` - SOCKET, CONNECT, ACCEPT, READ, WRITE, CLOSE
- `Direction` - IN (read) or OUT (write)
- `Parser` - reads and parses DTrace output line-by-line

### 3. Stream Tracker (`internal/stream/tracker.go`)

**Purpose**: Reassembles TCP streams from individual syscalls

**Key features**:
- Maintains map of (PID, FD) → TCPStream
- Buffers inbound and outbound data separately
- Tracks stream lifecycle (creation → close)
- Thread-safe with mutex protection

**Data structure**:
- `StreamID` - unique stream identifier (PID + FD)
- `TCPStream` - bidirectional byte buffers

### 4. HTTP Parser (`internal/http/parser.go`)

**Purpose**: Parses HTTP/1.x protocol from TCP streams

**Key features**:
- Parses request line, headers, and body
- Parses response status, headers, and body
- Matches requests with responses (FIFO)
- Handles Content-Length for body parsing
- Consumes parsed data from stream buffers

**Data structures**:
- `HTTPRequest` - parsed request
- `HTTPResponse` - parsed response
- `HTTPTransaction` - complete request/response pair

### 5. Output Writer (`internal/output/writer.go`)

**Purpose**: Formats and writes HTTP transactions to file

**Features**:
- Human-readable format
- Shows timestamp, PID, method, URL
- Shows key headers (Host, Content-Type, Content-Length)
- Truncates large bodies for readability
- Thread-safe

**Output format**:
```
[2025-11-27 17:31:45.123] PID 4213
  → HTTP GET /users
     Host: localhost:8080
  ← Response 200 OK
     Content-Type: application/json
     Body: {"users": [...]}
```

### 6. CLI (`cmd/adi-profiler/main.go`)

**Purpose**: Orchestrates the entire profiling pipeline

**Workflow**:
1. Parse command: `run -- <command>`
2. Check for root privileges (required for DTrace)
3. Start target process as subprocess
4. Launch DTrace with target PID
5. Process DTrace output:
   - Parse events → RawEvent
   - Track streams → TCPStream
   - Parse HTTP → HTTPTransaction
   - Write output → file
6. Handle cleanup on exit/signal

**Signal handling**:
- SIGINT/SIGTERM gracefully shutdown
- Cleans up DTrace and target process
- Flushes output file

### 7. Test Harness (`test/`)

**Purpose**: Validate the profiler works end-to-end

**Components**:
- `server.go` - Simple HTTP server with multiple endpoints
- `client.go` - Client that makes 5 different HTTP requests

**Test endpoints**:
- GET / - Plain text response
- GET /users - JSON array response
- GET /user/42 - JSON object response
- GET /echo?message=X - Echo service

## Build and Test

### Build:
```bash
go build -o adi-profiler ./cmd/adi-profiler
```

### Test:
```bash
# Terminal 1
go run test/server.go

# Terminal 2
sudo ./adi-profiler run -- go run test/client.go
```

### Output:
- Console: Real-time transaction logs
- File: `adi-trace.txt` with detailed traces

## Technical Decisions

### 1. DTrace vs eBPF
**Decision**: DTrace for MVP (macOS only)
**Rationale**: Simpler to implement, sufficient for local development

### 2. Tab-delimited vs Binary Protocol
**Decision**: Tab-delimited text output from DTrace
**Rationale**: Easier to debug, parse, and extend

### 3. FIFO Request/Response Matching
**Decision**: Simple FIFO queue for matching
**Rationale**: Sufficient for HTTP/1.x (pipelined or not), simpler than full state machine

### 4. Buffer Size Limit (16KB)
**Decision**: Capture up to 16KB per syscall
**Rationale**: Balance between completeness and performance/memory

### 5. Synchronous Processing
**Decision**: Process DTrace output in single goroutine
**Rationale**: Simpler, no race conditions, sufficient for MVP

## Limitations

**MVP constraints**:
- macOS only (no Linux/eBPF)
- HTTP/1.x only (no HTTP/2, gRPC, WebSocket)
- Plaintext only (no HTTPS/TLS)
- Single process at a time
- No filesystem or database tracing
- Basic body truncation (no smart JSON formatting)

## Future Enhancements

See `local-omnitrace-engine.md` for the full vision:

**High priority**:
- Linux eBPF support
- Multi-process profiling
- Better body formatting (JSON pretty-print)

**Medium priority**:
- Additional protocols (Postgres, MySQL, Redis)
- Container/cgroup support
- JSON structured output

**Low priority**:
- Web UI dashboard
- Real-time streaming API
- Filesystem tracing

## Dependencies

**Standard library only**:
- `bufio` - buffered I/O
- `bytes` - byte buffer manipulation
- `encoding/json` - JSON (test only)
- `fmt` - formatting
- `io` - I/O interfaces
- `net/http` - HTTP (test only)
- `os` - OS interface
- `os/exec` - process execution
- `os/signal` - signal handling
- `path/filepath` - file path utilities
- `strconv` - string conversion
- `strings` - string utilities
- `sync` - synchronization primitives
- `syscall` - syscall constants
- `time` - time utilities

**External dependencies**: None

## Testing

**Unit tests**: Not included in MVP (manual testing preferred)

**Manual test procedure**:
1. Build profiler
2. Start test server
3. Run client under profiling
4. Verify output file contains 5 transactions
5. Verify each transaction has request and response
6. Verify timestamps are reasonable

**Success criteria**:
- ✅ Binary builds without errors
- ✅ DTrace script loads without errors
- ✅ Test client runs to completion
- ✅ All 5 HTTP transactions captured
- ✅ Request and response data complete
- ✅ Output file readable and formatted correctly

## Conclusion

The MVP successfully demonstrates:
- Zero-instrumentation profiling with DTrace
- Complete HTTP transaction reconstruction
- Clean architecture for future extension
- Working end-to-end system

Ready for extension to full "Local Omnitrace Engine" specification.

