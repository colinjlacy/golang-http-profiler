# ADI Profiler - HTTP Traffic Profiler MVP

A minimal viable profiler for macOS that captures HTTP/1.x network traffic using DTrace and Go.

## Features

- Zero-instrumentation profiling using DTrace
- Captures HTTP/1.x requests and responses
- Works on macOS without modifying target applications
- Outputs human-readable trace files

## Requirements

- macOS with DTrace support
- Go 1.16 or later
- Root/sudo access (required for DTrace)

## Building

```bash
go build -o adi-profiler ./cmd/adi-profiler
```

## Usage

```bash
sudo ./adi-profiler run -- <command> [args...]
```

The profiler will:
1. Start your target command as a subprocess
2. Capture network traffic (using DTrace or tcpdump)
3. Parse HTTP traffic in real-time
4. Write a detailed trace to `adi-trace.txt`

### Example

```bash
# Run a Go HTTP client under profiling
sudo ./adi-profiler run -- go run test/client.go
```

### Corporate Mac / SIP Enabled?

If you're on a Mac with System Integrity Protection (common on corporate machines), DTrace may be blocked. The profiler will **automatically fall back to tcpdump mode**:

```bash
# Automatically uses tcpdump if DTrace fails
sudo ./adi-profiler run -- go run test/client.go

# Or explicitly use tcpdump mode
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

See [SIP-WORKAROUND.md](SIP-WORKAROUND.md) for details.

## Testing

See [test/README.md](test/README.md) for instructions on running the test harness.

Quick test:

```bash
# Terminal 1: Start test server
go run test/server.go

# Terminal 2: Profile test client
sudo ./adi-profiler run -- go run test/client.go
```

Check `adi-trace.txt` for captured HTTP traffic.

## Architecture

The profiler consists of three main components:

1. **DTrace Capture Layer** (`scripts/capture.d`)
   - Hooks socket syscalls (read, write, connect, accept)
   - Captures raw data buffers
   - Outputs structured events

2. **Processing Engine** (`internal/`)
   - Parses DTrace output
   - Reassembles TCP streams
   - Parses HTTP/1.x protocol
   - Matches requests with responses

3. **CLI Interface** (`cmd/adi-profiler/`)
   - Launches target process
   - Orchestrates DTrace and processing
   - Writes output to file

## Output Format

The trace file contains human-readable HTTP transactions:

```
[2025-11-27 17:31:45.123] PID 4213
  → HTTP GET /users
     Host: localhost:8080
  ← Response 200 OK
     Content-Type: application/json
     Body: [{"id":1,"name":"Alice"},...]
```

## Limitations (MVP)

- macOS only (no Linux/eBPF support yet)
- HTTP/1.x only (no HTTP/2, gRPC, etc.)
- Plaintext only (no HTTPS/TLS)
- Single process at a time
- No filesystem or database tracing

## Future Enhancements

See [local-omnitrace-engine.md](local-omnitrace-engine.md) for the full vision, including:
- Linux eBPF support
- Additional protocols (gRPC, Postgres, MySQL, Redis)
- Filesystem tracing
- Container support
- JSON/structured output
- Web UI

## Troubleshooting

### "must run as root"
DTrace requires root privileges. Use `sudo` to run the profiler.

### "could not find capture.d script"
Make sure `scripts/capture.d` exists relative to the profiler binary, or in the current directory.

### No output captured
- Ensure the target process is making HTTP requests
- Check that the server is accessible (e.g., `localhost:8080`)
- Verify DTrace is working: `sudo dtrace -l | grep syscall::read`

### System Integrity Protection blocking DTrace
The profiler will automatically switch to tcpdump mode if DTrace is blocked by SIP. See [SIP-WORKAROUND.md](SIP-WORKAROUND.md) for details.

Alternatively, use `--tcpdump` flag explicitly:
```bash
sudo ./adi-profiler --tcpdump run -- your-command
```

## License

See LICENSE file.
