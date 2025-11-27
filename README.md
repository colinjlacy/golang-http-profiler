# golang-ast-inspection

Minimal eBPF-backed HTTP syscall profiler plus a tiny test service and traffic generator. Everything is wired for x86_64 Ubuntu (20/22/23) and Go 1.25.

## What’s here
- `cmd/server`: basic HTTP service on port 8080 with `/`, `/healthz`, `/echo`, `/slow`.
- `cmd/traffic`: small Go script that repeatedly hits the service.
- `cmd/profiler`: eBPF-powered profiler that attaches to socket syscalls and writes request/response metadata to a local file.
- `bpf/profiler.bpf.c`: BPF program (compiled via `bpf2go` during build).
- `docker-compose.yml`: orchestrates the three containers; profiler runs privileged and writes logs to `./output/ebpf_http.log`.

## Prereqs (Ubuntu 20/22/23)
- Docker + docker compose.
- x86_64 kernel with BTF available (`/sys/kernel/btf/vmlinux` is present on stock Ubuntu).
- Ability to run privileged containers (needed for kprobes/eBPF).
- Go toolchain 1.25+ if you build locally (Docker build also uses Go 1.25).

## Quick start (Docker)
```bash
# From repo root
docker compose build
docker compose up

# Watch profiler output
tail -f output/ebpf_http.log
```

- The profiler filters on `HTTP_PORT` (default `8080`) and writes to `/output/ebpf_http.log` inside the container, mapped to `./output/ebpf_http.log` on the host.
- The traffic generator issues GET/POST traffic in a loop so you can see request/response bodies, methods, URLs, and status codes captured from syscall payloads.

## Config knobs
- `HTTP_PORT`: port the HTTP service listens on and the profiler filters for (default `8080`).
- `OUTPUT_PATH`: file path inside the profiler container for log output (default `/output/ebpf_http.log`).
- `TOTAL_REQUESTS`, `REQUEST_DELAY_MS`, `TARGET_HOST` for the traffic generator.

## Local build (outside Docker)
```bash
# Linux only; requires clang/llvm and kernel headers
go mod download
go generate ./pkg/profiler            # builds the BPF object via bpf2go (emits files under pkg/profiler with tag ebpf_build)
go build ./cmd/server                 # HTTP service
go build ./cmd/traffic                # traffic generator
go build -tags ebpf_build ./cmd/profiler  # profiler binary (uses generated bindings)
```

## Output format
Plain text lines with syscall-derived metadata and parsed HTTP hints:
```
ts=2024-04-08T18:24:10.123Z pid=1234 comm=curl dir=send src=127.0.0.1:57532 dst=127.0.0.1:8080 bytes=89 method=GET url=/echo body="" raw="GET /echo HTTP/1.1\r\nHost: ..."
```
Fields include URL, method, status (when parsing responses), request/response bodies (truncated), plus raw payload slices from the send/recv syscalls.
