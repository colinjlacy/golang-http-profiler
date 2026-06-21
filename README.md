# Runtime Conditions Profilers

This repository contains three separate implementation areas:

- `ebpf-profiler/` - the original Linux eBPF runtime observation profiler.
- `go/` - Go declaration library, Go AST profiler, and Go sample services.
- `python/` - Python declaration library, Python AST profiler, and Python sample services.

The Runtime Conditions Profile specification draft lives in `docs/`. Start with
`docs/intro.md` for the core spec, extension drafts, and SDK integration guides.

The GitHub Pages reader site lives in `site/`. It is a static site that presents
the current spec, extension model, implementation guides, and end-to-end Kratix
demo as a cohesive reader flow. The workflow in `.github/workflows/pages.yml`
publishes that directory to GitHub Pages.

## eBPF Profiler

```sh
cd ebpf-profiler
go generate ./pkg/profiler
go test ./...
go build ./cmd/profiler
```

The generated eBPF bindings are produced by `bpf2go` from `ebpf-profiler/pkg/profiler/bpf.go`.

## Go AST Profiler

```sh
cd go
go test ./...
go run ./profiler/cmd/runtimeconditions -dir ./apps/traffic -name traffic-generator
docker compose up
```

## Python AST Profiler

```sh
cd python
python3 -m unittest discover -s tests
python3 -m runtimeconditions.profiler -d apps/traffic -n traffic-generator
docker compose up
```
