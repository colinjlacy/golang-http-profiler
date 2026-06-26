# Runtime Conditions Demos

This tree contains runnable examples and downstream adapter assets.

## Layout

- `apps/request-logger-http/` - Go workload that imports first-party declaration packages and demonstrates explicit profile declarations.
- `apps/todos-api/` - simple provider API used by the request logger demo.
- `catalog/apis/` - OpenAPI and catalog files used by the adapter demo.
- `kratix/` - Kratix Promise and adapter assets for downstream fulfillment demos.

## Generate the Request Logger Profile

From the repository root:

```sh
cd go/profiler
go run . \
  -dir ../../demos/apps/request-logger-http \
  -name request-logger-http \
  -workload-version dev
```

The request logger is its own Go module:

```sh
cd demos/apps/request-logger-http
go test ./...
```

## Published Demo Images

The workflow at `.github/workflows/publish-ghcr-images.yml` builds and pushes images for:

- `redis-pipeline`
- `application-release-pipeline`
- `todos-api`
- `request-logger`
