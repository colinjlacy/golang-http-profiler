# Go Runtime Conditions

This tree contains the maintained Go AST profiler module.

## Layout

- `profiler/`: CLI module for generating Runtime Conditions Profile YAML.
- `profiler/extractor/`: Go AST extractor used by the CLI.

First-party Go declaration packages live beside their extension definitions under `extensions/*/go`. Demo applications live under `demos/apps`.

## Generate a Profile

```sh
cd profiler
go run . \
  -dir ../../demos/apps/request-logger-http \
  -name request-logger-http \
  -workload-version dev
```

## Test

```sh
cd profiler
go test ./...
```
