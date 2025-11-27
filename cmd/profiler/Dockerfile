ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends clang llvm make pkg-config libelf-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN go mod download
RUN go generate ./pkg/profiler
WORKDIR /src/cmd/profiler
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags ebpf_build -o /bin/ebpf-profiler

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /bin/ebpf-profiler /usr/local/bin/ebpf-profiler
VOLUME ["/output"]
ENTRYPOINT ["ebpf-profiler"]
