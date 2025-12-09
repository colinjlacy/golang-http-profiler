ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-bookworm AS build

WORKDIR /src
COPY . .
WORKDIR /src/cmd/request-logger
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /bin/request-logger

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /bin/request-logger /usr/local/bin/request-logger
ENTRYPOINT ["request-logger"]

