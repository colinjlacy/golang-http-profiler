FROM golang:1.25-alpine AS build

WORKDIR /src
COPY extensions ./extensions
COPY demos/apps/request-logger-http/go.mod ./demos/apps/request-logger-http/go.mod
COPY demos/apps/request-logger-http/*.go ./demos/apps/request-logger-http/

WORKDIR /src/demos/apps/request-logger-http
RUN go mod download
RUN go build -o /out/request-logger .

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/request-logger /request-logger

ENTRYPOINT ["/request-logger"]
