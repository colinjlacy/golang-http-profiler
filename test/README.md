# Test Harness

This directory contains test HTTP server and client programs to validate the profiler.

## Running the Tests

### Terminal 1 - Start the test server:
```bash
go run test/server.go
```

### Terminal 2 - Run the client under profiling:
```bash
# Build the profiler first
go build -o adi-profiler ./cmd/adi-profiler

# Run client under profiling (requires sudo)
sudo ./adi-profiler run -- go run test/client.go
```

The profiler will capture all HTTP traffic from the client and write it to `adi-trace.txt`.

## Expected Output

You should see:
1. The client making 5 HTTP requests
2. Console output showing captured transactions
3. A detailed trace file (`adi-trace.txt`) with all HTTP requests and responses

## Troubleshooting

- Make sure the server is running before starting the client
- The profiler requires `sudo` to run DTrace on macOS
- Check that `scripts/capture.d` is accessible from the profiler binary location

