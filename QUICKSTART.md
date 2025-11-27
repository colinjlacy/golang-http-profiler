# Quick Start Guide

Get the HTTP profiler running in under 5 minutes.

## Step 1: Build the Profiler

```bash
go build -o adi-profiler ./cmd/adi-profiler
```

## Step 2: Start Test Server

In one terminal window:

```bash
go run test/server.go
```

You should see: `Test HTTP server starting on :8080`

## Step 3: Run Client Under Profiling

In another terminal window:

```bash
sudo ./adi-profiler run -- go run test/client.go
```

**Note for Corporate Macs**: If you see a "System Integrity Protection" error, the profiler will automatically switch to tcpdump mode, which works with SIP enabled. See [SIP-WORKAROUND.md](SIP-WORKAROUND.md) for details.

You can also explicitly use tcpdump mode:

```bash
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

You'll be prompted for your password (required for packet capture).

## Step 4: View Results

Check the console output for real-time transaction logs, then open `adi-trace.txt` to see the full trace:

```bash
cat adi-trace.txt
```

## Expected Output

You should see 5 HTTP transactions captured:

1. GET /
2. GET /users
3. GET /user/42
4. GET /echo?message=hello
5. GET /echo?message=world

Each transaction shows:
- Timestamp and PID
- Request method and URL
- Request headers
- Response status code
- Response headers and body

## Next Steps

Try profiling your own applications:

```bash
sudo ./adi-profiler run -- your-http-client-command
```

The profiler will capture all HTTP/1.x traffic made by your command.

## Troubleshooting

**"must run as root"**
→ Use `sudo` to run the profiler

**"System Integrity Protection" error**
→ The profiler will automatically use tcpdump mode
→ Or explicitly use: `sudo ./adi-profiler --tcpdump run -- your-command`
→ See [SIP-WORKAROUND.md](SIP-WORKAROUND.md) for details

**"could not find capture.d script"**
→ Make sure you're running from the project root directory
→ Or use `--tcpdump` mode which doesn't need the script

**No output in trace file**
→ Ensure your target application makes HTTP requests to port 8080
→ Check that tcpdump is working: `sudo tcpdump -i lo0 -c 5`

**Server connection refused**
→ Make sure the test server is running in another terminal

