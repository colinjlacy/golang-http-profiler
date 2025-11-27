# Quick Test Guide - TCPDump Mode

Run these commands to test the profiler with tcpdump mode (works with SIP):

## 1. Build

```bash
go build -o adi-profiler ./cmd/adi-profiler
```

## 2. Start Server (Terminal 1)

```bash
go run test/server.go
```

Leave this running.

## 3. Run Profiler (Terminal 2)

```bash
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

You'll see output like:

```
ADI Profiler starting (tcpdump mode)...
Target command: [go run test/client.go]
Target process started with PID 12345
TCPDump started with PID 12346
Capturing HTTP traffic on ports 80, 3000, 8000, 8080

[12:34:56.123] PID 12345: GET / → 200 OK
[12:34:56.234] PID 12345: GET /users → 200 OK
[12:34:56.345] PID 12345: GET /user/42 → 200 OK
[12:34:56.456] PID 12345: GET /echo?message=hello → 200 OK
[12:34:56.567] PID 12345: GET /echo?message=world → 200 OK

Target process exited
Profiling complete. Output written to adi-trace.txt
```

## 4. View Results

```bash
cat adi-trace.txt
```

Should show 5 HTTP transactions with full request/response details.

## Or: Use Automated Test

```bash
sudo ./test-tcpdump.sh
```

This runs everything automatically and reports success/failure.

## Expected Success Criteria

- ✅ No SIP errors
- ✅ 5 HTTP transactions captured
- ✅ Requests and responses complete
- ✅ Output file created

## If It Doesn't Work

1. **Check tcpdump**: `which tcpdump`
2. **Check server is running**: `curl http://localhost:8080/`
3. **Check interface name**: `ifconfig | grep lo`
   - If not `lo0`, update `main_tcpdump.go` line with your interface name

## Cleanup

```bash
rm adi-trace.txt
```

---

**Note**: This mode works on any Mac with SIP enabled. No need to disable security features!

