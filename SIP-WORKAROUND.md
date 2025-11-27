# System Integrity Protection (SIP) Workaround

If you're running on a Mac with System Integrity Protection (SIP) enabled (most corporate Macs), DTrace syscall probes will be blocked.

## The Problem

When you try to run the profiler with DTrace, you'll see an error like:

```
dtrace: system integrity protection is on, some features will not be available
dtrace: failed to compile script: probe description syscall::socket:return does not match any probes
```

## The Solution: TCPDump Mode

The profiler automatically includes a **tcpdump mode** that works with SIP enabled.

### How to Use

Simply run the profiler normally - it will **automatically fall back to tcpdump** if DTrace fails:

```bash
sudo ./adi-profiler run -- go run test/client.go
```

Or explicitly use tcpdump mode:

```bash
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

### How It Works

Instead of using DTrace to capture syscalls, the profiler uses `tcpdump` to capture network packets on the loopback interface. This:

- **Works with SIP enabled** - no need to disable security features
- **Captures all HTTP traffic** on common ports (80, 3000, 8000, 8080)
- **Parses packets in real-time** - same output format as DTrace mode
- **Requires sudo** - tcpdump needs root privileges to capture packets

### Differences from DTrace Mode

| Feature | DTrace Mode | TCPDump Mode |
|---------|-------------|--------------|
| Works with SIP | ❌ No | ✅ Yes |
| Captures HTTP | ✅ Yes | ✅ Yes |
| Shows PID | ✅ Yes | ⚠️ Limited |
| Filesystem tracing | ✅ Yes | ❌ No |
| Process-specific | ✅ Yes | ⚠️ Port-based |

### Limitations of TCPDump Mode

1. **Port-based filtering**: Captures all traffic on specified ports, not just from target process
2. **No PID tracking**: Can't distinguish between multiple processes using the same port
3. **HTTP only**: Can't capture filesystem or other syscall activity
4. **Common ports only**: Currently monitors ports 80, 3000, 8000, 8080

### Testing

```bash
# Terminal 1: Start test server
go run test/server.go

# Terminal 2: Run client with tcpdump mode
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

You should see HTTP transactions captured in `adi-trace.txt`.

### Troubleshooting

**"tcpdump: lo0: No such device exists"**
→ Loopback interface might have a different name. Check with `ifconfig`

**No packets captured**
→ Make sure the test server is running on port 8080
→ Try adding more ports to the filter in `main_tcpdump.go`

**Permission denied**
→ Use `sudo` to run the profiler

### For Production Use

For more reliable profiling on SIP-protected systems, consider:

1. **Use tcpdump mode** (current solution) - works for HTTP traffic
2. **Disable SIP temporarily** (not recommended for corporate machines)
3. **Use application-level instrumentation** (requires code changes)
4. **Run on Linux** - eBPF doesn't have SIP restrictions

## Future Enhancements

The tcpdump mode can be improved to:
- Support more ports/protocols
- Better PID attribution using `lsof` to correlate ports to processes
- Capture non-HTTP protocols
- Support multiple protocols simultaneously

For now, it provides a reliable way to capture HTTP traffic on SIP-protected Macs.

