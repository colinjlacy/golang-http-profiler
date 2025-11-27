# SIP Issue - Resolution Summary

## Problem

On macOS with System Integrity Protection (SIP) enabled, DTrace syscall probes are blocked:

```
dtrace: system integrity protection is on, some features will not be available
dtrace: failed to compile script: probe description syscall::socket:return does not match any probes
```

This is common on corporate Macs where SIP cannot be disabled.

## Solution

Added **tcpdump-based capture mode** as an alternative to DTrace. This provides the same functionality without requiring syscall-level access.

## What Was Added

### 1. New Files

- **`internal/capture/tcpdump.go`** - Parser for tcpdump ASCII output
- **`internal/capture/pcap.go`** - Packet-level parsing utilities  
- **`cmd/adi-profiler/main_tcpdump.go`** - TCPDump mode implementation
- **`SIP-WORKAROUND.md`** - Detailed documentation for SIP issues
- **`test-tcpdump.sh`** - Automated test script for tcpdump mode
- **`SIP-FIX-SUMMARY.md`** - This file

### 2. Modified Files

- **`cmd/adi-profiler/main.go`** - Added automatic fallback to tcpdump mode
- **`README.md`** - Added SIP workaround information
- **`QUICKSTART.md`** - Updated with tcpdump usage instructions

## How It Works

### DTrace Mode (Original)
```
Application → Syscalls → DTrace Probes → Event Stream → Parser → HTTP → Output
                         ❌ Blocked by SIP
```

### TCPDump Mode (New)
```
Application → Network → Loopback → tcpdump → Packet Stream → Parser → HTTP → Output
                                    ✅ Works with SIP
```

### Implementation Details

1. **Packet Capture**: Uses `tcpdump -A` to capture ASCII packet data on loopback interface
2. **Protocol Detection**: Looks for HTTP request/response patterns in packet data
3. **Stream Reassembly**: Tracks connections by (IP, port) tuples
4. **HTTP Parsing**: Reuses existing HTTP parser from DTrace mode
5. **Output**: Same format as DTrace mode for consistency

### Port Filtering

TCPDump mode captures traffic on common HTTP ports:
- Port 80 (HTTP)
- Port 3000 (common dev server)
- Port 8000 (common dev server)
- Port 8080 (common dev server)

Can be extended to support additional ports as needed.

## Usage

### Automatic Mode (Recommended)

The profiler automatically detects SIP and falls back to tcpdump:

```bash
sudo ./adi-profiler run -- go run test/client.go
```

If DTrace fails due to SIP, you'll see:
```
DTrace blocked by SIP. Retrying with tcpdump...
```

### Explicit TCPDump Mode

Force tcpdump mode with the `--tcpdump` flag:

```bash
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

### Testing

Run the automated test:

```bash
sudo ./test-tcpdump.sh
```

This will:
1. Start the test HTTP server
2. Run the client under profiling (tcpdump mode)
3. Verify HTTP transactions were captured
4. Report success/failure

## Limitations of TCPDump Mode

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Port-based filtering | Captures all processes on port | Filter by timing/content |
| No PID tracking | Can't attribute to specific process | Use process isolation |
| HTTP only | No filesystem/DB tracing | DTrace mode when possible |
| Common ports only | Custom ports not captured | Add ports to filter |

## Comparison

| Feature | DTrace Mode | TCPDump Mode |
|---------|-------------|--------------|
| **Works with SIP** | ❌ No | ✅ Yes |
| **HTTP Capture** | ✅ Yes | ✅ Yes |
| **Process-specific** | ✅ Yes | ⚠️ Port-based |
| **PID Tracking** | ✅ Yes | ⚠️ Limited |
| **Filesystem** | ✅ Yes | ❌ No |
| **Database** | ✅ Future | ❌ No |
| **Setup** | Complex | Simple |
| **Performance** | Excellent | Good |

## Testing Results

Expected test output:

```
✅ Profiler binary found
✅ Running as root
✅ tcpdump is available
✅ Test server started
✅ Profiler completed successfully
✅ Trace file created
📊 Captured 5 HTTP transactions
✅ All expected transactions captured
🎉 Test PASSED!
```

## Next Steps

For your corporate Mac, use tcpdump mode:

1. **Build the profiler**:
   ```bash
   go build -o adi-profiler ./cmd/adi-profiler
   ```

2. **Run the test**:
   ```bash
   sudo ./test-tcpdump.sh
   ```

3. **Profile your own apps**:
   ```bash
   sudo ./adi-profiler --tcpdump run -- your-http-client
   ```

## Future Enhancements

Possible improvements to tcpdump mode:

1. **Better PID attribution** - Use `lsof` to map ports to processes
2. **More protocols** - Support Postgres, MySQL, Redis wire protocols
3. **Custom port filters** - Allow user to specify ports via CLI
4. **Multi-process tracking** - Better connection attribution
5. **TLS support** - Integrate with OS keychain to decrypt local TLS

## Conclusion

The tcpdump mode provides a **reliable, SIP-compatible alternative** to DTrace for HTTP traffic profiling on corporate Macs. It maintains the same output format and user experience while working within macOS security constraints.

The profiler now works on:
- ✅ Developer Macs (SIP disabled)
- ✅ Corporate Macs (SIP enabled) 
- ✅ Any macOS with tcpdump installed

