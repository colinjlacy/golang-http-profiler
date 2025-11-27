# Debugging Guide - No HTTP Transactions Captured

The profiler ran but didn't capture any HTTP transactions. Let's debug why.

## Step 1: Check TCPDump Output Format

Run this to see what tcpdump actually outputs:

```bash
sudo ./simple-tcpdump-test.sh
```

This will:
1. Start the test server
2. Capture tcpdump output to a file
3. Make one HTTP request
4. Show you the tcpdump output format

**Look for**: 
- Does the output contain HTTP request text (GET, POST, etc.)?
- What format is the packet data in?
- Is it readable ASCII or hex/binary?

## Step 2: Run Profiler with Debug Output

```bash
# Make sure server is running in Terminal 1
go run test/server.go

# In Terminal 2, run profiler with debug
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

**Look for debug output like**:
```
[DEBUG] HTTP packet: req=true resp=false data_len=123
[DEBUG] Parsed 1 HTTP transactions
```

If you see:
- **No debug output at all** = tcpdump parser isn't reading any packets
- **Packets but no HTTP** = tcpdump output format doesn't match our parser
- **HTTP packets but no transactions** = HTTP parser can't parse the stream

## Step 3: Check TCPDump is Working

Test tcpdump directly:

```bash
# Terminal 1: Start server
go run test/server.go

# Terminal 2: Run tcpdump manually
sudo tcpdump -A -s 0 -n -i lo0 "tcp port 8080"

# Terminal 3: Make a request
curl http://localhost:8080/
```

You should see tcpdump output showing the HTTP request/response.

If tcpdump works manually but not in the profiler, the issue is our parser.

## Common Issues

### Issue 1: TCPDump Output Format

TCPDump `-A` flag outputs ASCII, but in a specific format:

```
13:24:17.123456 IP 127.0.0.1.54321 > 127.0.0.1.8080: Flags [P.], length 123
E..{..@.@.............GET / HTTP/1.1
Host: localhost:8080
```

The parser needs to handle this format correctly.

### Issue 2: Buffering

TCPDump might be buffering output. The `-l` flag should fix this, but if not:
- Try adding `-U` (unbuffered)
- Try redirecting stderr: `2>&1`

### Issue 3: Interface Name

If tcpdump says "No such device":
- Check interface name: `ifconfig | grep "^lo"`
- Update in `main_tcpdump.go` if needed (might be `lo` not `lo0`)

### Issue 4: Parser Not Reading Lines

If the scanner isn't reading lines from tcpdump stdout:
- TCPDump stderr might be going to stdout
- Buffering issues
- Process startup timing

## Next Steps

After running the tests above, report back with:

1. **TCPDump output file** (`tcpdump-output.txt`) - what does it look like?
2. **Debug output** - do you see any `[DEBUG]` lines?
3. **TCPDump manual test** - does it work when run directly?

Then we can fix the specific issue.

## Quick Fixes to Try

### Fix 1: Change TCPDump Flags

Edit `cmd/adi-profiler/main_tcpdump.go` line with tcpdump command:

```go
// Try with different flags
cmd := exec.Command("tcpdump",
    "-A",           // ASCII
    "-s", "0",      // full packets
    "-n",           // no name resolution
    "-i", "lo0",    // interface
    "-l",           // line buffered
    "-U",           // packet buffered (add this)
    "tcp port 8080")
```

### Fix 2: Capture Both Stdout and Stderr

Edit `cmd/adi-profiler/main_tcpdump.go`:

```go
stdout, err := cmd.StdoutPipe()
// ... 
// Change this:
cmd.Stderr = os.Stderr
// To this:
stderr, _ := cmd.StderrPipe()
go io.Copy(os.Stderr, stderr)
```

### Fix 3: Use -X Instead of -A

Change `-A` to `-X` in tcpdump command for hex+ASCII output, then update parser to handle hex format.

## Alternative: Use gopacket Library

If tcpdump parsing continues to be problematic, we could switch to using the `gopacket` library to capture packets directly in Go. This would:
- ✅ More reliable parsing
- ✅ Better control over packet data
- ❌ Requires CGO and libpcap-dev
- ❌ Additional dependency

Let me know what you find from the debug tests and we'll fix the specific issue!

