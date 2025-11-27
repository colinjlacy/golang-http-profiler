# Debugging Steps - Empty Trace File Issue

## Problem

The profiler runs successfully but `adi-trace.txt` only contains the header and footer - no HTTP transactions were captured.

## What I've Done

1. **Added debug logging** to show:
   - How many packets were captured
   - How many HTTP packets were detected
   - How many transactions were parsed

2. **Added `-v` flag** to tcpdump (verbose mode) - this might help show packet contents

3. **Created debug scripts**:
   - `simple-tcpdump-test.sh` - captures tcpdump output to a file so you can inspect it
   - `debug-tcpdump.sh` - tests tcpdump directly
   - `DEBUG-GUIDE.md` - comprehensive debugging guide

## Next Steps for You

### Step 1: Test with Updated Profiler

The profiler has been rebuilt with debug output. Try running it again:

```bash
# Terminal 1: Start server
go run test/server.go

# Terminal 2: Run profiler with debug output
sudo ./adi-profiler --tcpdump run -- go run test/client.go
```

**Look for lines like**:
```
[DEBUG] HTTP packet: req=true resp=false data_len=123
[DEBUG] Parsed 1 HTTP transactions
```

If you see these debug lines, the parser is working but something else is wrong.  
If you don't see any debug lines, tcpdump output isn't being read correctly.

### Step 2: Inspect TCPDump Output Format

Run this to see what tcpdump actually outputs:

```bash
sudo ./simple-tcpdump-test.sh
```

This will create `tcpdump-output.txt`. Open it and check:
- Does it contain HTTP request text (like "GET / HTTP/1.1")?
- What format is it in?
- Share the first 50 lines with me

### Step 3: Test TCPDump Manually

```bash
# Terminal 1
go run test/server.go

# Terminal 2  
sudo tcpdump -A -s 0 -n -i lo0 -v "tcp port 8080"

# Terminal 3
curl http://localhost:8080/
```

Do you see HTTP request/response text in Terminal 2?

## Likely Issues

### Issue #1: TCPDump Output Not Being Read

**Symptom**: No debug output at all  
**Cause**: Scanner not reading from tcpdump stdout  
**Fix**: Need to debug why stdout pipe isn't working

### Issue #2: TCPDump Format Not Recognized

**Symptom**: "Total packets: 0"  
**Cause**: Parser doesn't recognize tcpdump output format  
**Fix**: Need to see actual tcpdump output and adjust parser

### Issue #3: HTTP Detection Failing

**Symptom**: "Total packets: X, HTTP packets: 0"  
**Cause**: Packet data doesn't match HTTP patterns  
**Fix**: Need to adjust how we extract ASCII from tcpdump output

### Issue #4: HTTP Parsing Failing

**Symptom**: "HTTP packets: X" but no transactions  
**Cause**: HTTP parser can't reassemble streams  
**Fix**: Need to debug stream reassembly logic

## What to Share

After running the tests, please share:

1. **Console output** from running the profiler (especially `[DEBUG]` lines)
2. **First 50-100 lines of `tcpdump-output.txt`**
3. **Result of manual tcpdump test** (did you see HTTP text?)

Then I can provide a specific fix!

## Alternative: Use Different Capture Method

If tcpdump parsing continues to be difficult, we have alternatives:

### Option A: Use gopacket Library
- Go library for packet capture
- More reliable than parsing tcpdump text
- Requires: `go get github.com/google/gopacket`
- Requires: libpcap

### Option B: Network Proxy
- Run a local HTTP proxy
- Intercept requests/responses
- Simpler parsing, no packet capture needed
- Works with any security settings

### Option C: Fix DTrace for SIP
- Request SIP to be disabled (requires IT approval on corporate Macs)
- Or use partial DTrace capabilities that work with SIP

Let me know what you find from the debug tests!

