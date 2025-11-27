#!/bin/bash

# Test script for tcpdump mode
# This validates the profiler works with SIP enabled

echo "========================================="
echo "ADI Profiler - TCPDump Mode Test"
echo "========================================="
echo ""

# Check if binary exists
if [ ! -f "./adi-profiler" ]; then
    echo "❌ Error: adi-profiler binary not found"
    echo "   Run: go build -o adi-profiler ./cmd/adi-profiler"
    exit 1
fi

echo "✅ Profiler binary found"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Error: Must run as root"
    echo "   Run: sudo ./test-tcpdump.sh"
    exit 1
fi

echo "✅ Running as root"
echo ""

# Check if tcpdump is available
if ! command -v tcpdump &> /dev/null; then
    echo "❌ Error: tcpdump not found"
    exit 1
fi

echo "✅ tcpdump is available"
echo ""

# Start test server in background
echo "Starting test HTTP server..."
go run test/server.go &
SERVER_PID=$!

# Give server time to start
sleep 2

# Check if server started
if ! ps -p $SERVER_PID > /dev/null; then
    echo "❌ Error: Test server failed to start"
    exit 1
fi

echo "✅ Test server started (PID $SERVER_PID)"
echo ""

# Run profiler with tcpdump mode
echo "Running profiler in tcpdump mode..."
echo "---"
./adi-profiler --tcpdump run -- go run test/client.go

PROFILER_EXIT=$?

# Stop server
echo ""
echo "Stopping test server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "========================================="

# Check results
if [ $PROFILER_EXIT -eq 0 ]; then
    echo "✅ Profiler completed successfully"
else
    echo "❌ Profiler exited with error code $PROFILER_EXIT"
fi

# Check if trace file was created
if [ -f "adi-trace.txt" ]; then
    echo "✅ Trace file created"
    
    # Count HTTP transactions
    TRANSACTION_COUNT=$(grep -c "HTTP GET" adi-trace.txt)
    echo "📊 Captured $TRANSACTION_COUNT HTTP transactions"
    
    if [ $TRANSACTION_COUNT -ge 5 ]; then
        echo "✅ All expected transactions captured"
        echo ""
        echo "========================================="
        echo "🎉 Test PASSED!"
        echo "========================================="
        echo ""
        echo "View the trace file:"
        echo "  cat adi-trace.txt"
        exit 0
    else
        echo "⚠️  Expected at least 5 transactions, got $TRANSACTION_COUNT"
        echo ""
        echo "View the trace file:"
        echo "  cat adi-trace.txt"
        exit 1
    fi
else
    echo "❌ Trace file not created"
    exit 1
fi

