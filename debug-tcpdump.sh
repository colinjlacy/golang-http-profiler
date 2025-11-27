#!/bin/bash

# Debug script to see what tcpdump actually outputs

echo "Testing tcpdump output format..."
echo "================================"
echo ""
echo "Starting test server in background..."

go run test/server.go &
SERVER_PID=$!
sleep 2

echo "Starting tcpdump capture (will capture 10 packets)..."
echo ""

# Run tcpdump with same flags as profiler
sudo tcpdump -A -s 0 -n -i lo0 -l -c 10 "tcp port 8080" &
TCPDUMP_PID=$!

sleep 1

# Make a test request
echo "Making test HTTP request..."
curl -s http://localhost:8080/ > /dev/null

sleep 2

# Stop everything
kill $TCPDUMP_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "================================"
echo "Check the output above to see tcpdump format"

