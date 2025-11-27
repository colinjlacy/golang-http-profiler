#!/bin/bash

# Simple test to see tcpdump output format

echo "Starting server..."
go run test/server.go &
SERVER_PID=$!
sleep 2

echo ""
echo "Capturing tcpdump output to file..."
echo "===================================="

# Capture to file so we can inspect it
timeout 5 sudo tcpdump -A -s 0 -n -i lo0 -l "tcp port 8080" > tcpdump-output.txt 2>&1 &
TCPDUMP_PID=$!

sleep 1

# Make one request
echo "Making HTTP request..."
curl -s http://localhost:8080/ > /dev/null

sleep 2

# Stop tcpdump gracefully
sudo kill -INT $TCPDUMP_PID 2>/dev/null
sleep 1

# Kill server
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "TCPDump output saved to: tcpdump-output.txt"
echo ""
echo "First 50 lines:"
echo "===================================="
head -50 tcpdump-output.txt
echo "===================================="
echo ""
echo "Full output available in: tcpdump-output.txt"

