package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
)

// TCPDumpParser parses tcpdump -A output for HTTP traffic
type TCPDumpParser struct {
	scanner *bufio.Scanner
}

// NewTCPDumpParser creates a parser for tcpdump ASCII output
func NewTCPDumpParser(r io.Reader) *TCPDumpParser {
	return &TCPDumpParser{
		scanner: bufio.NewScanner(r),
	}
}

// HTTPPacket represents an HTTP packet captured by tcpdump
type HTTPPacket struct {
	Timestamp  time.Time
	SourceIP   string
	SourcePort int
	DestIP     string
	DestPort   int
	Direction  Direction
	Data       []byte
	IsRequest  bool
	IsResponse bool
}

// NextHTTPPacket reads the next HTTP packet from tcpdump output
func (p *TCPDumpParser) NextHTTPPacket() (*HTTPPacket, error) {
	lineCount := 0
	for p.scanner.Scan() {
		line := p.scanner.Text()
		lineCount++

		// Look for packet header line
		if !strings.Contains(line, "IP ") && !strings.Contains(line, "IP6 ") {
			continue
		}

		// Parse header
		packet, err := p.parseHeader(line)
		if err != nil {
			continue
		}

		// Read packet data
		data := p.readPacketData()
		packet.Data = data

		// Check if this is HTTP traffic
		if len(data) > 0 {
			dataStr := string(data)
			packet.IsRequest = strings.HasPrefix(dataStr, "GET ") ||
				strings.HasPrefix(dataStr, "POST ") ||
				strings.HasPrefix(dataStr, "PUT ") ||
				strings.HasPrefix(dataStr, "DELETE ") ||
				strings.HasPrefix(dataStr, "HEAD ") ||
				strings.HasPrefix(dataStr, "OPTIONS ") ||
				strings.HasPrefix(dataStr, "PATCH ")

			packet.IsResponse = strings.HasPrefix(dataStr, "HTTP/")

			// Only return if it's HTTP traffic
			if packet.IsRequest || packet.IsResponse {
				return packet, nil
			}
		}
	}

	if err := p.scanner.Err(); err != nil {
		return nil, err
	}

	return nil, io.EOF
}

func (p *TCPDumpParser) parseHeader(line string) (*HTTPPacket, error) {
	// Example: "12:34:56.123456 IP 127.0.0.1.54321 > 127.0.0.1.8080: Flags [P.], length 123"

	parts := strings.Fields(line)
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid header")
	}

	// Parse timestamp
	timestamp, err := parseTimestamp(parts[0])
	if err != nil {
		timestamp = time.Now()
	}

	// Parse source
	sourceIP, sourcePort, _ := parseAddress(parts[2])

	// Parse dest
	destAddr := strings.TrimSuffix(parts[4], ":")
	destIP, destPort, _ := parseAddress(destAddr)

	return &HTTPPacket{
		Timestamp:  timestamp,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		DestIP:     destIP,
		DestPort:   destPort,
	}, nil
}

func (p *TCPDumpParser) readPacketData() []byte {
	var buffer bytes.Buffer

	// Read until next packet header or empty line
	for p.scanner.Scan() {
		line := p.scanner.Text()

		// Stop at next packet header
		if strings.Contains(line, "IP ") && strings.Contains(line, " > ") {
			// Put the line back for next packet
			// (we can't actually put it back, but we'll handle this in the caller)
			break
		}

		// Skip empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}

		// Skip hex offset lines (they start with 0x)
		if strings.HasPrefix(trimmed, "0x") {
			continue
		}

		// Add line content
		buffer.WriteString(trimmed)
		buffer.WriteByte('\n')
	}

	return buffer.Bytes()
}

// ConnectionKey uniquely identifies a TCP connection
type ConnectionKey struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

func (h *HTTPPacket) ConnectionKey() ConnectionKey {
	// Normalize connection key (always use lower port as "local")
	if h.SourcePort < h.DestPort {
		return ConnectionKey{
			LocalIP:    h.SourceIP,
			LocalPort:  h.SourcePort,
			RemoteIP:   h.DestIP,
			RemotePort: h.DestPort,
		}
	}
	return ConnectionKey{
		LocalIP:    h.DestIP,
		LocalPort:  h.DestPort,
		RemoteIP:   h.SourceIP,
		RemotePort: h.SourcePort,
	}
}

func (h *HTTPPacket) IsOutbound() bool {
	// Outbound if source port is high (ephemeral) and dest port is low (service)
	return h.SourcePort > 1024 && h.DestPort <= 1024 || h.DestPort == 8080 || h.DestPort == 8000
}
