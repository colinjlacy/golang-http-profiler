package capture

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// PCAPParser reads tcpdump output and emits RawEvents
type PCAPParser struct {
	reader    *bufio.Reader
	pidFilter int
}

// NewPCAPParser creates a new tcpdump output parser
func NewPCAPParser(r io.Reader, pidFilter int) *PCAPParser {
	return &PCAPParser{
		reader:    bufio.NewReader(r),
		pidFilter: pidFilter,
	}
}

// TCPPacket represents a captured TCP packet
type TCPPacket struct {
	Timestamp  time.Time
	SourceIP   string
	SourcePort int
	DestIP     string
	DestPort   int
	Direction  Direction
	Data       []byte
	Flags      string
}

// NextPacket reads and parses the next packet from tcpdump output
func (p *PCAPParser) NextPacket() (*TCPPacket, error) {
	for {
		line, err := p.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		packet, err := p.parsePacket(line)
		if err != nil {
			// Skip unparseable lines
			continue
		}

		return packet, nil
	}
}

func (p *PCAPParser) parsePacket(line string) (*TCPPacket, error) {
	// Parse tcpdump output format
	// Example: "12:34:56.789012 IP 127.0.0.1.54321 > 127.0.0.1.8080: Flags [P.], length 123"

	parts := strings.Fields(line)
	if len(parts) < 6 {
		return nil, fmt.Errorf("not enough fields")
	}

	// Parse timestamp
	timestamp, err := parseTimestamp(parts[0])
	if err != nil {
		return nil, err
	}

	// Skip "IP" marker
	if parts[1] != "IP" && parts[1] != "IP6" {
		return nil, fmt.Errorf("not an IP packet")
	}

	// Parse source address (IP.port)
	sourceIP, sourcePort, err := parseAddress(parts[2])
	if err != nil {
		return nil, err
	}

	// Skip ">"
	if parts[3] != ">" {
		return nil, fmt.Errorf("malformed packet")
	}

	// Parse dest address (IP.port:)
	destAddr := strings.TrimSuffix(parts[4], ":")
	destIP, destPort, err := parseAddress(destAddr)
	if err != nil {
		return nil, err
	}

	packet := &TCPPacket{
		Timestamp:  timestamp,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		DestIP:     destIP,
		DestPort:   destPort,
	}

	// Parse flags and data
	for i := 5; i < len(parts); i++ {
		if parts[i] == "Flags" && i+1 < len(parts) {
			packet.Flags = strings.Trim(parts[i+1], "[],")
		}
		if parts[i] == "length" && i+1 < len(parts) {
			// We'll get the actual data from -X output
			break
		}
	}

	return packet, nil
}

func parseTimestamp(ts string) (time.Time, error) {
	// Parse HH:MM:SS.microseconds format
	now := time.Now()
	parts := strings.Split(ts, ":")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid timestamp format")
	}

	hour, _ := strconv.Atoi(parts[0])
	minute, _ := strconv.Atoi(parts[1])
	secParts := strings.Split(parts[2], ".")
	second, _ := strconv.Atoi(secParts[0])

	var microsecond int
	if len(secParts) > 1 {
		microsecond, _ = strconv.Atoi(secParts[1])
	}

	return time.Date(now.Year(), now.Month(), now.Day(),
		hour, minute, second, microsecond*1000, time.Local), nil
}

func parseAddress(addr string) (string, int, error) {
	// Parse "IP.port" format
	lastDot := strings.LastIndex(addr, ".")
	if lastDot == -1 {
		return "", 0, fmt.Errorf("invalid address format")
	}

	ip := addr[:lastDot]
	portStr := addr[lastDot+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}

	return ip, port, nil
}
