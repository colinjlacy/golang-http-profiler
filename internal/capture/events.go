package capture

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Direction indicates whether data is being read or written
type Direction int

const (
	DirIn  Direction = 1 // read
	DirOut Direction = 2 // write
)

func (d Direction) String() string {
	if d == DirIn {
		return "IN"
	}
	return "OUT"
}

// EventType represents the type of syscall event
type EventType string

const (
	EventSocket  EventType = "SOCKET"
	EventConnect EventType = "CONNECT"
	EventAccept  EventType = "ACCEPT"
	EventRead    EventType = "READ"
	EventWrite   EventType = "WRITE"
	EventClose   EventType = "CLOSE"
	EventStart   EventType = "DTRACE_START"
	EventEnd     EventType = "DTRACE_END"
)

// RawEvent represents a syscall event from DTrace
type RawEvent struct {
	Type       EventType
	Timestamp  time.Time
	PID        int
	Fd         int
	Direction  Direction
	Data       []byte
	Size       int // actual size (may be larger than len(Data) if truncated)
	RemoteAddr string
	LocalAddr  string
	ReturnCode int // for connect, etc.
}

// Parser reads DTrace output and emits RawEvents
type Parser struct {
	reader *bufio.Reader
}

// NewParser creates a new DTrace output parser
func NewParser(r io.Reader) *Parser {
	return &Parser{
		reader: bufio.NewReader(r),
	}
}

// NextEvent reads and parses the next event from DTrace output
// Returns io.EOF when done
func (p *Parser) NextEvent() (*RawEvent, error) {
	line, err := p.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return p.NextEvent() // skip empty lines
	}

	parts := strings.Split(line, "\t")
	if len(parts) < 1 {
		return p.NextEvent() // skip malformed lines
	}

	eventType := EventType(parts[0])

	// Handle special events
	switch eventType {
	case EventStart, EventEnd:
		return &RawEvent{Type: eventType}, nil
	}

	// All other events need at least: TYPE, TIMESTAMP, PID, FD
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed event line: %s", line)
	}

	event := &RawEvent{Type: eventType}

	// Parse timestamp (nanoseconds since epoch)
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}
	event.Timestamp = time.Unix(0, ts)

	// Parse PID
	pid, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid PID: %w", err)
	}
	event.PID = pid

	// Parse FD
	fd, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid FD: %w", err)
	}
	event.Fd = fd

	// Type-specific parsing
	switch eventType {
	case EventSocket:
		// SOCKET timestamp pid fd
		// Nothing more to parse

	case EventConnect:
		// CONNECT timestamp pid fd returncode
		if len(parts) >= 5 {
			rc, _ := strconv.Atoi(parts[4])
			event.ReturnCode = rc
		}

	case EventAccept:
		// ACCEPT timestamp pid fd
		// Nothing more to parse

	case EventRead:
		// READ timestamp pid fd size data
		if len(parts) >= 5 {
			size, _ := strconv.Atoi(parts[4])
			event.Size = size
			event.Direction = DirIn

			if len(parts) >= 6 {
				// Data is the rest of the line
				event.Data = []byte(parts[5])
			}
		}

	case EventWrite:
		// WRITE timestamp pid fd size data
		if len(parts) >= 5 {
			size, _ := strconv.Atoi(parts[4])
			event.Size = size
			event.Direction = DirOut

			if len(parts) >= 6 {
				// Data is the rest of the line
				event.Data = []byte(parts[5])
			}
		}

	case EventClose:
		// CLOSE timestamp pid fd
		// Nothing more to parse
	}

	return event, nil
}
