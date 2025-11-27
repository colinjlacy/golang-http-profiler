package stream

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/colinjlacy/golang-ast-inspection/internal/capture"
)

// StreamID uniquely identifies a TCP stream
type StreamID struct {
	PID int
	Fd  int
}

func (s StreamID) String() string {
	return fmt.Sprintf("pid=%d,fd=%d", s.PID, s.Fd)
}

// TCPStream represents a bidirectional TCP connection
type TCPStream struct {
	ID         StreamID
	RemoteAddr string
	LocalAddr  string
	InBuffer   *bytes.Buffer // data read from socket
	OutBuffer  *bytes.Buffer // data written to socket
	Closed     bool
}

// NewTCPStream creates a new TCP stream
func NewTCPStream(id StreamID) *TCPStream {
	return &TCPStream{
		ID:        id,
		InBuffer:  &bytes.Buffer{},
		OutBuffer: &bytes.Buffer{},
	}
}

// Tracker manages all active TCP streams
type Tracker struct {
	streams map[StreamID]*TCPStream
	mu      sync.RWMutex
}

// NewTracker creates a new stream tracker
func NewTracker() *Tracker {
	return &Tracker{
		streams: make(map[StreamID]*TCPStream),
	}
}

// ProcessEvent processes a raw event and updates stream state
func (t *Tracker) ProcessEvent(event *capture.RawEvent) (*TCPStream, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	id := StreamID{PID: event.PID, Fd: event.Fd}

	switch event.Type {
	case capture.EventSocket:
		// Create a new stream for this socket
		stream := NewTCPStream(id)
		t.streams[id] = stream
		return stream, nil

	case capture.EventConnect:
		// Mark stream as connected (we'll get address info later if needed)
		stream := t.getOrCreateStream(id)
		return stream, nil

	case capture.EventAccept:
		// New inbound connection
		stream := NewTCPStream(id)
		t.streams[id] = stream
		return stream, nil

	case capture.EventRead:
		// Append data to inbound buffer
		stream := t.getOrCreateStream(id)
		if len(event.Data) > 0 {
			stream.InBuffer.Write(event.Data)
		}
		return stream, nil

	case capture.EventWrite:
		// Append data to outbound buffer
		stream := t.getOrCreateStream(id)
		if len(event.Data) > 0 {
			stream.OutBuffer.Write(event.Data)
		}
		return stream, nil

	case capture.EventClose:
		// Mark stream as closed
		stream := t.getStream(id)
		if stream != nil {
			stream.Closed = true
		}
		return stream, nil
	}

	return nil, nil
}

// GetStream returns the stream for a given ID
func (t *Tracker) GetStream(id StreamID) *TCPStream {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getStream(id)
}

func (t *Tracker) getStream(id StreamID) *TCPStream {
	return t.streams[id]
}

func (t *Tracker) getOrCreateStream(id StreamID) *TCPStream {
	stream := t.streams[id]
	if stream == nil {
		stream = NewTCPStream(id)
		t.streams[id] = stream
	}
	return stream
}

// GetAllStreams returns all active streams
func (t *Tracker) GetAllStreams() []*TCPStream {
	t.mu.RLock()
	defer t.mu.RUnlock()

	streams := make([]*TCPStream, 0, len(t.streams))
	for _, stream := range t.streams {
		streams = append(streams, stream)
	}
	return streams
}

// RemoveStream removes a stream from tracking
func (t *Tracker) RemoveStream(id StreamID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.streams, id)
}
