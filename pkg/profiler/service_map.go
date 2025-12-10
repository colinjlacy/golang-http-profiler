//go:build linux

package profiler

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// EndpointInfo represents a unique destination+method+path combination with schema info
type EndpointInfo struct {
	Destination     string      `yaml:"destination"`                // destination service name
	DestinationType string      `yaml:"destination_type,omitempty"` // "container", "external", or "unknown"
	Method          string      `yaml:"method"`
	Path            string      `yaml:"path"`
	RequestSchema   interface{} `yaml:"request_schema"`  // null, "non-json", or JSON structure
	ResponseSchema  interface{} `yaml:"response_schema"` // null, "non-json", or JSON structure
	FirstSeen       time.Time   `yaml:"first_seen"`
	LastSeen        time.Time   `yaml:"last_seen"`
	Count           int64       `yaml:"count"`
}

// ConnectionInfo represents a non-HTTP connection (database, cache, message bus)
type ConnectionInfo struct {
	Destination     string    `yaml:"destination"`                // destination service/host name
	DestinationType string    `yaml:"destination_type,omitempty"` // "container", "external", or "unknown"
	Protocol        string    `yaml:"protocol"`                   // e.g., "postgres", "mysql", "redis"
	Category        string    `yaml:"category"`                   // e.g., "database", "cache", "message_bus"
	Port            uint16    `yaml:"port"`                       // Remote port
	Confidence      int       `yaml:"confidence"`                 // 0-100 confidence score
	Reason          string    `yaml:"reason,omitempty"`           // Detection reason
	FirstSeen       time.Time `yaml:"first_seen"`
	LastSeen        time.Time `yaml:"last_seen"`
	Count           int64     `yaml:"count"`
}

// ServiceProfile represents all outbound activity from a single service
type ServiceProfile struct {
	Name        string            `yaml:"name"`
	Image       string            `yaml:"image,omitempty"`
	Endpoints   []*EndpointInfo   `yaml:"endpoints,omitempty"`   // HTTP endpoints called
	Connections []*ConnectionInfo `yaml:"connections,omitempty"` // Non-HTTP connections (databases, caches, etc.)
	FirstSeen   time.Time         `yaml:"first_seen"`
	LastSeen    time.Time         `yaml:"last_seen"`
}

// PendingRequest stores request info while waiting for response
type PendingRequest struct {
	SrcService  string
	SrcImage    string
	DstService  string
	DstImage    string
	DstType     string
	Method      string
	Path        string
	RequestBody string
	Timestamp   time.Time
}

// HTTPEventInfo contains the relevant fields from an HTTP event for service mapping
type HTTPEventInfo struct {
	Direction  string // "send" or "recv"
	SourceIP   string
	SourcePort uint16
	DestIP     string
	DestPort   uint16
	PID        uint32
	Method     string
	URL        string
	StatusCode string
	Body       string
	SrcService string
	SrcImage   string
	DstService string
	DstImage   string
	DstType    string
}

// ConnectionEventInfo contains fields for non-HTTP connection events
type ConnectionEventInfo struct {
	Direction  string // "send" or "recv"
	SrcService string
	SrcImage   string
	DstService string
	DstImage   string
	DstType    string // "container" or "external"
	Protocol   string // e.g., "postgres", "mysql", "redis"
	Category   string // e.g., "database", "cache", "message_bus"
	Port       uint16 // Remote port
	Confidence int    // 0-100
	Reason     string // Detection reason
}

// ServiceMap tracks service profiles with debounced file writing
type ServiceMap struct {
	mu              sync.RWMutex
	services        map[string]*ServiceProfile // key: service name
	pendingRequests map[string]*PendingRequest // connection key -> pending request
	outputPath      string
	dirty           bool
	debounceTimer   *time.Timer
	debouncePeriod  time.Duration
}

// NewServiceMap creates a new service map with debounced file writing
func NewServiceMap(outputPath string, debouncePeriod time.Duration) *ServiceMap {
	return &ServiceMap{
		services:        make(map[string]*ServiceProfile),
		pendingRequests: make(map[string]*PendingRequest),
		outputPath:      outputPath,
		debouncePeriod:  debouncePeriod,
	}
}

// endpointKey generates a unique key for an endpoint within a service
func endpointKey(dst, method, path string) string {
	return fmt.Sprintf("%s|%s|%s", dst, method, path)
}

// connectionKey generates a key for request/response correlation
func connectionKey(pid uint32, srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	return fmt.Sprintf("%d|%s:%d|%s:%d", pid, srcIP, srcPort, dstIP, dstPort)
}

// connInfoKey generates a key for connection deduplication
func connInfoKey(dst, protocol string, port uint16) string {
	return fmt.Sprintf("%s|%s|%d", dst, protocol, port)
}

// extractJSONSchema extracts the structure of a JSON object (keys only, no values)
func extractJSONSchema(body string) interface{} {
	if body == "" {
		return nil
	}

	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return "non-json"
	}

	return extractSchema(data)
}

// extractSchema recursively extracts the schema structure from parsed JSON
func extractSchema(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			result[key] = extractSchema(val)
		}
		return result
	case []interface{}:
		if len(v) == 0 {
			return []interface{}{}
		}
		return []interface{}{extractSchema(v[0])}
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// schemasEqual compares two schema structures for equality
func schemasEqual(a, b interface{}) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}

// RecordHTTPEvent records an HTTP event and handles request/response correlation
// Records from both client and server perspectives
func (sm *ServiceMap) RecordHTTPEvent(event HTTPEventInfo) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Normalize service names
	srcService := event.SrcService
	dstService := event.DstService
	if srcService == "" {
		srcService = "unknown"
	}
	if dstService == "" {
		if event.DstType == "external" {
			dstService = "external"
		} else {
			dstService = "unknown"
		}
	}

	// Handle based on event type
	if event.Method != "" && event.StatusCode == "" {
		// This is a request (either send from client or recv by server)
		sm.handleRequest(event, srcService, dstService)
	} else if event.StatusCode != "" {
		// This is a response (either recv by client or send from server)
		sm.handleResponse(event, srcService, dstService)
	}
}

// RecordConnectionEvent records a non-HTTP connection event (database, cache, message bus)
func (sm *ServiceMap) RecordConnectionEvent(event ConnectionEventInfo) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Normalize service names
	srcService := event.SrcService
	dstService := event.DstService
	if srcService == "" {
		srcService = "unknown"
	}
	if dstService == "" {
		dstService = event.Protocol // use protocol as destination name (e.g., "postgres", "redis")
	}

	now := time.Now()

	// Get or create service profile
	profile := sm.getOrCreateProfile(srcService, event.SrcImage, now)
	profile.LastSeen = now

	// Find or create connection info
	var matchingConn *ConnectionInfo
	for _, conn := range profile.Connections {
		if conn.Destination == dstService && conn.Protocol == event.Protocol && conn.Port == event.Port {
			matchingConn = conn
			break
		}
	}

	if matchingConn != nil {
		// Update existing connection
		matchingConn.LastSeen = now
		matchingConn.Count++
		if event.Confidence > matchingConn.Confidence {
			matchingConn.Confidence = event.Confidence
			matchingConn.Reason = event.Reason
		}
	} else {
		// Create new connection entry
		newConn := &ConnectionInfo{
			Destination:     dstService,
			DestinationType: event.DstType,
			Protocol:        event.Protocol,
			Category:        event.Category,
			Port:            event.Port,
			Confidence:      event.Confidence,
			Reason:          event.Reason,
			FirstSeen:       now,
			LastSeen:        now,
			Count:           1,
		}
		profile.Connections = append(profile.Connections, newConn)
	}

	sm.dirty = true
	sm.scheduleDebouncedWrite()
}

// getOrCreateProfile gets or creates a service profile
func (sm *ServiceMap) getOrCreateProfile(name, image string, now time.Time) *ServiceProfile {
	profile, exists := sm.services[name]
	if !exists {
		profile = &ServiceProfile{
			Name:        name,
			Image:       image,
			Endpoints:   []*EndpointInfo{},
			Connections: []*ConnectionInfo{},
			FirstSeen:   now,
			LastSeen:    now,
		}
		sm.services[name] = profile
	}
	return profile
}

// handleRequest processes an outgoing HTTP request
func (sm *ServiceMap) handleRequest(event HTTPEventInfo, srcService, dstService string) {
	connKey := connectionKey(event.PID, event.SourceIP, event.SourcePort, event.DestIP, event.DestPort)

	sm.pendingRequests[connKey] = &PendingRequest{
		SrcService:  srcService,
		SrcImage:    event.SrcImage,
		DstService:  dstService,
		DstImage:    event.DstImage,
		DstType:     event.DstType,
		Method:      event.Method,
		Path:        event.URL,
		RequestBody: event.Body,
		Timestamp:   time.Now(),
	}

	sm.cleanupOldPendingRequests()
}

// handleResponse processes an HTTP response and correlates with request
func (sm *ServiceMap) handleResponse(event HTTPEventInfo, srcService, dstService string) {
	connKey := connectionKey(event.PID, event.SourceIP, event.SourcePort, event.DestIP, event.DestPort)

	pendingReq, found := sm.pendingRequests[connKey]
	if !found {
		return
	}

	delete(sm.pendingRequests, connKey)

	requestSchema := extractJSONSchema(pendingReq.RequestBody)
	responseSchema := extractJSONSchema(event.Body)

	sm.recordEndpoint(
		pendingReq.SrcService, pendingReq.SrcImage,
		pendingReq.DstService, pendingReq.DstType,
		pendingReq.Method, pendingReq.Path,
		requestSchema, responseSchema,
	)
}

// recordEndpoint records an HTTP endpoint call
func (sm *ServiceMap) recordEndpoint(
	srcService, srcImage, dstService, dstType,
	method, path string,
	requestSchema, responseSchema interface{},
) {
	now := time.Now()

	// Get or create service profile
	profile := sm.getOrCreateProfile(srcService, srcImage, now)
	profile.LastSeen = now

	// Find or create endpoint with matching schemas
	var matchingEndpoint *EndpointInfo
	for _, ep := range profile.Endpoints {
		if ep.Destination == dstService && ep.Method == method && ep.Path == path &&
			schemasEqual(ep.RequestSchema, requestSchema) &&
			schemasEqual(ep.ResponseSchema, responseSchema) {
			matchingEndpoint = ep
			break
		}
	}

	if matchingEndpoint != nil {
		matchingEndpoint.LastSeen = now
		matchingEndpoint.Count++
	} else {
		newEndpoint := &EndpointInfo{
			Destination:     dstService,
			DestinationType: dstType,
			Method:          method,
			Path:            path,
			RequestSchema:   requestSchema,
			ResponseSchema:  responseSchema,
			FirstSeen:       now,
			LastSeen:        now,
			Count:           1,
		}
		profile.Endpoints = append(profile.Endpoints, newEndpoint)
	}

	sm.dirty = true
	sm.scheduleDebouncedWrite()
}

// cleanupOldPendingRequests removes pending requests older than 30 seconds
func (sm *ServiceMap) cleanupOldPendingRequests() {
	cutoff := time.Now().Add(-30 * time.Second)
	for key, req := range sm.pendingRequests {
		if req.Timestamp.Before(cutoff) {
			delete(sm.pendingRequests, key)
		}
	}
}

// scheduleDebouncedWrite schedules a debounced write to disk
func (sm *ServiceMap) scheduleDebouncedWrite() {
	// Cancel existing timer if any
	if sm.debounceTimer != nil {
		sm.debounceTimer.Stop()
	}

	sm.debounceTimer = time.AfterFunc(sm.debouncePeriod, func() {
		sm.mu.Lock()
		if sm.dirty {
			sm.writeToFileLocked()
			sm.dirty = false
		}
		sm.mu.Unlock()
	})
}

// writeToFileLocked writes the service map to disk (must hold lock)
func (sm *ServiceMap) writeToFileLocked() error {
	services := make([]*ServiceProfile, 0, len(sm.services))
	for _, profile := range sm.services {
		services = append(services, profile)
	}

	output := struct {
		GeneratedAt time.Time         `yaml:"generated_at"`
		Services    []*ServiceProfile `yaml:"services"`
	}{
		GeneratedAt: time.Now(),
		Services:    services,
	}

	data, err := yaml.Marshal(output)
	if err != nil {
		return fmt.Errorf("marshal service map: %w", err)
	}

	tmpPath := sm.outputPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return fmt.Errorf("write temp service map: %w", err)
	}

	if err := os.Rename(tmpPath, sm.outputPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename service map: %w", err)
	}

	return nil
}

// Flush writes the current state to disk immediately
func (sm *ServiceMap) Flush() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.debounceTimer != nil {
		sm.debounceTimer.Stop()
		sm.debounceTimer = nil
	}

	if len(sm.services) == 0 {
		return nil
	}

	err := sm.writeToFileLocked()
	sm.dirty = false
	return err
}

// Close stops the service map and performs final flush
func (sm *ServiceMap) Close() error {
	return sm.Flush()
}
