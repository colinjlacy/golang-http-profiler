package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
)

type health struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

type echoBody struct {
	Message string `json:"message"`
}

// RequestInfo is published to NATS for each incoming request
type RequestInfo struct {
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	RemoteAddr string    `json:"remote_addr"`
	Timestamp  time.Time `json:"timestamp"`
}

var nc *nats.Conn

func main() {
	port := envAsInt("HTTP_PORT", 8080)
	addr := fmt.Sprintf(":%d", port)

	// Connect to NATS if URL is provided
	natsURL := os.Getenv("NATS_URL")
	if natsURL != "" {
		var err error
		nc, err = nats.Connect(natsURL)
		if err != nil {
			log.Printf("Warning: failed to connect to NATS at %s: %v", natsURL, err)
		} else {
			log.Printf("Connected to NATS at %s", natsURL)
			defer nc.Close()
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", withNATSPublish(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok %s\n", time.Now().Format(time.RFC3339Nano))
	}))

	mux.HandleFunc("/healthz", withNATSPublish(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := health{Status: "ok", Time: time.Now().Format(time.RFC3339Nano)}
		_ = json.NewEncoder(w).Encode(resp)
	}))

	mux.HandleFunc("/echo", withNATSPublish(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body echoBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))

	mux.HandleFunc("/slow", withNATSPublish(func(w http.ResponseWriter, r *http.Request) {
		delay := envAsInt("SLOW_DELAY_MS", 400)
		time.Sleep(time.Duration(delay) * time.Millisecond)
		fmt.Fprintf(w, "delayed %dms\n", delay)
	}))

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Printf("HTTP server listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// withNATSPublish wraps a handler to publish request info to NATS
func withNATSPublish(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Publish to NATS if connected
		if nc != nil && nc.IsConnected() {
			info := RequestInfo{
				Method:     r.Method,
				Path:       r.URL.Path,
				RemoteAddr: r.RemoteAddr,
				Timestamp:  time.Now(),
			}
			data, err := json.Marshal(info)
			if err == nil {
				if err := nc.Publish("requests.received", data); err != nil {
					log.Printf("Failed to publish to NATS: %v", err)
				}
			}
		}
		next(w, r)
	}
}

func envAsInt(key string, def int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return def
}
