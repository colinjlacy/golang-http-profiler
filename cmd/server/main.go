package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type health struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

type echoBody struct {
	Message string `json:"message"`
}

func main() {
	port := envAsInt("HTTP_PORT", 8080)
	addr := fmt.Sprintf(":%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok %s\n", time.Now().Format(time.RFC3339Nano))
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := health{Status: "ok", Time: time.Now().Format(time.RFC3339Nano)}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body echoBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})

	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		delay := envAsInt("SLOW_DELAY_MS", 400)
		time.Sleep(time.Duration(delay) * time.Millisecond)
		fmt.Fprintf(w, "delayed %dms\n", delay)
	})

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

func envAsInt(key string, def int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return def
}
