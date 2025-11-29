package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type echoBody struct {
	Message string `json:"message"`
}

func main() {
	host := envOrDefault("TARGET_HOST", "127.0.0.1")
	port := envAsInt("HTTP_PORT", 8080)
	total := envAsInt("TOTAL_REQUESTS", 50)
	delayMs := envAsInt("REQUEST_DELAY_MS", 500)

	client := &http.Client{Timeout: 5 * time.Second}
	base := fmt.Sprintf("http://%s:%d", host, port)

	log.Printf("Traffic generator hitting %s for %d requests", base, total)

	for i := 0; i < total; i++ {
		call(client, "GET", base+"/", nil)
		call(client, "GET", base+"/healthz", nil)

		body := echoBody{Message: fmt.Sprintf("hello-%d", i)}
		payload, _ := json.Marshal(body)
		call(client, "POST", base+"/echo", bytes.NewReader(payload))
		call(client, "GET", base+"/slow", nil)

		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
}

func call(client *http.Client, method, url string, body *bytes.Reader) {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader([]byte{})
	} else {
		reader = body
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		log.Printf("new request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("request error: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("%s %s -> %d", method, url, resp.StatusCode)
}

func envAsInt(key string, def int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return def
}

func envOrDefault(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
