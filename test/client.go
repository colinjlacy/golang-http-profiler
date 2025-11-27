package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	fmt.Println("Test HTTP client starting...")
	fmt.Println("Waiting for server to be ready...")
	time.Sleep(1 * time.Second)

	// Make several HTTP requests
	requests := []string{
		"http://localhost:8080/",
		"http://localhost:8080/users",
		"http://localhost:8080/user/42",
		"http://localhost:8080/echo?message=hello",
		"http://localhost:8080/echo?message=world",
	}

	for i, url := range requests {
		fmt.Printf("\n[%d] Making request to: %s\n", i+1, url)

		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			fmt.Printf("Error reading body: %v\n", err)
			continue
		}

		fmt.Printf("Status: %d\n", resp.StatusCode)
		fmt.Printf("Body: %s\n", string(body))

		// Small delay between requests
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("\nClient completed all requests")
}
