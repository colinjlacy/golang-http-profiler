package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

type echoBody struct {
	Message string `json:"message"`
}

func main() {
	// HTTP settings
	host := envOrDefault("TARGET_HOST", "127.0.0.1")
	port := envAsInt("HTTP_PORT", 8080)
	total := envAsInt("TOTAL_REQUESTS", 50)
	delayMs := envAsInt("REQUEST_DELAY_MS", 500)

	// PostgreSQL settings
	pgHost := envOrDefault("POSTGRES_HOST", "")
	pgPort := envAsInt("POSTGRES_PORT", 5432)
	pgUser := envOrDefault("POSTGRES_USER", "testuser")
	pgPass := envOrDefault("POSTGRES_PASSWORD", "testpass")
	pgDB := envOrDefault("POSTGRES_DB", "testdb")

	// Redis settings
	redisHost := envOrDefault("REDIS_HOST", "")
	redisPort := envAsInt("REDIS_PORT", 6379)

	client := &http.Client{Timeout: 5 * time.Second}
	base := fmt.Sprintf("http://%s:%d", host, port)

	// Initialize PostgreSQL connection if configured
	var db *sql.DB
	if pgHost != "" {
		connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			pgHost, pgPort, pgUser, pgPass, pgDB)
		var err error
		db, err = sql.Open("postgres", connStr)
		if err != nil {
			log.Printf("Warning: failed to open PostgreSQL connection: %v", err)
		} else {
			// Test connection
			if err := db.Ping(); err != nil {
				log.Printf("Warning: failed to ping PostgreSQL: %v", err)
				db = nil
			} else {
				log.Printf("Connected to PostgreSQL at %s:%d", pgHost, pgPort)
				defer db.Close()

				// Create a simple test table
				_, err := db.Exec(`CREATE TABLE IF NOT EXISTS test_data (
					id SERIAL PRIMARY KEY,
					name VARCHAR(100),
					created_at TIMESTAMP DEFAULT NOW()
				)`)
				if err != nil {
					log.Printf("Warning: failed to create table: %v", err)
				}
			}
		}
	}

	// Initialize Redis connection if configured
	var rdb *redis.Client
	ctx := context.Background()
	if redisHost != "" {
		rdb = redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:%d", redisHost, redisPort),
		})
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("Warning: failed to ping Redis: %v", err)
			rdb = nil
		} else {
			log.Printf("Connected to Redis at %s:%d", redisHost, redisPort)
			defer rdb.Close()
		}
	}

	log.Printf("Traffic generator hitting %s for %d requests", base, total)

	for i := 0; i < total; i++ {
		// HTTP calls
		call(client, "GET", base+"/", nil)
		call(client, "GET", base+"/healthz", nil)

		body := echoBody{Message: fmt.Sprintf("hello-%d", i)}
		payload, _ := json.Marshal(body)
		call(client, "POST", base+"/echo", bytes.NewReader(payload))
		call(client, "GET", base+"/slow", nil)

		// PostgreSQL calls
		if db != nil {
			// Insert a record
			name := fmt.Sprintf("item-%d", i)
			_, err := db.Exec("INSERT INTO test_data (name) VALUES ($1)", name)
			if err != nil {
				log.Printf("PostgreSQL INSERT error: %v", err)
			} else {
				log.Printf("PostgreSQL INSERT -> %s", name)
			}

			// Query records
			var count int
			err = db.QueryRow("SELECT COUNT(*) FROM test_data").Scan(&count)
			if err != nil {
				log.Printf("PostgreSQL SELECT error: %v", err)
			} else {
				log.Printf("PostgreSQL SELECT COUNT -> %d", count)
			}
		}

		// Redis calls
		if rdb != nil {
			// Set a key
			key := fmt.Sprintf("key:%d", i)
			value := fmt.Sprintf("value-%d", i)
			err := rdb.Set(ctx, key, value, 5*time.Minute).Err()
			if err != nil {
				log.Printf("Redis SET error: %v", err)
			} else {
				log.Printf("Redis SET %s -> %s", key, value)
			}

			// Get the key back
			result, err := rdb.Get(ctx, key).Result()
			if err != nil {
				log.Printf("Redis GET error: %v", err)
			} else {
				log.Printf("Redis GET %s -> %s", key, result)
			}

			// Increment a counter
			counter, err := rdb.Incr(ctx, "request_counter").Result()
			if err != nil {
				log.Printf("Redis INCR error: %v", err)
			} else {
				log.Printf("Redis INCR request_counter -> %d", counter)
			}
		}

		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	log.Printf("Traffic generation complete")
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
