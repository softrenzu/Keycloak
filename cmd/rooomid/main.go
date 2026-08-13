package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/softrenzu/RooomGate/internal/server"
)

func env(primary, legacy, fallback string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	if v := os.Getenv(legacy); v != "" {
		return v
	}
	return fallback
}

func main() {
	addr := env("ROOOMGATE_ADDR", "ROOOMID_ADDR", ":8080")
	s := server.New()
	srv := &http.Server{
		Addr: addr,
		Handler: s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	log.Printf("RooomGate listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
