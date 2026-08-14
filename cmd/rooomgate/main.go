package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/softrenzu/RooomGate/internal/server"
)

func main() {
	addr := os.Getenv("ROOOMGATE_ADDR")
	if addr == "" {
		addr = os.Getenv("ROOOMID_ADDR")
	}
	if addr == "" {
		addr = ":8080"
	}
	s := server.New()
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("RooomGate listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
