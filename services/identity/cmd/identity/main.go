package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"identity/core/internal/core"
)

func main() {
	port := os.Getenv("PORT"); if port == "" { port = "8091" }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(map[string]string{"status":"ok", "service":"identity-core"}) })
	mux.HandleFunc("POST /v1/risk/evaluate", func(w http.ResponseWriter, r *http.Request) { var input core.LoginContext; if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil { http.Error(w, "invalid request", http.StatusUnprocessableEntity); return }; _ = json.NewEncoder(w).Encode(core.EvaluateRisk(input)) })
	server := &http.Server{Addr: ":"+port, Handler: mux, ReadHeaderTimeout: 3*time.Second, ReadTimeout: 5*time.Second, WriteTimeout: 5*time.Second, IdleTimeout: 30*time.Second}
	log.Printf("identity core listening on %s", port)
	log.Fatal(server.ListenAndServe())
}
