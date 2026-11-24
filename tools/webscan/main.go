// Command webscan is a local prototype of the website check: a page where
// a visitor enters a site's address and gets a report.
//
//	go run ./tools/webscan                     # serves http://127.0.0.1:8099
//	go run ./tools/webscan -url example.com    # prints the report as JSON
//	go run ./tools/webscan -url example.com -owner
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/webscan"
)

//go:embed index.html
var indexHTML []byte

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "address to serve the page on")
	target := flag.String("url", "", "scan this site, print the report as JSON and exit")
	owner := flag.Bool("owner", false, "also check for files that should never be public (only for your own site)")
	flag.Parse()

	if *target != "" {
		rep, err := webscan.Scan(context.Background(), *target, webscan.Options{Owner: *owner,
			Progress: func(s string) { fmt.Fprintln(os.Stderr, "·", s) }})
		if err != nil {
			log.Fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}

	// One scan at a time per visitor address, and a few at once overall.
	var mu sync.Mutex
	running := map[string]bool{}
	slots := make(chan struct{}, 3)

	http.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	http.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			URL   string `json:"url"`
			Owner bool   `json:"owner"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if _, err := webscan.Normalize(in.URL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		mu.Lock()
		if running[r.RemoteAddr] {
			mu.Unlock()
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "a scan is already running"})
			return
		}
		running[r.RemoteAddr] = true
		mu.Unlock()
		defer func() { mu.Lock(); delete(running, r.RemoteAddr); mu.Unlock() }()
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-time.After(30 * time.Second):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy, try again in a minute"})
			return
		}

		// The answer is a stream of JSON lines: progress, then the report.
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-store")
		fl, _ := w.(http.Flusher)
		var wmu sync.Mutex
		send := func(v any) {
			wmu.Lock()
			defer wmu.Unlock()
			b, _ := json.Marshal(v)
			_, _ = w.Write(append(b, '\n'))
			if fl != nil {
				fl.Flush()
			}
		}
		rep, err := webscan.Scan(r.Context(), in.URL, webscan.Options{Owner: in.Owner,
			Progress: func(s string) { send(map[string]string{"type": "progress", "message": s}) }})
		if err != nil {
			send(map[string]string{"type": "error", "message": err.Error()})
			return
		}
		log.Printf("scanned %s: grade %s, %d findings, %d requests, %.1fs", rep.Site, rep.Grade, len(rep.Findings), rep.Requests, rep.Seconds)
		send(map[string]any{"type": "report", "report": rep})
	})
	log.Printf("website check prototype on http://%s", *addr)
	srv := &http.Server{Addr: *addr, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
