// Package asktest is a fake Claude Messages API for tests: an HTTP server
// that answers POST /v1/messages with a scripted stream, records every
// request, and never reaches the network. CI uses it for every assistant
// test; nothing in it talks to Anthropic.
package asktest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Tool is a tool call in a scripted reply.
type Tool struct {
	ID, Name string
	// Input is the tool input as JSON ("{}" when empty).
	Input string
}

// Usage is a reply's tokens.
type Usage struct{ Input, CacheWrite, CacheRead, Output int64 }

// Reply is one scripted answer.
type Reply struct {
	// Thinking adds a thinking block (empty text, with a signature) first,
	// as current models send.
	Thinking bool
	Text     string
	Tools    []Tool
	// Stop is the stop reason (default: tool_use with tools, else end_turn).
	Stop string
	// Refusal declines before any output, with this category.
	Refusal string
	// FallbackTo: the model writes Partial, is refused (cyber), and this
	// model takes over and writes Text.
	FallbackTo string
	Partial    string
	Usage      Usage
	// Status answers with this HTTP error instead.
	Status int
}

// Request is one request the server received.
type Request struct {
	Header http.Header
	Body   []byte
}

// Server is the fake API.
type Server struct {
	URL     string
	Model   string
	mu      sync.Mutex
	replies []Reply
	reqs    []Request
}

// New starts a fake API that answers with replies in order; it fails the
// test if more requests come than replies.
func New(t testing.TB, replies ...Reply) *Server {
	t.Helper()
	s := &Server{Model: "claude-sonnet-5-5", replies: replies}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, Request{Header: r.Header.Clone(), Body: body})
		var rep *Reply
		if len(s.replies) > 0 {
			rep = &s.replies[0]
			s.replies = s.replies[1:]
		}
		s.mu.Unlock()
		if r.URL.Path != "/v1/messages" || r.Method != http.MethodPost {
			http.Error(w, `{"type":"error","error":{"type":"not_found_error","message":"no such path"}}`, 404)
			return
		}
		if rep == nil {
			t.Errorf("asktest: unexpected request %d", len(s.reqs))
			http.Error(w, `{"type":"error","error":{"type":"api_error","message":"no scripted reply"}}`, 500)
			return
		}
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		model := req.Model
		if model == "" {
			model = s.Model
		}
		if rep.Status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("request-id", "req_err")
			w.WriteHeader(rep.Status)
			fmt.Fprintf(w, `{"type":"error","error":{"type":"overloaded_error","message":"scripted %d"}}`, rep.Status)
			return
		}
		write(w, model, len(s.reqs), *rep)
	}))
	t.Cleanup(hs.Close)
	s.URL = hs.URL
	return s
}

// Push adds replies.
func (s *Server) Push(r ...Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies = append(s.replies, r...)
}

// Requests returns the requests so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Bodies returns the decoded request bodies so far.
func (s *Server) Bodies() []map[string]any {
	var out []map[string]any
	for _, r := range s.Requests() {
		var m map[string]any
		_ = json.Unmarshal(r.Body, &m)
		out = append(out, m)
	}
	return out
}

func write(w http.ResponseWriter, model string, n int, r Reply) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("request-id", fmt.Sprintf("req_test_%d", n))
	ev := func(typ string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b)
	}
	usage := map[string]any{"input_tokens": r.Usage.Input, "cache_creation_input_tokens": r.Usage.CacheWrite,
		"cache_read_input_tokens": r.Usage.CacheRead, "output_tokens": 1}
	ev("message_start", map[string]any{"type": "message_start", "message": map[string]any{
		"id": fmt.Sprintf("msg_test_%d", n), "type": "message", "role": "assistant", "model": model,
		"content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": usage}})
	idx := 0
	block := func(start map[string]any, deltas ...map[string]any) {
		ev("content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": start})
		for _, d := range deltas {
			ev("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": d})
		}
		ev("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx})
		idx++
	}
	text := func(s string) {
		var deltas []map[string]any
		for _, part := range splitText(s) {
			deltas = append(deltas, map[string]any{"type": "text_delta", "text": part})
		}
		block(map[string]any{"type": "text", "text": ""}, deltas...)
	}
	stop := r.Stop
	var stopDetails any
	iterations := []any{}
	if r.Refusal != "" {
		stop = "refusal"
		stopDetails = map[string]any{"type": "refusal", "category": r.Refusal, "explanation": "scripted refusal"}
	} else {
		if r.Thinking {
			block(map[string]any{"type": "thinking", "thinking": "", "signature": ""},
				map[string]any{"type": "signature_delta", "signature": fmt.Sprintf("sig-%d-AbC+/=", n)})
		}
		if r.FallbackTo != "" {
			text(r.Partial)
			block(map[string]any{"type": "fallback", "from": map[string]any{"model": model}, "to": map[string]any{"model": r.FallbackTo},
				"trigger": map[string]any{"type": "refusal", "category": "cyber"}})
			iterations = append(iterations,
				map[string]any{"type": "message", "model": model, "input_tokens": r.Usage.Input, "cache_creation_input_tokens": r.Usage.CacheWrite,
					"cache_read_input_tokens": r.Usage.CacheRead, "output_tokens": 10, "cache_creation": map[string]any{}},
				map[string]any{"type": "fallback_message", "model": r.FallbackTo, "input_tokens": r.Usage.Input, "cache_creation_input_tokens": r.Usage.CacheWrite,
					"cache_read_input_tokens": r.Usage.CacheRead, "output_tokens": r.Usage.Output, "cache_creation": map[string]any{}})
		}
		if r.Text != "" {
			text(r.Text)
		}
		for _, t := range r.Tools {
			in := t.Input
			if in == "" {
				in = "{}"
			}
			half := len(in) / 2
			block(map[string]any{"type": "tool_use", "id": t.ID, "name": t.Name, "input": map[string]any{}},
				map[string]any{"type": "input_json_delta", "partial_json": in[:half]},
				map[string]any{"type": "input_json_delta", "partial_json": in[half:]})
		}
		if stop == "" {
			stop = "end_turn"
			if len(r.Tools) > 0 {
				stop = "tool_use"
			}
		}
	}
	du := map[string]any{"output_tokens": r.Usage.Output, "input_tokens": r.Usage.Input,
		"cache_creation_input_tokens": r.Usage.CacheWrite, "cache_read_input_tokens": r.Usage.CacheRead}
	if len(iterations) > 0 {
		du["iterations"] = iterations
	}
	ev("message_delta", map[string]any{"type": "message_delta",
		"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil, "stop_details": stopDetails}, "usage": du})
	ev("message_stop", map[string]any{"type": "message_stop"})
}

// splitText sends text in a few pieces, as the API does.
func splitText(s string) []string {
	if len(s) < 8 {
		return []string{s}
	}
	words := strings.SplitAfter(s, " ")
	var out []string
	for i := 0; i < len(words); i += 3 {
		out = append(out, strings.Join(words[i:min(i+3, len(words))], ""))
	}
	return out
}
