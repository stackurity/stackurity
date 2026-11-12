// Command fakeclaude is a fake Claude Messages API for browser tests of Ask
// Stackurity (tests/ui/ask.mjs in CI). It answers POST /v1/messages with a
// scripted stream and never reaches the network. It is not part of the
// server and is never shipped.
//
//	fakeclaude -listen 127.0.0.1:18196
//
// A question containing "slow" gets a long answer streamed slowly (to test
// Stop and navigating while an answer streams); "tools" first calls the
// read-only list_assets tool; "linkfix:GROUP_ID linkissue:N" gets an answer
// that links that fix group and issue, a dashboard page and a page Ask may
// not link to; anything else gets a short markdown answer with a link to a
// Stackurity page.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var (
	linkFix   = regexp.MustCompile(`linkfix:([A-Za-z0-9:_.-]+)`)
	linkIssue = regexp.MustCompile(`linkissue:(\d+)`)
)

const answer = "**Short answer:** upgrade `openssl` on [the asset](/assets/1).\n\n- Check [the issue](/findings/1)\n- Then run the scan again\n"

func main() {
	listen := flag.String("listen", "127.0.0.1:18196", "address to listen on")
	flag.Parse()
	var n atomic.Int64
	http.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"type":"error","error":{"type":"not_found_error","message":"no such path"}}`, 404)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		var req struct {
			Model    string            `json:"model"`
			Messages []json.RawMessage `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		last := ""
		if len(req.Messages) > 0 {
			last = string(req.Messages[len(req.Messages)-1])
		}
		id := n.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("request-id", fmt.Sprintf("req_fake_%d", id))
		fl, _ := w.(http.Flusher)
		ev := func(typ string, v any) bool {
			b, _ := json.Marshal(v)
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b); err != nil {
				return false
			}
			if fl != nil {
				fl.Flush()
			}
			return r.Context().Err() == nil
		}
		usage := map[string]any{"input_tokens": 1200, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 1}
		ev("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": fmt.Sprintf("msg_fake_%d", id), "type": "message",
			"role": "assistant", "model": req.Model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": usage}})
		stop := "end_turn"
		if strings.Contains(last, "tools") && !strings.Contains(last, "tool_result") {
			ev("content_block_start", map[string]any{"type": "content_block_start", "index": 0,
				"content_block": map[string]any{"type": "tool_use", "id": "toolu_fake", "name": "list_assets", "input": map[string]any{}}})
			ev("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": "{}"}})
			ev("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
			stop = "tool_use"
		} else {
			text, pause := answer, 10*time.Millisecond
			if f, i := linkFix.FindStringSubmatch(last), linkIssue.FindStringSubmatch(last); f != nil && i != nil {
				text = fmt.Sprintf("**Links answer:** apply [the fix](/fixes/%s) for [the issue](/findings/%s). See the [audit log](/audit), not [tokens](/settings/tokens).\n", f[1], i[1])
			}
			if strings.Contains(last, "slow") {
				words := make([]string, 300)
				for i := range words {
					words[i] = fmt.Sprintf("Word%d", i)
				}
				text, pause = strings.Join(words, " ")+".", 30*time.Millisecond
			}
			ev("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
			for i := 0; i < len(text); i += 12 {
				if !ev("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0,
					"delta": map[string]any{"type": "text_delta", "text": text[i:min(i+12, len(text))]}}) {
					return
				}
				time.Sleep(pause)
			}
			ev("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
		}
		ev("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
			"usage": map[string]any{"output_tokens": 300, "input_tokens": 1200, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}})
		ev("message_stop", map[string]any{"type": "message_stop"})
	})
	log.Printf("fakeclaude listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
