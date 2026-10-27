package mcp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ServeHTTP answers one POST to the MCP endpoint (Streamable HTTP). The
// caller has checked the method, the Origin and the credentials, and set
// s.API to act with them. Every request is answered with one JSON object;
// no session is kept, so Mcp-Session-Id and Last-Event-ID are ignored.
//
// A request carrying the 2026-07-28 per-request _meta must mirror its
// version, method and tool name in the MCP-Protocol-Version, Mcp-Method and
// Mcp-Name headers (a mismatch is 400 HeaderMismatch, an unknown method
// 404). A request of the initialize era may send MCP-Protocol-Version; an
// unsupported value is 400, none means 2025-03-26.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMessage+1))
	if err != nil {
		writeRPC(w, 400, nil, &rpcError{Code: codeParse, Message: "could not read the request"})
		return
	}
	if len(body) > maxMessage {
		writeRPC(w, 413, nil, &rpcError{Code: codeInvalidRequest, Message: "message too large"})
		return
	}
	var msg struct {
		request
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		writeRPC(w, 400, nil, &rpcError{Code: codeParse, Message: "parse error: send one JSON-RPC message (batches are not supported)"})
		return
	}
	req := msg.request
	if req.Method == "" {
		if len(msg.Result) > 0 || len(msg.Error) > 0 {
			w.WriteHeader(http.StatusAccepted) // a response to nothing we asked: accepted and dropped
			return
		}
		writeRPC(w, 400, req.ID, &rpcError{Code: codeInvalidRequest, Message: "not a JSON-RPC request"})
		return
	}
	header := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	modern := requestVersion(req.Params)
	if modern != "" {
		if !modernVersions[modern] {
			writeRPC(w, 400, req.ID, unsupportedVersion(modern))
			return
		}
		if problem := mirrored(r, req, modern); problem != "" {
			writeRPC(w, 400, req.ID, &rpcError{Code: codeHeaderMismatch, Message: "Header mismatch: " + problem})
			return
		}
	} else if header != "" && !legacyVersions[header] {
		writeRPC(w, 400, req.ID, unsupportedVersion(header))
		return
	}
	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusAccepted) // a notification
		return
	}
	result, rerr := s.handle(r.Context(), req)
	status := 200
	if rerr != nil && modern != "" && rerr.Code == codeMethodNotFound {
		status = 404
	}
	writeRPC(w, status, req.ID, rerr, result)
}

// mirrored checks the headers that 2026-07-28 requests mirror from their
// body, and says what does not match.
func mirrored(r *http.Request, req request, version string) string {
	if v := r.Header.Get("MCP-Protocol-Version"); v != version {
		return "MCP-Protocol-Version " + strconv.Quote(v) + " does not match the request's protocol version " + strconv.Quote(version)
	}
	if v := r.Header.Get("Mcp-Method"); v != req.Method {
		return "Mcp-Method " + strconv.Quote(v) + " does not match the method " + strconv.Quote(req.Method)
	}
	switch req.Method {
	case "tools/call", "resources/read", "prompts/get":
		var p struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		}
		_ = json.Unmarshal(req.Params, &p)
		want := p.Name
		if req.Method == "resources/read" {
			want = p.URI
		}
		got, ok := headerValue(r.Header.Get("Mcp-Name"))
		if !ok || got != want {
			return "Mcp-Name does not match " + strconv.Quote(want)
		}
	}
	return ""
}

// headerValue decodes a mirrored header value, which may use the
// =?base64?...?= form.
func headerValue(v string) (string, bool) {
	if v == "" {
		return "", false
	}
	if strings.HasPrefix(v, "=?base64?") && strings.HasSuffix(v, "?=") && len(v) >= len("=?base64??=") {
		raw, err := base64.StdEncoding.DecodeString(v[len("=?base64?") : len(v)-2])
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
	for _, c := range v {
		if c < 0x20 && c != '\t' || c > 0x7e {
			return "", false
		}
	}
	return v, true
}

func writeRPC(w http.ResponseWriter, status int, id json.RawMessage, rerr *rpcError, result ...any) {
	resp := response{JSONRPC: "2.0", ID: id, Error: rerr}
	if len(id) == 0 {
		resp.ID = json.RawMessage("null")
	}
	if len(result) > 0 && rerr == nil {
		resp.Result = result[0]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
