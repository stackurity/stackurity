package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/feedback"
	"github.com/stackurity/stackurity/internal/tenant"
)

const intakeKey = "test-intake-key-0123456789abcdef0123456789"

// queueEnv is the Stackurity team's server with the queue on.
func queueEnv(t *testing.T, maxBytes int64) (*env, string) {
	dir := filepath.Join(t.TempDir(), "queue")
	disk, err := feedback.OpenDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if maxBytes == 0 {
		maxBytes = 1 << 30
	}
	e := newEnvWith(t, func(s *api.Server) {
		s.FeedbackQueue = &api.FeedbackQueue{Disk: disk, IntakeKey: intakeKey, StorageMax: maxBytes}
		s.BaseURL = "https://app.example.test"
	})
	return e, dir
}

// pngWithLocation is a small PNG carrying a text chunk with a location.
func pngWithLocation(t *testing.T) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	data := []byte("Comment\x00GPS 12.9716N 77.5946E")
	var c bytes.Buffer
	_ = binary.Write(&c, binary.BigEndian, uint32(len(data)))
	c.WriteString("tEXt")
	c.Write(data)
	_ = binary.Write(&c, binary.BigEndian, crc32.ChecksumIEEE(append([]byte("tEXt"), data...)))
	raw := b.Bytes()
	return append(append(append([]byte{}, raw[:33]...), c.Bytes()...), raw[33:]...)
}

type upload struct {
	name string
	data []byte
}

func intakeBody(t *testing.T, item map[string]any, files ...upload) (*bytes.Buffer, string) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="item"`)
	h.Set("Content-Type", "application/json")
	pw, _ := mw.CreatePart(h)
	_ = json.NewEncoder(pw).Encode(item)
	for _, f := range files {
		fw, _ := mw.CreateFormFile("attachment", f.name)
		fw.Write(f.data)
	}
	mw.Close()
	return &b, mw.FormDataContentType()
}

func postIntake(t *testing.T, e *env, key string, item map[string]any, files ...upload) (int, map[string]any) {
	body, ct := intakeBody(t, item, files...)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/feedback-queue/intake", body)
	req.Header.Set("Content-Type", ct)
	if key != "" {
		req.Header.Set("X-Stackurity-Feedback-Key", key)
	}
	req.Header.Set("X-Stackurity-Feedback-Client-IP", "203.0.113.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func validItem() map[string]any {
	return map[string]any{"kind": "issue", "description": "The export button does nothing", "email": "me@example.com",
		"page": "/assets/12", "browser": "Chrome 131 on macOS", "viewport": "1280x800", "version": "0.14.2",
		"edition": "community", "hosting": "self_hosted", "source": "app"}
}

// bearerJSON sends a request with a bearer token and decodes the answer.
func bearerJSON(t *testing.T, e *env, token, method, path string, in any, out any) int {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestFeedbackIntakeStoresCheckedAttachments(t *testing.T) {
	e, dir := queueEnv(t, 0)
	pdf := []byte("%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")

	// Without the relay's key nothing is accepted.
	if code, _ := postIntake(t, e, "", validItem()); code != 401 {
		t.Fatalf("no key: %d", code)
	}
	if code, _ := postIntake(t, e, intakeKey+"x", validItem()); code != 401 {
		t.Fatalf("wrong key: %d", code)
	}

	code, res := postIntake(t, e, intakeKey, validItem(), upload{"../../etc/screen shot.PNG", pngWithLocation(t)}, upload{"report.html", pdf})
	if code != 201 {
		t.Fatalf("intake: %d %v", code, res)
	}
	ref, _ := res["ref"].(string)
	token, _ := res["token"].(string)
	if !strings.HasPrefix(ref, "FB-") || !strings.HasPrefix(token, "fbs_") || res["source"] != "self_hosted" || res["attachments"] != float64(2) {
		t.Fatalf("reply: %v", res)
	}
	// Files are stored under random names, the image without its location.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("stored %d files", len(entries))
	}
	for _, en := range entries {
		if !feedback.ValidKey(en.Name()) {
			t.Errorf("file name %q", en.Name())
		}
		b, _ := os.ReadFile(filepath.Join(dir, en.Name()))
		if bytes.Contains(b, []byte("12.9716N")) {
			t.Errorf("location kept in %s", en.Name())
		}
	}

	// An operator sees the item with safe names and types from content.
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	var got struct {
		Item struct {
			Kind, Source, Browser, Viewport string
			ContactEmail                    string `json:"contact_email"`
		} `json:"item"`
		Attachments []struct {
			ID          int64  `json:"id"`
			Name        string `json:"name"`
			ContentType string `json:"content_type"`
		} `json:"attachments"`
	}
	if code := ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, &got); code != 200 {
		t.Fatalf("get: %d", code)
	}
	if len(got.Attachments) != 2 || got.Attachments[0].Name != "screen shot.png" || got.Attachments[0].ContentType != "image/png" ||
		got.Attachments[1].Name != "report.pdf" || got.Attachments[1].ContentType != "application/pdf" {
		t.Fatalf("attachments: %+v", got.Attachments)
	}

	// Refusals: content that is not an accepted type whatever its name,
	// too many files, a bad item.
	cases := []struct {
		name  string
		item  map[string]any
		files []upload
		want  int
	}{
		{"html named png", validItem(), []upload{{"x.png", []byte("<html><script>alert(1)</script></html>")}}, 415},
		{"svg", validItem(), []upload{{"x.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>`)}}, 415},
		{"exe named pdf", validItem(), []upload{{"x.pdf", append([]byte("MZ\x90\x00"), make([]byte, 100)...)}}, 415},
		{"broken png", validItem(), []upload{{"x.png", []byte("\x89PNG\r\n\x1a\n\x00\x00")}}, 415},
		{"four files", validItem(), []upload{{"a.pdf", pdf}, {"b.pdf", pdf}, {"c.pdf", pdf}, {"d.pdf", pdf}}, 400},
		{"pdf too large", validItem(), []upload{{"a.pdf", append([]byte("%PDF-1.4\n"), make([]byte, feedback.MaxPDFBytes)...)}}, 413},
		{"bad kind", map[string]any{"kind": "other", "description": "x", "source": "app"}, nil, 400},
		{"no description", map[string]any{"kind": "issue", "description": " ", "source": "app"}, nil, 400},
		{"bad source", map[string]any{"kind": "issue", "description": "x", "source": "admin"}, nil, 400},
	}
	for _, c := range cases {
		if code, res := postIntake(t, e, intakeKey, c.item, c.files...); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, res, c.want)
		}
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("refused uploads left %d files", len(entries)-2)
	}
}

func TestFeedbackIntakeStorageCap(t *testing.T) {
	e, dir := queueEnv(t, 100)
	pdf := append([]byte("%PDF-1.4\n"), bytes.Repeat([]byte("x"), 80)...)
	if code, res := postIntake(t, e, intakeKey, validItem(), upload{"a.pdf", pdf}); code != 201 {
		t.Fatalf("first: %d %v", code, res)
	}
	if code, res := postIntake(t, e, intakeKey, validItem(), upload{"b.pdf", pdf}); code != 507 {
		t.Fatalf("over the cap: %d %v", code, res)
	}
	// Text-only feedback still gets through.
	if code, res := postIntake(t, e, intakeKey, validItem()); code != 201 {
		t.Fatalf("no attachments: %d %v", code, res)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files kept", len(entries))
	}
}

func TestFeedbackQueueOnlyForOperators(t *testing.T) {
	e, _ := queueEnv(t, 0)
	_, res := postIntake(t, e, intakeKey, validItem(), upload{"a.pdf", []byte("%PDF-1.4 x")})
	ref := res["ref"].(string)
	ctx := context.Background()

	// Customer administrators, of the default workspace and of another
	// organisation, and their API tokens, never see the queue.
	e.user("admin@x.io", auth.RoleAdmin)
	if _, _, err := e.st.CreateWorkspace(ctx, "Beta Corp", "", "admin-beta@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	var adminTok map[string]any
	admin := e.login("admin@x.io")
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "admin"}, &adminTok); code != 201 {
		t.Fatalf("token: %d %v", code, adminTok)
	}
	paths := []struct{ method, path string }{
		{"GET", "/api/v1/admin/feedback"}, {"GET", "/api/v1/admin/feedback/" + ref},
		{"PATCH", "/api/v1/admin/feedback/" + ref}, {"POST", "/api/v1/admin/feedback/" + ref + "/attachments/1/link"},
		{"GET", "/api/v1/admin/feedback-tokens"}, {"POST", "/api/v1/admin/feedback-tokens"},
	}
	for _, who := range []*session{admin, e.login("admin-beta@x.io")} {
		for _, p := range paths {
			var out map[string]any
			if code := who.do(p.method, p.path, map[string]any{"status": "released", "name": "x"}, &out); code != 403 {
				t.Errorf("customer admin %s %s: %d %v", p.method, p.path, code, out)
			}
		}
	}
	for _, p := range paths {
		if code := bearerJSON(t, e, adminTok["secret"].(string), p.method, p.path, map[string]any{"status": "released"}, nil); code != 403 {
			t.Errorf("admin API token %s %s: %d", p.method, p.path, code)
		}
	}
	// Nothing changed.
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	var item struct {
		Item struct{ Status string } `json:"item"`
	}
	ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	if item.Item.Status != "new" {
		t.Fatalf("status changed to %q", item.Item.Status)
	}
	// The status lookup and intake are not reachable with a session either.
	if code := admin.do("POST", "/api/v1/feedback-queue/status", map[string]any{"items": []any{}}, nil); code != 401 {
		t.Errorf("status with a session: %d", code)
	}
}

func TestFeedbackTriageTokenScope(t *testing.T) {
	e, _ := queueEnv(t, 0)
	_, res := postIntake(t, e, intakeKey, validItem(), upload{"a.pdf", []byte("%PDF-1.4 x")})
	ref := res["ref"].(string)
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	var created struct {
		Token string `json:"token"`
		Info  struct {
			ID int64 `json:"id"`
		} `json:"info"`
	}
	if code := ops.do("POST", "/api/v1/admin/feedback-tokens", map[string]any{"name": "triage-agent", "days": 7}, &created); code != 201 {
		t.Fatalf("create: %d", code)
	}
	tok := created.Token
	if !strings.HasPrefix(tok, api.FeedbackTokenPrefix+"_") {
		t.Fatalf("token %q", tok)
	}

	// Reads items and attachments, writes status and notes.
	var list struct {
		Items []struct{ Ref string } `json:"items"`
	}
	if code := bearerJSON(t, e, tok, "GET", "/api/v1/admin/feedback?status=new", nil, &list); code != 200 || len(list.Items) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	var item struct {
		Attachments []struct{ ID int64 } `json:"attachments"`
	}
	if code := bearerJSON(t, e, tok, "GET", "/api/v1/admin/feedback/"+ref, nil, &item); code != 200 || len(item.Attachments) != 1 {
		t.Fatalf("get: %d", code)
	}
	var updated struct {
		Status      string
		TriageNotes string `json:"triage_notes"`
	}
	if code := bearerJSON(t, e, tok, "PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "triaged", "note": "safe to fix"}, &updated); code != 200 {
		t.Fatalf("patch: %d", code)
	}
	if !strings.Contains(updated.TriageNotes, "agent:triage-agent: safe to fix") {
		t.Fatalf("notes %q", updated.TriageNotes)
	}
	var link struct{ URL string }
	if code := bearerJSON(t, e, tok, "POST", fmt.Sprintf("/api/v1/admin/feedback/%s/attachments/%d/link", ref, item.Attachments[0].ID), nil, &link); code != 200 {
		t.Fatalf("link: %d", code)
	}

	// Nothing else: not the token routes, not any workspace route.
	for _, p := range []struct{ method, path string }{
		{"GET", "/api/v1/admin/feedback-tokens"}, {"POST", "/api/v1/admin/feedback-tokens"},
		{"DELETE", fmt.Sprintf("/api/v1/admin/feedback-tokens/%d", created.Info.ID)},
		{"GET", "/api/v1/auth/me"}, {"GET", "/api/v1/assets"}, {"GET", "/api/v1/admin/workspaces"},
		{"GET", "/api/v1/feedback/mine"}, {"POST", "/api/v1/feedback"}, {"GET", "/api/v1/admin/feedbackx"},
	} {
		if code := bearerJSON(t, e, tok, p.method, p.path, map[string]any{"name": "x"}, nil); code != 401 && code != 403 {
			t.Errorf("triage token %s %s: %d", p.method, p.path, code)
		}
	}
	// Bad values are refused.
	for _, body := range []map[string]any{
		{"status": "deleted"}, {"status": "wont_fix"}, {"link": "https://evil.example/pull/1"},
		{"link": "javascript:alert(1)"}, {"fixed_in": "../../"}, {"status": "duplicate"},
		{"duplicate_of": ref, "status": "duplicate"},
	} {
		if code := bearerJSON(t, e, tok, "PATCH", "/api/v1/admin/feedback/"+ref, body, nil); code != 400 {
			t.Errorf("patch %v: %d", body, code)
		}
	}
	// Revoked or expired, it stops working.
	if code := ops.do("DELETE", fmt.Sprintf("/api/v1/admin/feedback-tokens/%d", created.Info.ID), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code := bearerJSON(t, e, tok, "GET", "/api/v1/admin/feedback", nil, nil); code != 401 {
		t.Fatalf("revoked: %d", code)
	}
	ops.do("POST", "/api/v1/admin/feedback-tokens", map[string]any{"name": "old"}, &created)
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE feedback_agent_tokens SET expires_at = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if code := bearerJSON(t, e, created.Token, "GET", "/api/v1/admin/feedback", nil, nil); code != 401 {
		t.Fatalf("expired: %d", code)
	}
	// On a server without the queue, a triage token is refused.
	plain := newEnv(t)
	if code := bearerJSON(t, plain, tok, "GET", "/api/v1/admin/feedback", nil, nil); code != 401 {
		t.Fatalf("no queue: %d", code)
	}
}

func TestFeedbackAttachmentLinks(t *testing.T) {
	e, _ := queueEnv(t, 0)
	img := pngWithLocation(t)
	_, res := postIntake(t, e, intakeKey, validItem(), upload{"shot.png", img})
	ref := res["ref"].(string)
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	var item struct {
		Attachments []struct{ ID int64 } `json:"attachments"`
	}
	ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	aid := item.Attachments[0].ID
	var link struct {
		URL string `json:"url"`
	}
	if code := ops.do("POST", fmt.Sprintf("/api/v1/admin/feedback/%s/attachments/%d/link", ref, aid), nil, &link); code != 200 {
		t.Fatalf("link: %d", code)
	}
	// Another item's id with this attachment is refused.
	if code := ops.do("POST", fmt.Sprintf("/api/v1/admin/feedback/FB-999/attachments/%d/link", aid), nil, nil); code != 404 {
		t.Fatalf("wrong item: %d", code)
	}
	u, _ := url.Parse(link.URL)
	if u.Host != "app.example.test" {
		t.Fatalf("link %s", link.URL)
	}
	get := func(q string) *http.Response {
		resp, err := http.Get(e.srv.URL + u.Path + "?" + q)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := get(u.RawQuery)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" ||
		!strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("download: %d %v", resp.StatusCode, resp.Header)
	}
	if bytes.Contains(body, []byte("12.9716N")) || !bytes.HasPrefix(body, []byte("\x89PNG")) {
		t.Fatal("served file has metadata or is not the PNG")
	}
	q := u.Query()
	sig, exp := q.Get("sig"), q.Get("exp")
	for name, query := range map[string]string{
		"no signature":     "exp=" + exp,
		"bad signature":    "exp=" + exp + "&sig=" + strings.Repeat("0", len(sig)),
		"other expiry":     "exp=" + fmt.Sprint(time.Now().Add(5*time.Minute).Unix()) + "&sig=" + sig,
		"expired":          "exp=" + fmt.Sprint(time.Now().Add(-time.Minute).Unix()) + "&sig=" + sig,
		"far future":       "exp=" + fmt.Sprint(time.Now().Add(48*time.Hour).Unix()) + "&sig=" + sig,
		"other attachment": "",
	} {
		path := u.Path
		if name == "other attachment" {
			path = fmt.Sprintf("/feedback-attachments/%d", aid+1)
			query = u.RawQuery
		}
		resp, _ := http.Get(e.srv.URL + path + "?" + query)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
}

func TestFeedbackStatusByToken(t *testing.T) {
	e, _ := queueEnv(t, 0)
	_, res := postIntake(t, e, intakeKey, validItem())
	ref, token := res["ref"].(string), res["token"].(string)
	_, other := postIntake(t, e, intakeKey, validItem())
	status := func(items ...map[string]string) []map[string]any {
		b, _ := json.Marshal(map[string]any{"items": items})
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/feedback-queue/status", bytes.NewReader(b))
		req.Header.Set("X-Stackurity-Feedback-Key", intakeKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct{ Items []map[string]any }
		json.NewDecoder(resp.Body).Decode(&out)
		return out.Items
	}
	got := status(map[string]string{"ref": ref, "token": token}, map[string]string{"ref": ref, "token": other["token"].(string)},
		map[string]string{"ref": "FB-99999", "token": token})
	if len(got) != 3 || got[0]["status"] != "received" || got[1]["status"] != "unknown" || got[2]["status"] != "unknown" {
		t.Fatalf("status: %v", got)
	}
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	// Internal steps and notes are not shown to the sender.
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "needs_owner", "note": "pricing question", "resolution": "draft"}, nil)
	got = status(map[string]string{"ref": ref, "token": token})
	if got[0]["status"] != "reviewing" || got[0]["resolution"] != nil || strings.Contains(fmt.Sprint(got), "pricing") {
		t.Fatalf("internal state leaked: %v", got)
	}
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "wont_fix", "resolution": "We keep exports in the API."}, nil)
	got = status(map[string]string{"ref": ref, "token": token})
	if got[0]["status"] != "wont_fix" || got[0]["resolution"] != "We keep exports in the API." {
		t.Fatalf("closed: %v", got)
	}
}

// relay stands in for stackurity.dev/feedback: it hands what an
// installation sends to the queue with the key, as the website does.
func relay(t *testing.T, queue *env) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := queue.srv.URL + "/api/v1/feedback-queue/intake"
		body, ct := io.Reader(r.Body), r.Header.Get("Content-Type")
		switch {
		case r.URL.Path == "/feedback/status":
			target = queue.srv.URL + "/api/v1/feedback-queue/status"
		case strings.HasPrefix(ct, "application/json"):
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			in["description"] = in["message"]
			delete(in, "message")
			b, c := intakeBody(t, in)
			body, ct = b, c
		}
		req, _ := http.NewRequest("POST", target, body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("X-Stackurity-Feedback-Key", intakeKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMyFeedbackEndToEnd(t *testing.T) {
	queue, dir := queueEnv(t, 0)
	rl := relay(t, queue)
	inst := newEnv(t)
	inst.api.FeedbackURL = rl.URL + "/feedback"
	inst.user("viewer@x.io", auth.RoleViewer)
	inst.user("other@x.io", auth.RoleAdmin)
	s := inst.login("viewer@x.io")

	// With attachments: multipart, checked and stripped here first.
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for k, v := range map[string]string{"kind": "issue", "message": "Export button does nothing", "page": "/assets/9?q=secret", "viewport": "390x844"} {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("attachment", "shot.png")
	fw.Write(pngWithLocation(t))
	mw.Close()
	resp := s.req("POST", "/api/v1/feedback", &b, map[string]string{"Content-Type": mw.FormDataContentType(), "X-Stackurity-CSRF": "1",
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"})
	var sent map[string]any
	json.NewDecoder(resp.Body).Decode(&sent)
	resp.Body.Close()
	if resp.StatusCode != 202 || !strings.HasPrefix(fmt.Sprint(sent["ref"]), "FB-") {
		t.Fatalf("send: %d %v", resp.StatusCode, sent)
	}
	ref := sent["ref"].(string)
	// Without: JSON.
	if code := s.do("POST", "/api/v1/feedback", map[string]any{"kind": "feature", "message": "Dark mode"}, &sent); code != 202 {
		t.Fatalf("json send: %d %v", code, sent)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("%d files at the queue", len(entries))
	}
	queue.user("ops@x.io", auth.RoleAdmin)
	queue.instanceAdmin("ops@x.io")
	ops := queue.login("ops@x.io")
	var item struct {
		Item struct{ Page, Browser, Viewport, Source string } `json:"item"`
	}
	ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	if item.Item.Page != "/assets/9" || item.Item.Browser != "Chrome 131 on macOS" || item.Item.Viewport != "390x844" || item.Item.Source != "self_hosted" {
		t.Fatalf("captured: %+v", item.Item)
	}

	var mine struct {
		Items []struct {
			Ref, Status, Kind string
			StatusNote        string `json:"status_note"`
			FixedIn           string `json:"fixed_in"`
		} `json:"items"`
	}
	if code := s.do("GET", "/api/v1/feedback/mine", nil, &mine); code != 200 || len(mine.Items) != 2 || mine.Items[1].Ref != ref || mine.Items[1].Status != "received" {
		t.Fatalf("mine: %d %+v", code, mine)
	}
	// Another user of the same organisation does not see them.
	var theirs struct{ Items []any }
	inst.login("other@x.io").do("GET", "/api/v1/feedback/mine", nil, &theirs)
	if len(theirs.Items) != 0 {
		t.Fatalf("other user sees %v", theirs.Items)
	}
	// Released at the queue: the sender sees it (after the cache age).
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "released", "fixed_in": "0.15.0", "resolution": "Fixed the export button."}, nil)
	if _, err := inst.st.Pool.Exec(tenant.System(context.Background()), `UPDATE feedback_sent SET checked_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	s.do("GET", "/api/v1/feedback/mine", nil, &mine)
	if mine.Items[1].Status != "released" || mine.Items[1].FixedIn != "0.15.0" || mine.Items[1].StatusNote != "Fixed the export button." {
		t.Fatalf("after release: %+v", mine.Items[1])
	}

	// A refused attachment: the user is told why, nothing is sent.
	b.Reset()
	mw = multipart.NewWriter(&b)
	mw.WriteField("kind", "issue")
	mw.WriteField("message", "x")
	fw, _ = mw.CreateFormFile("attachment", "x.png")
	fw.Write([]byte("<script>alert(1)</script>"))
	mw.Close()
	resp = s.req("POST", "/api/v1/feedback", &b, map[string]string{"Content-Type": mw.FormDataContentType(), "X-Stackurity-CSRF": "1"})
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("bad attachment: %d", resp.StatusCode)
	}
}

func TestFeedbackRetention(t *testing.T) {
	e, dir := queueEnv(t, 0)
	_, res := postIntake(t, e, intakeKey, validItem(), upload{"a.pdf", []byte("%PDF-1.4 a")})
	ref := res["ref"].(string)
	_, res2 := postIntake(t, e, intakeKey, validItem(), upload{"b.pdf", []byte("%PDF-1.4 b")})
	ref2 := res2["ref"].(string)
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "released"}, nil)
	ctx := tenant.System(context.Background())
	if _, err := e.st.Pool.Exec(ctx, `UPDATE feedback_items SET closed_at = now() - interval '200 days' WHERE status = 'released'`); err != nil {
		t.Fatal(err)
	}
	remove := e.api.FeedbackQueue.Disk.Remove
	files, items, err := e.st.PurgeFeedback(context.Background(), 180*24*time.Hour, 730*24*time.Hour, remove)
	if err != nil || files != 1 || items != 0 {
		t.Fatalf("purge: %d %d %v", files, items, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files left", len(entries))
	}
	var linkCode int
	var item struct {
		Attachments []struct {
			ID       int64
			PurgedAt *time.Time `json:"purged_at"`
		} `json:"attachments"`
	}
	ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	linkCode = ops.do("POST", fmt.Sprintf("/api/v1/admin/feedback/%s/attachments/%d/link", ref, item.Attachments[0].ID), nil, nil)
	if item.Attachments[0].PurgedAt == nil || linkCode != 410 {
		t.Fatalf("purged attachment: %+v %d", item.Attachments, linkCode)
	}
	// Records go two years after closing (or sending, if never closed).
	if _, err := e.st.Pool.Exec(ctx, `UPDATE feedback_items SET closed_at = now() - interval '800 days' WHERE status = 'released';
		UPDATE feedback_items SET created_at = now() - interval '800 days' WHERE status = 'new'`); err != nil {
		t.Fatal(err)
	}
	files, items, err = e.st.PurgeFeedback(context.Background(), 180*24*time.Hour, 730*24*time.Hour, remove)
	if err != nil || files != 1 || items != 2 {
		t.Fatalf("second purge: %d %d %v", files, items, err)
	}
	if code := ops.do("GET", "/api/v1/admin/feedback/"+ref2, nil, nil); code != 404 {
		t.Fatalf("old item still there: %d", code)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("%d files left", len(entries))
	}
}

func TestFeedbackDeleteAndForgedLinks(t *testing.T) {
	e, dir := queueEnv(t, 0)
	e.api.FeedbackQueue.LinkKey = "a-separate-link-key-0123456789abcdef0123"
	_, res := postIntake(t, e, intakeKey, validItem(), upload{"a.pdf", []byte("%PDF-1.4 spam")})
	ref := res["ref"].(string)
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	var item struct {
		Attachments []struct{ ID int64 } `json:"attachments"`
	}
	ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	aid := item.Attachments[0].ID

	// Whoever holds the intake key (the relay) cannot sign a link.
	exp := time.Now().Add(5 * time.Minute).Unix()
	k := sha256.Sum256([]byte("stackurity feedback attachment link\x00" + intakeKey))
	for _, msg := range []string{fmt.Sprintf("%d:%d", aid, exp), fmt.Sprintf("1:%d:%d", aid, exp)} {
		m := hmac.New(sha256.New, k[:])
		m.Write([]byte(msg))
		resp, err := http.Get(fmt.Sprintf("%s/feedback-attachments/%d?exp=%d&sig=%s", e.srv.URL, aid, exp, hex.EncodeToString(m.Sum(nil))))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("link signed with the intake key: %d", resp.StatusCode)
		}
	}

	// The triage token cannot delete; an instance admin can.
	var created struct{ Token string }
	ops.do("POST", "/api/v1/admin/feedback-tokens", map[string]any{"name": "agent"}, &created)
	if code := bearerJSON(t, e, created.Token, "DELETE", "/api/v1/admin/feedback/"+ref, nil, nil); code != 403 {
		t.Fatalf("triage token delete: %d", code)
	}
	if code := ops.do("DELETE", "/api/v1/admin/feedback/"+ref, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, nil); code != 404 {
		t.Fatalf("after delete: %d", code)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("%d files left", len(entries))
	}

	// A file with no row (a crash before the item was stored) is listed
	// for the sweep once it is old enough, and kept while it may be in flight.
	key, _, err := e.api.FeedbackQueue.Disk.Write(strings.NewReader("%PDF-1.4 orphan"), feedback.PDF, 100)
	if err != nil {
		t.Fatal(err)
	}
	if keys, _ := e.api.FeedbackQueue.Disk.Keys(time.Now().Add(-time.Hour)); len(keys) != 0 {
		t.Fatalf("new file listed as old: %v", keys)
	}
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(filepath.Join(dir, key), old, old)
	keys, _ := e.api.FeedbackQueue.Disk.Keys(time.Now().Add(-time.Hour))
	known, err := e.st.FeedbackStorageKeys(context.Background())
	if err != nil || len(keys) != 1 || known[keys[0]] {
		t.Fatalf("orphan: %v %v %v", keys, known, err)
	}
}
