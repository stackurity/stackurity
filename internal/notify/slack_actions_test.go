package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// A Slack channel without a signing secret gets exactly the 0.9 message:
// URL buttons, no values, no block ids. With one, Assign to me and Snooze 1
// week are interactive buttons whose value names the channel, the action
// and the fix; Open stays a URL button.
func TestSlackInteractiveButtons(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	r, incs, rows, infos := syntheticUrgent(2, 4, func(a int) string { return []string{"", "commmerceblog", "pos-api"}[a] })
	m, ok := d.urgentMessage(r, incs, rows, nil, infos, nil)
	if !ok {
		t.Fatal("no message")
	}
	if !reflect.DeepEqual(slackPayload(m), slackPayloadFor(m, 0)) {
		t.Fatal("a channel without a signing secret renders differently")
	}
	for _, b := range slackPayloadFor(m, 0)["blocks"].([]map[string]any) {
		if b["type"] != "actions" {
			continue
		}
		if _, ok := b["block_id"]; ok {
			t.Errorf("block id without a Slack app: %v", b)
		}
		for _, el := range b["elements"].([]map[string]any) {
			if el["url"] == nil || el["value"] != nil {
				t.Errorf("0.9 buttons are URL buttons without values: %v", el)
			}
			if el["text"].(map[string]any)["text"] == "Snooze 1 week" {
				t.Errorf("label changed without a Slack app: %v", el)
			}
		}
	}

	blocks := slackPayloadFor(m, 42)["blocks"].([]map[string]any)
	interactive, open, ids := 0, 0, map[string]bool{}
	for _, b := range blocks {
		if b["type"] != "actions" {
			continue
		}
		bid, _ := b["block_id"].(string)
		if !strings.HasPrefix(bid, "stk-") || ids[bid] {
			t.Errorf("block id %q", bid)
		}
		ids[bid] = true
		for _, el := range b["elements"].([]map[string]any) {
			ch, kind, fix, ok := ParseSlackActionValue(el["value"].(string))
			if !ok || ch != 42 || fix == "" || !strings.HasSuffix(el["action_id"].(string), "-"+kind) {
				t.Errorf("value %v", el)
			}
			label := el["text"].(map[string]any)["text"]
			switch kind {
			case "assign", "snooze":
				interactive++
				if el["url"] != nil {
					t.Errorf("interactive button with a URL: %v", el)
				}
				if kind == "snooze" && label != "Snooze 1 week" || kind == "assign" && label != "Assign to me" {
					t.Errorf("label %v", label)
				}
			case "open":
				open++
				if !strings.HasPrefix(el["url"].(string), "https://stk.example/fixes/") {
					t.Errorf("open %v", el)
				}
			}
		}
	}
	if interactive != 12 || open != 6 || len(blocks) > slackBlocksMax {
		t.Errorf("%d interactive and %d open buttons in %d blocks", interactive, open, len(blocks))
	}
}

func TestParseSlackActionValue(t *testing.T) {
	for _, v := range []string{"", "stk1|0|assign|x", "stk1|-3|assign|x", "stk2|1|assign|x", "stk1|1|delete|x", "stk1|1|assign|",
		"stk1|1|assign", "stk1|abc|assign|x", "stk1|1|assign|" + strings.Repeat("x", 2001)} {
		if _, _, _, ok := ParseSlackActionValue(v); ok {
			t.Errorf("%q accepted", v)
		}
	}
	ch, kind, fix, ok := ParseSlackActionValue(SlackActionValue(7, "snooze", "1:package_upgrade:0|odd"))
	if !ok || ch != 7 || kind != "snooze" || fix != "1:package_upgrade:0|odd" {
		t.Errorf("round trip: %d %s %s %v", ch, kind, fix, ok)
	}
}

type captureRT struct{ bodies []string }

func (c *captureRT) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.bodies = append(c.bodies, string(b))
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}, Request: r}, nil
}

// The dispatcher sends interactive buttons only when the channel's signing
// secret resolves; otherwise the message keeps the URL buttons.
func TestDispatcherInteractiveOnlyWithSigningSecret(t *testing.T) {
	t.Setenv("STACKURITY_SECRET_HOOK", "https://hooks.slack.com/services/T0/B0/xyz")
	t.Setenv("STACKURITY_SECRET_SIGNING", "8f742231b10e8888abcd99yyyzzz85a5")
	rt := &captureRT{}
	d := &Dispatcher{BaseURL: "https://stk.example", Sender: &Sender{HTTP: &http.Client{Transport: rt}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r, incs, rows, infos := syntheticUrgent(1, 1, func(int) string { return "host" })
	m, _ := d.urgentMessage(r, incs, rows, nil, infos, nil)
	for _, c := range []struct {
		cfg         string
		interactive bool
	}{
		{`{}`, false},
		{`{"signing_secret_ref":"env:STACKURITY_SECRET_SIGNING"}`, true},
		{`{"signing_secret_ref":"env:STACKURITY_SECRET_MISSING"}`, false},
	} {
		ch := &store.Channel{ID: 9, Kind: KindSlack, Name: "s", Config: json.RawMessage(c.cfg), SecretRef: "env:STACKURITY_SECRET_HOOK"}
		if err := d.send(context.Background(), ch, store.Delivery{ID: 1}, 1, m); err != nil {
			t.Fatal(err)
		}
		body := rt.bodies[len(rt.bodies)-1]
		if got := strings.Contains(body, `"value":"stk1|9|assign|`); got != c.interactive {
			t.Errorf("%s: interactive %v, want %v: %s", c.cfg, got, c.interactive, body)
		}
		if strings.Contains(body, "8f742231") {
			t.Error("the signing secret is in the message")
		}
	}
}
