package store_test

import (
	"errors"
	"testing"
)

// A channel says separately whether anything through it worked (a test
// counts: last_ok_at), whether a real message was ever delivered
// (last_delivery_at, from the delivery log only), and where its secret
// reference points (secret_source), so "last success 2 hours ago" with an
// empty delivery log, or a secret the stored credentials do not list, can be
// told apart on the integration's page.
func TestChannelDeliveryAndSecretStatus(t *testing.T) {
	ctx, s := loopStore(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	hook := []byte(`{"url":"https://example.com/h"}`)
	stored, err := s.CreateChannel(ctx, "webhook", "stored", hook, "secret:HOOK_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if stored.SecretSource != "missing" || stored.LastDeliveryAt != nil || stored.LastOKAt != nil {
		t.Fatalf("new channel naming an unstored secret: %+v", stored)
	}
	exec(`INSERT INTO workspace_secrets (name, sealed) VALUES ('HOOK_TOKEN', '\x00')`)
	server, err := s.CreateChannel(ctx, "webhook", "server", hook, "env:STACKURITY_SECRET_HOOK")
	if err != nil {
		t.Fatal(err)
	}
	none, err := s.CreateChannel(ctx, "webhook", "none", hook, "")
	if err != nil {
		t.Fatal(err)
	}

	// A test send that worked sets last_ok_at only.
	if err := s.ChannelResult(ctx, stored.ID, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetChannel(ctx, stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SecretSource != "stored" || got.LastOKAt == nil || got.LastDeliveryAt != nil {
		t.Fatalf("after a test: %+v", got)
	}

	// A real delivery marked sent sets last_delivery_at; a failed one does not.
	if _, err := s.EnqueueDelivery(ctx, stored.ID, nil, nil, "urgent", "a", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueDelivery(ctx, none.ID, nil, nil, "urgent", "b", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE deliveries SET status = 'sent', sent_at = now() - interval '1 hour' WHERE channel_id = $1`, stored.ID)
	exec(`UPDATE deliveries SET status = 'failed', last_error = 'refused' WHERE channel_id = $1`, none.ID)
	_ = s.ChannelResult(ctx, none.ID, errors.New("refused"))

	cs, err := s.ListChannels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for i, c := range cs {
		by[c.Name] = i
	}
	if c := cs[by["stored"]]; c.LastDeliveryAt == nil || c.SecretSource != "stored" {
		t.Fatalf("stored: %+v", c)
	}
	if c := cs[by["server"]]; c.SecretSource != "server" || c.LastDeliveryAt != nil || c.ID != server.ID {
		t.Fatalf("server: %+v", c)
	}
	if c := cs[by["none"]]; c.SecretSource != "" || c.LastDeliveryAt != nil || c.LastOKAt != nil {
		t.Fatalf("none: %+v", c)
	}
}
