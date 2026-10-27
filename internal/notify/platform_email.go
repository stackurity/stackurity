package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// Email sent by Stackurity. On a hosted installation the platform's own mail
// server delivers the stackurity_email channels of every organisation, so
// none of them configures SMTP. Abuse is limited three ways:
//
//   - recipients are members of the organisation, or addresses that clicked
//     a confirmation link emailed to them (store.RequestEmailConfirmations);
//   - per-organisation limits per minute, hour and day, counted in emails
//     (one per recipient). A message over a limit is never dropped: an urgent,
//     connected or overdue message is held and rolled into the route's next
//     summary (or, for a route without summaries, the hourly digest); a
//     summary or digest waits until the limit frees;
//   - messages stay grouped as for every channel: one per check, plus
//     summaries, never one per issue.

// Mailer sends one message to a list of recipients through the platform's
// mail server. Recipients do not see each other's addresses.
type Mailer interface {
	SendMail(ctx context.Context, to []string, m Message) error
	// From is the sender address people see.
	From() string
}

// SMTPMailer is a Mailer over SMTP (STACKURITY_CLOUD_SMTP_* on Stackurity
// Cloud).
type SMTPMailer struct {
	Sender   *Sender
	Config   ChannelConfig // host, port, username, from, tls
	Password string
}

func (m *SMTPMailer) From() string { return m.Config.From }

func (m *SMTPMailer) SendMail(ctx context.Context, to []string, msg Message) error {
	cfg := m.Config
	cfg.To = to
	cfg.headerTo = "Stackurity notifications <undisclosed-recipients:;>"
	if len(to) == 1 {
		cfg.headerTo = to[0]
	}
	return m.Sender.sendEmail(ctx, cfg, m.Password, msg)
}

// DefaultEmailLimits are the per-organisation limits when none are set.
var DefaultEmailLimits = store.EmailLimits{PerMinute: 30, PerHour: 300, PerDay: 1000}

// DefaultMaxRecipients is how many members and addresses one
// stackurity_email channel may name.
const DefaultMaxRecipients = 20

// PlatformEmail reports whether email sent by Stackurity is available.
func (d *Dispatcher) PlatformEmail() bool { return d.PlatformMail != nil }

// EmailLimits are the per-organisation limits in force.
func (d *Dispatcher) EmailLimits() store.EmailLimits {
	if d.EmailQuota == (store.EmailLimits{}) {
		return DefaultEmailLimits
	}
	return d.EmailQuota
}

// MaxEmailRecipients is how many recipients a stackurity_email channel may
// name.
func (d *Dispatcher) MaxEmailRecipients() int {
	if d.MaxRecipients > 0 {
		return d.MaxRecipients
	}
	return DefaultMaxRecipients
}

// recipients resolves a stackurity_email channel to the addresses it may
// send to now: its enabled members and its confirmed addresses.
func (d *Dispatcher) recipients(ctx context.Context, ch *store.Channel) ([]string, error) {
	var cfg ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return nil, err
	}
	out, err := d.Store.MemberEmails(ctx, cfg.UserIDs)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range out {
		seen[e] = true
	}
	if len(cfg.To) > 0 {
		ok, err := d.Store.ConfirmedEmails(ctx, cfg.To)
		if err != nil {
			return nil, err
		}
		for _, t := range cfg.To {
			t = strings.ToLower(t)
			if ok[t] && !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out, nil
}

// errNoRecipients: nothing to send to until someone confirms.
var errNoRecipients = &PermanentError{Err: errors.New("no recipients yet: add a member, or wait for an address to confirm the link it was sent")}

// quotaCheck is the email limit check of a due delivery to a
// stackurity_email channel, before it is claimed. It returns the
// reservation to send under, or holds or defers the delivery and returns
// ok false. Summaries and digests, which held messages go into, are
// deferred until the limit frees; other messages are held for them.
func (d *Dispatcher) quotaCheck(ctx context.Context, ch *store.Channel, del store.Delivery, route *store.Route) (reservation int64, ok bool, err error) {
	to, err := d.recipients(ctx, ch)
	if err != nil {
		return 0, false, err
	}
	if len(to) == 0 {
		return 0, true, nil // the send fails with errNoRecipients
	}
	id, err := d.Store.ReserveEmails(ctx, len(to), d.EmailLimits())
	var over *store.EmailOverLimit
	if !errors.As(err, &over) {
		return id, err == nil, err
	}
	if del.Event == EventSummary || del.Event == EventDigest || del.RouteID == nil {
		return 0, false, d.Store.DeferDelivery(ctx, del.ID, over.Until)
	}
	why := fmt.Sprintf("email limit per %s reached; included in the next summary", over.Limit)
	if route == nil || !sendsSummary(*route) {
		why = fmt.Sprintf("email limit per %s reached; included in the next hourly digest", over.Limit)
	}
	return 0, false, d.Store.HoldDeliveryBy(ctx, del.ID, store.HeldEmailQuota, why)
}

// sendPlatformEmail delivers to a stackurity_email channel.
func (d *Dispatcher) sendPlatformEmail(ctx context.Context, ch *store.Channel, msg Message) error {
	if d.PlatformMail == nil {
		return &PermanentError{Err: errors.New("email sent by Stackurity is not available on this server")}
	}
	to, err := d.recipients(ctx, ch)
	if err != nil {
		return err
	}
	if len(to) == 0 {
		return errNoRecipients
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return d.PlatformMail.SendMail(sctx, to, msg)
}

// SendEmailConfirmations emails a confirmation link to each address of the
// context's workspace that must confirm before email sent by Stackurity
// reaches it. organisation and inviter name who asks.
func (d *Dispatcher) SendEmailConfirmations(ctx context.Context, tokens map[string]string, organisation, inviter string) error {
	if d.PlatformMail == nil || len(tokens) == 0 {
		return nil
	}
	var errs []error
	for email, token := range tokens {
		link := strings.TrimSuffix(d.BaseURL, "/") + "/email/confirm#" + token
		who := organisation
		if inviter != "" {
			who = inviter + " at " + organisation
		}
		m := Message{Event: "confirm_email", Title: "Confirm Stackurity notifications from " + organisation, At: d.now().UTC(),
			Summary: []string{
				who + " wants to send Stackurity security notifications to this address.",
				"To receive them, confirm within 7 days: " + link,
				"If you do not know them, ignore this email: nothing will be sent to you.",
			}}
		id, err := d.Store.ReserveEmails(ctx, 1, d.EmailLimits())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = d.PlatformMail.SendMail(sctx, []string{email}, m)
		cancel()
		if err != nil {
			_ = d.Store.ReleaseEmails(context.WithoutCancel(ctx), id)
			errs = append(errs, fmt.Errorf("%s: %w", email, err))
		}
	}
	return errors.Join(errs...)
}
