package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// Bulk email: one message to many people, in a category they can
// unsubscribe from (store.EmailCategories: marketing, vulnerability_news).
// It is the only way such email is sent, and on every send it:
//
//   - checks, just before that recipient's email goes, that the person is
//     still subscribed, the address is not suppressed for the category and
//     did not ask never to be emailed, and the account is enabled (so an
//     unsubscribe counts at once, even in the middle of a send);
//   - records the recipient as claimed before handing the email to the
//     mail server, so running the same campaign again (after a crash, a
//     timeout or by mistake) never sends anyone a second copy;
//   - waits Interval between two emails;
//   - adds the List-Unsubscribe and List-Unsubscribe-Post headers (RFC 8058)
//     and a footer with links to unsubscribe from the category and to the
//     preference page, both signed for that person, and the sender's
//     postal address.
//
// Transactional email and notifications about a person's own organisation
// never go through here and cannot be unsubscribed from with these links.

// BulkCategoryLabel is a category's name as people read it.
func BulkCategoryLabel(c string) string {
	switch c {
	case store.CategoryMarketing:
		return "Marketing"
	case store.CategoryVulnerabilityNews:
		return "Vulnerability news"
	}
	return c
}

// Signed links in bulk email. A token names one person (user id), what it
// may do and until when, with an HMAC-SHA256 over all of it with the
// installation's "email-preferences" key:
//
//   - unsubscribe (kind "u"): turn one category off, from the footer link
//     or a mail client's one-click POST. It cannot turn anything on, or
//     touch the other category.
//   - preferences (kind "p"): read and change both categories on the
//     preference page, without signing in. It expires sooner.
const (
	PrefsKindUnsubscribe = "u"
	PrefsKindCentre      = "p"

	prefsKeyName = "email-preferences"
	// UnsubscribeLinkTTL is how long an unsubscribe link works: well beyond
	// the 30 days laws such as CAN-SPAM require.
	UnsubscribeLinkTTL = 2 * 365 * 24 * time.Hour
	// PreferencesLinkTTL is how long a preference page link works.
	PreferencesLinkTTL = 90 * 24 * time.Hour
)

// PrefsClaim is what a signed preference token allows.
type PrefsClaim struct {
	Kind     string // PrefsKindUnsubscribe or PrefsKindCentre
	UserID   int64
	Category string // the category, for unsubscribe; "all" for the preference page
	Expires  time.Time
}

func prefsPayload(c PrefsClaim) string {
	return "v1:" + c.Kind + ":" + strconv.FormatInt(c.UserID, 10) + ":" + c.Category + ":" + strconv.FormatInt(c.Expires.Unix(), 10)
}

// PrefsToken signs a claim.
func PrefsToken(key []byte, c PrefsClaim) string {
	p := prefsPayload(c)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("email-preferences:" + p))
	return base64.RawURLEncoding.EncodeToString([]byte(p)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ErrPrefsTokenExpired: a correctly signed token past its expiry.
var ErrPrefsTokenExpired = errors.New("this link has expired")

// ErrPrefsTokenInvalid: anything else wrong with a token.
var ErrPrefsTokenInvalid = errors.New("this link is not valid")

// ParsePrefsToken checks a token's signature, shape and expiry.
func ParsePrefsToken(key []byte, token string, now time.Time) (PrefsClaim, error) {
	var c PrefsClaim
	if len(token) > 300 {
		return c, ErrPrefsTokenInvalid
	}
	p64, sig64, ok := strings.Cut(token, ".")
	if !ok {
		return c, ErrPrefsTokenInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(p64)
	if err != nil {
		return c, ErrPrefsTokenInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(sig64)
	if err != nil {
		return c, ErrPrefsTokenInvalid
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("email-preferences:" + string(raw)))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return c, ErrPrefsTokenInvalid
	}
	f := strings.Split(string(raw), ":")
	if len(f) != 5 || f[0] != "v1" {
		return c, ErrPrefsTokenInvalid
	}
	c.Kind, c.Category = f[1], f[3]
	if c.UserID, err = strconv.ParseInt(f[2], 10, 64); err != nil || c.UserID <= 0 {
		return c, ErrPrefsTokenInvalid
	}
	exp, err := strconv.ParseInt(f[4], 10, 64)
	if err != nil {
		return c, ErrPrefsTokenInvalid
	}
	c.Expires = time.Unix(exp, 0).UTC()
	switch {
	case c.Kind == PrefsKindUnsubscribe && store.ValidEmailCategory(c.Category):
	case c.Kind == PrefsKindCentre && c.Category == "all":
	default:
		return c, ErrPrefsTokenInvalid
	}
	if !now.Before(c.Expires) {
		return c, ErrPrefsTokenExpired
	}
	return c, nil
}

// PrefsKey is the installation's key for preference links.
func PrefsKey(ctx context.Context, st *store.Store) ([]byte, error) {
	return st.PlatformKey(ctx, prefsKeyName)
}

// bulkFooter is what a bulk email adds for its recipient.
type bulkFooter struct {
	category      string
	unsubscribe   string // the visible unsubscribe link (preference page)
	preferences   string // the preference page, both categories
	postalAddress string
	test          bool
}

// Bulk sends bulk email. Store and Mail are required; BaseURL is the
// dashboard's address the links point to.
type Bulk struct {
	Store   *store.Store
	Mail    Mailer
	BaseURL string
	// PostalAddress is the sender's physical address, shown in every
	// footer (laws such as CAN-SPAM require one in commercial email).
	PostalAddress string
	// Interval is the wait between two emails (default 1s).
	Interval time.Duration
	Log      *slog.Logger
	Now      func() time.Time
	// Sleep waits between emails; tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (b *Bulk) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Bulk) interval() time.Duration {
	if b.Interval > 0 {
		return b.Interval
	}
	return time.Second
}

func (b *Bulk) sleep(ctx context.Context, d time.Duration) error {
	if b.Sleep != nil {
		return b.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var campaignKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// BulkCampaign is a bulk email to send: its key (the same key continues
// the same campaign), category and message. The message's Title is the
// subject; Summary lines are the opening paragraphs; Sections list what
// it is about; Link and LinkLabel are its main link.
type BulkCampaign struct {
	Key      string
	Category string
	Message  Message
}

func (c BulkCampaign) check() error {
	switch {
	case !campaignKey.MatchString(c.Key):
		return fmt.Errorf("campaign key %q: use lower-case letters, digits, '.', '-' and '_' (at most 100)", c.Key)
	case !store.ValidEmailCategory(c.Category):
		return fmt.Errorf("unknown email category %q", c.Category)
	case strings.TrimSpace(c.Message.Title) == "" || len(c.Message.Title) > 200:
		return errors.New("the subject must be 1 to 200 characters")
	}
	return nil
}

func (c BulkCampaign) message() Message {
	m := c.Message
	m.Event = c.Category
	return m
}

// BulkResult counts what a run did, or (dry run) would do.
type BulkResult struct {
	Recipients int            `json:"recipients"`
	Sent       int            `json:"sent"`             // sent now (dry run: would be sent)
	Done       int            `json:"already_done"`     // sent or claimed by an earlier run
	Failed     int            `json:"failed"`           // the mail server refused; a later run retries them
	Skipped    map[string]int `json:"skipped"`          // by reason (store.Skip*)
	Errors     []string       `json:"errors,omitempty"` // the first few send errors
}

func (r *BulkResult) skip(reason string) {
	if r.Skipped == nil {
		r.Skipped = map[string]int{}
	}
	r.Skipped[reason]++
}

// Plan is a dry run: what Send would do now, changing nothing and sending
// nothing.
func (b *Bulk) Plan(ctx context.Context, c BulkCampaign, to []store.BulkRecipient) (BulkResult, error) {
	res := BulkResult{Recipients: len(to)}
	if err := c.check(); err != nil {
		return res, err
	}
	var campaignID int64
	if got, err := b.Store.CampaignByKey(ctx, c.Key); err == nil {
		campaignID = got.ID
	} else if !errors.Is(err, store.ErrNotFound) {
		return res, err
	}
	for _, r := range to {
		if campaignID > 0 {
			st, err := b.Store.CampaignSendStatus(ctx, campaignID, r.UserID)
			if err != nil {
				return res, err
			}
			if st == "sent" || st == "sending" {
				res.Done++
				continue
			}
		}
		why, err := b.Store.BulkEligible(ctx, r, c.Category)
		if err != nil {
			return res, err
		}
		if why != "" {
			res.skip(why)
			continue
		}
		res.Sent++
	}
	return res, nil
}

// Send sends a campaign to the recipients, one at a time, Interval apart.
// It can be run again with the same campaign: whoever already got it is
// skipped, and whoever failed is tried again. It stops when ctx ends.
func (b *Bulk) Send(ctx context.Context, c BulkCampaign, to []store.BulkRecipient, by string) (BulkResult, error) {
	res := BulkResult{Recipients: len(to)}
	if err := c.check(); err != nil {
		return res, err
	}
	m := c.message()
	body, err := json.Marshal(m)
	if err != nil {
		return res, err
	}
	camp, err := b.Store.EnsureCampaign(ctx, store.Campaign{Key: c.Key, Category: c.Category, Subject: m.Title, Message: body}, by)
	if err != nil {
		return res, err
	}
	key, err := PrefsKey(ctx, b.Store)
	if err != nil {
		return res, err
	}
	sent := false
	for _, r := range to {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		claim, why, err := b.Store.ClaimCampaignSend(ctx, camp.ID, r, c.Category)
		if err != nil {
			return res, err
		}
		switch claim {
		case store.ClaimDone:
			res.Done++
			continue
		case store.ClaimSkipped:
			res.skip(why)
			continue
		}
		if sent {
			if err := b.sleep(ctx, b.interval()); err != nil {
				// Not sent: the claim is released for the next run.
				_ = b.Store.FinishCampaignSend(context.WithoutCancel(ctx), camp.ID, r.UserID, err)
				return res, err
			}
		}
		pm := b.personalise(m, key, r.UserID, false)
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		serr := b.Mail.SendMail(sctx, []string{r.Email}, pm)
		cancel()
		sent = true
		if err := b.Store.FinishCampaignSend(context.WithoutCancel(ctx), camp.ID, r.UserID, serr); err != nil {
			return res, err
		}
		if serr != nil {
			res.Failed++
			if len(res.Errors) < 5 {
				res.Errors = append(res.Errors, serr.Error())
			}
			if b.Log != nil {
				b.Log.Warn("bulk email not sent", "campaign", c.Key, "user", r.UserID, "err", serr)
			}
			continue
		}
		res.Sent++
	}
	return res, nil
}

// SendTest sends a campaign's message to one person, marked as a test:
// nothing is recorded, and their preferences are not checked. Its links
// work for that person.
func (b *Bulk) SendTest(ctx context.Context, c BulkCampaign, to store.BulkRecipient) error {
	if err := c.check(); err != nil {
		return err
	}
	key, err := PrefsKey(ctx, b.Store)
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return b.Mail.SendMail(sctx, []string{to.Email}, b.personalise(c.message(), key, to.UserID, true))
}

// BulkPreview is a campaign's email as a recipient would get it, with
// placeholder links.
type BulkPreview struct {
	From    string   `json:"from"`
	Subject string   `json:"subject"`
	Headers []string `json:"headers"`
	Text    string   `json:"text"`
	HTML    string   `json:"html"`
}

// Preview renders a campaign without sending it. The links in it are
// placeholders that work for nobody.
func (b *Bulk) Preview(c BulkCampaign) (BulkPreview, error) {
	if err := c.check(); err != nil {
		return BulkPreview{}, err
	}
	m := c.message()
	u := strings.TrimRight(b.BaseURL, "/")
	m.bulk = &bulkFooter{category: c.Category, unsubscribe: u + "/email/preferences#PREVIEW-unsubscribe",
		preferences: u + "/email/preferences#PREVIEW-preferences", postalAddress: b.PostalAddress}
	m.oneClick = u + "/email/preferences/one-click?t=PREVIEW"
	raw := string(buildEmail(b.Mail.From(), []string{"recipient@example.com"}, m))
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	p := BulkPreview{From: b.Mail.From(), Subject: m.Subject(), Text: bulkText(m), HTML: bulkHTML(m)}
	for _, l := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(l, "List-") || strings.HasPrefix(l, "X-Stackurity") || strings.HasPrefix(l, "Subject:") || strings.HasPrefix(l, "From:") {
			p.Headers = append(p.Headers, l)
		}
	}
	return p, nil
}

// personalise adds a recipient's signed links.
func (b *Bulk) personalise(m Message, key []byte, userID int64, test bool) Message {
	now := b.now()
	u := strings.TrimRight(b.BaseURL, "/")
	unsub := PrefsToken(key, PrefsClaim{Kind: PrefsKindUnsubscribe, UserID: userID, Category: m.Event, Expires: now.Add(UnsubscribeLinkTTL)})
	prefs := PrefsToken(key, PrefsClaim{Kind: PrefsKindCentre, UserID: userID, Category: "all", Expires: now.Add(PreferencesLinkTTL)})
	m.bulk = &bulkFooter{category: m.Event, unsubscribe: u + "/email/preferences#" + unsub, preferences: u + "/email/preferences#" + prefs,
		postalAddress: b.PostalAddress, test: test}
	m.oneClick = u + "/email/preferences/one-click?" + url.Values{"t": {unsub}}.Encode()
	if m.At.IsZero() {
		m.At = now.UTC()
	}
	return m
}

// bulkWhy is the footer's first line.
func bulkWhy(f *bulkFooter) string {
	return fmt.Sprintf("You are receiving this because you are subscribed to %s emails from Stackurity.", BulkCategoryLabel(f.category))
}

func bulkText(m Message) string {
	var b strings.Builder
	b.WriteString(m.Subject() + "\n\n")
	for _, l := range m.Summary {
		b.WriteString(l + "\n\n")
	}
	for _, s := range m.Sections {
		if s.Title != "" {
			b.WriteString(s.Title + "\n")
		}
		writeItems(&b, s.Items, "")
		b.WriteString("\n")
	}
	if m.Link != "" {
		label := m.LinkLabel
		if label == "" {
			label = "Read more"
		}
		b.WriteString(label + ": " + m.Link + "\n")
	}
	if f := m.bulk; f != nil {
		b.WriteString("\n--\n" + bulkWhy(f) + "\n")
		b.WriteString("Unsubscribe from " + BulkCategoryLabel(f.category) + ": " + f.unsubscribe + "\n")
		b.WriteString("Email preferences: " + f.preferences + "\n")
		if f.postalAddress != "" {
			b.WriteString(f.postalAddress + "\n")
		}
	}
	return b.String()
}

func bulkHTML(m Message) string {
	var b strings.Builder
	esc := html.EscapeString
	link := func(text, href string) string {
		if href == "" {
			return esc(text)
		}
		return `<a href="` + esc(href) + `">` + esc(text) + `</a>`
	}
	b.WriteString(`<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;color:#1f2933;max-width:640px">` + "\n")
	b.WriteString(`<h2 style="font-size:18px;margin:0 0 12px">` + esc(m.Subject()) + "</h2>\n")
	for _, l := range m.Summary {
		b.WriteString("<p>" + esc(l) + "</p>\n")
	}
	var items func([]Item)
	items = func(list []Item) {
		b.WriteString("<ul style=\"margin:4px 0 4px 18px;padding:0\">\n")
		for _, it := range list {
			b.WriteString("<li>" + link(it.Text, it.Link))
			if len(it.Items) > 0 {
				items(it.Items)
			}
			b.WriteString("</li>\n")
		}
		b.WriteString("</ul>\n")
	}
	for _, s := range m.Sections {
		if s.Title != "" {
			b.WriteString(`<h3 style="font-size:15px;margin:16px 0 4px">` + esc(s.Title) + "</h3>\n")
		}
		items(s.Items)
	}
	if m.Link != "" {
		label := m.LinkLabel
		if label == "" {
			label = "Read more"
		}
		b.WriteString(`<p style="margin-top:16px">` + link(label, m.Link) + "</p>\n")
	}
	if f := m.bulk; f != nil {
		b.WriteString(`<hr style="border:0;border-top:1px solid #d9e2ec;margin:24px 0 12px">` + "\n")
		b.WriteString(`<p style="font-size:12px;color:#52606d">` + esc(bulkWhy(f)) + "<br>")
		b.WriteString(link("Unsubscribe from "+BulkCategoryLabel(f.category), f.unsubscribe) + " &middot; " + link("Email preferences", f.preferences))
		if f.postalAddress != "" {
			b.WriteString("<br>" + esc(f.postalAddress))
		}
		b.WriteString("</p>\n")
	}
	b.WriteString("</body></html>\n")
	return b.String()
}
