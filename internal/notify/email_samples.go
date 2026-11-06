package notify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/feedback"
	"github.com/stackurity/stackurity/internal/store"
)

// EmailSample is one kind of email the server sends, with realistic data:
// every kind has one (email_test.go checks that), so the email checks and
// the previews (tools/emailpreview -samples) see all of them.
type EmailSample struct {
	// Name is the sample's file name, such as "account-password-reset".
	Name    string
	Message Message
	// Notification: an organisation's notification or a bulk email, which
	// has one-click unsubscribe headers.
	Notification bool
	// Secrets are the sample's tokens, codes and addresses, which must not
	// be in the subject.
	Secrets []string
	// Team: sent only by the Stackurity team's own server (the feedback
	// queue), so it may name the team's addresses.
	Team bool
}

// EmailSampleTime is when the samples are sent.
var EmailSampleTime = time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)

// EmailSamples are the samples for an installation at base (such as
// https://app.stackurity.dev).
func EmailSamples(base string) []EmailSample {
	base = strings.TrimRight(base, "/")
	at := EmailSampleTime
	d := &Dispatcher{BaseURL: base, Now: func() time.Time { return at }}
	const (
		ip       = "203.0.113.42"
		resetTok = "pwr_Zq7Kx2mN4pR8sT1vW6yB3cD9fG5hJ0kL"
		invTok   = "inv_Hq2Lm8Rt4Vx6Zb1Nc3Pd5Sf7Gh9Jk0Mw"
		confTok  = "ec_8Wn3Rk6Tq1Yv4Zx7Bm2Cp5Df9Gh0Js3Lk"
		code     = "482915"
	)
	key := []byte("emailpreview-unsubscribe-key-not-secret")

	// notification is m as email sent by Stackurity sends it to one
	// recipient (sendPlatformEmail): with its own unsubscribe links.
	notification := func(name string, m Message) EmailSample {
		token := UnsubscribeToken(key, 7, "dana@northwind-traders.com")
		m.unsubscribe = d.url("/email/unsubscribe", nil) + "#" + token
		m.oneClick = d.url("/email/unsubscribe/one-click", url.Values{"t": {token}})
		return EmailSample{Name: name, Message: m, Notification: true, Secrets: []string{token}}
	}
	incident := func(event string, in store.Incident) Message {
		in.ID, in.CreatedAt = 4182, at
		return d.message(in, event)
	}
	detail := func(v map[string]any) json.RawMessage {
		b, _ := json.Marshal(v)
		return b
	}
	vuln := store.Incident{Kind: "vulnerability", Key: "CVE-2026-31337", Title: "CVE-2026-31337 in openssl 3.0.13 (remote code execution)",
		Priority: "P1", Status: "open", OwnerTeam: "Platform", FindingCount: 4, AssetCount: 3,
		Detail: detail(map[string]any{"assets": []string{"web-1", "web-2", "api-gateway"}, "components": []string{"openssl 3.0.13"},
			"environments": []string{"production"}, "known_exploited": true, "fixed_versions": []string{"3.0.15"},
			"component_fixes": []map[string]any{{"component": "openssl", "type": "generic", "fixed_versions": []string{"3.0.15"}, "assets": 3, "unfixed": 0}},
			"component_count": 1})}
	sos := vuln
	sos.SOS = true
	escalated := vuln
	escalated.EscalationLevel = 2
	resolved := vuln
	resolved.Status = "resolved"

	route := store.Route{Name: "Security team"}
	fix := func(title, id string, asset int64) Item { return d.fixItem(title, id, asset) }
	urgent := d.grouped(route, EventUrgent, "web-1: 3 new urgent issues", []Section{{Items: []Item{{
		Text: "web-1: 3 new urgent issues (1 known exploited)", Link: d.findingsURL(12, nil), asset: 12,
		Items: []Item{
			fix("Upgrade openssl to 3.0.15 (clears 2 issues)", "openssl-3.0.15", 12),
			fix("Upgrade nginx to 1.26.2 (clears 1 issue)", "nginx-1.26.2", 12),
		}}}}})
	urgent.Priority = "P1"
	summary := d.grouped(route, EventSummary, "Daily summary: 12 new issues (3 urgent), 5 fixed", []Section{
		{Title: "New issues", Items: []Item{
			{Text: "web-1: 7 new issues (2 urgent)", Link: d.findingsURL(12, nil), asset: 12},
			{Text: "billing-api: 5 new issues (1 urgent)", Link: d.findingsURL(19, nil), asset: 19},
		}},
		{Title: "Fixed", Items: []Item{{Text: "web-2: 5 issues fixed by Upgrade glibc to 2.39-0ubuntu8.3", Link: d.findingsURL(13, nil), asset: 13}}},
		{Title: "Top fixes still open", Items: []Item{
			fix("Upgrade openssl to 3.0.15 on web-1 (clears 2 issues)", "openssl-3.0.15", 12),
			fix("Upgrade lodash to 4.17.21 on storefront (clears 3 issues)", "lodash-4.17.21", 21),
		}},
	})
	summary.Period = &Period{From: at.Add(-24 * time.Hour), To: at}
	overdue := d.grouped(route, EventOverdue, "2 urgent issues past their deadline across 1 fix", []Section{{Items: []Item{
		fix("Upgrade openssl to 3.0.15 on web-1 (2 urgent issues, due 1 Nov)", "openssl-3.0.15", 12),
		{Text: "See every overdue urgent issue", Link: d.findingsURL(0, url.Values{"overdue": {"true"}, "priority": {"P1"}})},
	}}})
	overdue.Priority = "P1"
	connected := d.grouped(route, EventConnected, "billing-api connected: 1,284 packages checked, 41 issues found, 2 fixes need you",
		[]Section{{Items: []Item{d.connectedItem(store.NewAsset{ID: 19, Name: "billing-api", Packages: 1284, Issues: 41},
			[]store.FixInfo{{ID: "spring-6.1.14", Title: "Upgrade spring-web to 6.1.14", FindingCount: 3}, {ID: "jackson-2.17.2", Title: "Upgrade jackson-databind to 2.17.2", FindingCount: 2}})}}})
	digest := Message{Event: EventDigest, Title: "Stackurity: 3 urgent messages held by the email limit", Route: route.Name, At: at,
		Summary: []string{"[P1] CVE-2026-31337 in openssl 3.0.13 (remote code execution)", "web-1: 3 new urgent issues", "billing-api: 2 new urgent issues"},
		Link:    d.url("/integrations/deliveries", nil)}

	released, _ := feedback.RenderEmail("released", feedback.EmailData{Ref: "FB-123", Version: "0.19.1",
		Resolution: "The filter is now kept when you go back."})
	wontFix, _ := feedback.RenderEmail("wont_fix", feedback.EmailData{Ref: "FB-124",
		Resolution: "Stackurity reads installed packages only, so it will not scan container layers it cannot see."})

	samples := []EmailSample{
		{Name: "account-invitation", Message: InvitationEmail("Northwind Traders", "Priya Shah (priya@northwind-traders.com)",
			"with Editor on all projects and assets", base+"/invite#"+invTok, at.Add(7*24*time.Hour), at), Secrets: []string{invTok}},
		{Name: "account-password-reset", Message: PasswordResetEmail(base, "dana@northwind-traders.com", base+"/reset-password#"+resetTok, ip, at),
			Secrets: []string{resetTok, ip}},
		{Name: "account-email-code", Message: EmailCodeEmail(base, "dana@northwind-traders.com", "signing in", code, ip, at),
			Secrets: []string{code, ip}},
		{Name: "account-email-code-signed-in", Message: EmailCodeSignInEmail(base, "dana@northwind-traders.com", ip, at), Secrets: []string{ip}},
		{Name: "account-two-factor-added", Message: FactorChangeEmail(base, "dana@northwind-traders.com", "A passkey, “MacBook Touch ID”, was added", "",
			ip, "Chrome on macOS", at), Secrets: []string{ip}},
		{Name: "account-two-factor-reset-by-admin", Message: FactorChangeEmail(base, "dana@northwind-traders.com", "Your two-factor methods were reset",
			"Priya Shah (priya@northwind-traders.com)", ip, "Firefox on Windows", at), Secrets: []string{ip}},
		{Name: "account-ask-budget-80", Message: AskSpendEmail(80, at)},
		{Name: "account-ask-budget-used-up", Message: AskSpendEmail(100, at)},
		{Name: "account-feedback-released", Message: FeedbackUpdateEmail(released.Subject, released.Body, at), Team: true},
		{Name: "account-feedback-wont-fix", Message: FeedbackUpdateEmail(wontFix.Subject, wontFix.Body, at), Team: true},
		{Name: "account-inactive-pause-first", Message: InactivePauseEmail(base, "Northwind Traders", at.Add(15*24*time.Hour), false, at)},
		{Name: "account-inactive-pause-last", Message: InactivePauseEmail(base, "Northwind Traders", at.Add(5*24*time.Hour), true, at)},
		{Name: "alerts-confirm-address", Message: alertConfirmEmail("Northwind Traders", d.url("/email/confirm", nil)+"#"+confTok,
			d.url("/email/block", nil)+"#"+confTok, d.url("/email/block/one-click", url.Values{"t": {confTok}}), at),
			Notification: true, Secrets: []string{confTok}},
		notification("notification-test", testEmail(at)),
		notification("notification-incident", incident("opened", vuln)),
		notification("notification-incident-sos", incident("opened", sos)),
		notification("notification-incident-escalated", incident("escalated", escalated)),
		notification("notification-incident-resolved", incident("resolved", resolved)),
		notification("notification-urgent", urgent),
		notification("notification-summary", summary),
		notification("notification-overdue", overdue),
		notification("notification-connected", connected),
		notification("notification-digest", digest),
		bulkSample(base, "bulk-release", store.CategoryMarketing, Message{Title: "Stackurity 0.17.0: what changed",
			Summary:  []string{"Email now looks like the rest of Stackurity, and every kind of email is checked before a release."},
			Sections: []Section{{Title: "Added", Items: []Item{{Text: "A button for the main action of every email"}, {Text: "Dark mode in mail clients that support it"}}}},
			Link:     "https://github.com/stackurity/stackurity/releases/tag/v0.17.0", LinkLabel: "Read the release notes"}),
		bulkSample(base, "bulk-vulnerability-news", store.CategoryVulnerabilityNews, Message{Title: "Vulnerability news: 3 exploited flaws to patch this week",
			Summary: []string{"Three vulnerabilities added to CISA's Known Exploited list affect software Stackurity users run."},
			Sections: []Section{{Title: "Known exploited", Items: []Item{
				{Text: "CVE-2026-106931 in Drupal core", Link: "https://nvd.nist.gov/vuln/detail/CVE-2026-106931"},
				{Text: "CVE-2026-110447 in GitLab Runner", Link: "https://nvd.nist.gov/vuln/detail/CVE-2026-110447"},
			}}},
			Link: base + "/", LinkLabel: "Open your dashboard"}),
	}
	for i := range samples {
		if samples[i].Message.At.IsZero() {
			samples[i].Message.At = at
		}
	}
	return samples
}

// bulkSample is a bulk email as one recipient gets it (Bulk.personalise).
func bulkSample(base, name, category string, m Message) EmailSample {
	m.Event = category
	unsub := fmt.Sprintf("%s/email/preferences#PREVIEW-unsubscribe-%s", base, category)
	m.bulk = &bulkFooter{category: category, unsubscribe: unsub, preferences: base + "/email/preferences#PREVIEW-preferences",
		postalAddress: "Example Ltd, 1 Main Road, Pune 411001, India", sender: "Stackurity <news@stackurity.dev>", home: base + "/"}
	m.oneClick = base + "/email/preferences/one-click?t=PREVIEW-" + category
	return EmailSample{Name: name, Message: m, Notification: true}
}
