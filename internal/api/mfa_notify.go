package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/notify"
)

// Every change to a person's second factors is emailed to their account's
// address: a passkey, the authenticator app or email codes added or
// removed, new recovery codes, and an administrator's reset. It cannot be
// turned off. It is how someone finds out that a phished password and code
// were used to register an attacker's passkey. It goes through the
// transactional mail (AccountMail); a server without it sends nothing.

// notifyFactorChange emails to (the account's address) that change
// happened ("A passkey, “MacBook Touch ID”, was added"), with when, from
// which address and device, and what to do if it was not them. admin names
// the administrator who made it, for a reset. It is sent after the
// response.
func (s *Server) notifyFactorChange(r *http.Request, to, change, admin string) {
	if s.AccountMail == nil || to == "" {
		return
	}
	m := factorChangeMessage(s.BaseURL, to, change, admin, clientIP(r), r.UserAgent(), time.Now().UTC())
	ctx := context.WithoutCancel(r.Context())
	go func() {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if err := s.AccountMail.SendMail(ctx, []string{to}, m); err != nil {
			s.Log.Error("two-factor change email not sent", "err", err)
		}
	}()
}

func factorChangeMessage(base, to, change, admin, ip, userAgent string, at time.Time) notify.Message {
	host := hostOf(base)
	where := "Stackurity"
	if host != "" {
		where = "Stackurity (" + host + ")"
	}
	who := ""
	if admin != "" {
		who = " by an administrator, " + admin + ","
	}
	from := "From " + ip + ", " + deviceSummary(userAgent) + "."
	if admin != "" {
		from = "From the administrator's " + ip + ", " + deviceSummary(userAgent) + "."
	}
	notMe := "If this was not you, someone may have your password: change it now, which signs you out everywhere, then remove anything you do not recognise under Your account → Two-factor methods and tell your administrator."
	if base != "" {
		notMe = "If this was not you, someone may have your password: reset it now at " + strings.TrimRight(base, "/") +
			"/forgot-password (that signs you out everywhere), then remove anything you do not recognise under Your account → Two-factor methods and tell your administrator."
	}
	return notify.Message{Event: "mfa_changed", Title: "Your Stackurity two-factor sign-in changed", At: at,
		Summary: []string{
			change + who + " on your account " + to + " at " + where + ".",
			"When: " + at.Format("2 Jan 2006 15:04 UTC") + ". " + from,
			notMe,
			"You get this email whenever your two-factor sign-in changes; it cannot be turned off.",
		}}
}

// deviceSummary names the browser and system from a User-Agent header
// ("Chrome on macOS"). Only names from fixed lists are used, never text
// from the header itself, so nothing a client sends reaches the email.
func deviceSummary(ua string) string {
	browser := ""
	for _, b := range []struct{ token, name string }{
		{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"}, {"CriOS/", "Chrome"},
		{"Chrome/", "Chrome"}, {"Safari/", "Safari"}, {"curl/", "curl"},
	} {
		if strings.Contains(ua, b.token) {
			browser = b.name
			break
		}
	}
	system := ""
	for _, o := range []struct{ token, name string }{
		{"iPhone", "iOS"}, {"iPad", "iPadOS"}, {"Android", "Android"}, {"CrOS", "ChromeOS"}, {"Windows", "Windows"},
		{"Mac OS X", "macOS"}, {"Macintosh", "macOS"}, {"Linux", "Linux"},
	} {
		if strings.Contains(ua, o.token) {
			system = o.name
			break
		}
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return "a browser on " + system
	}
	return "an unknown browser or program"
}
