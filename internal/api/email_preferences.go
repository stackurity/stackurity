package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Email preferences for bulk email (internal/notify/bulk.go): signed in
// under Your account, or from the signed links in each bulk email without
// signing in. Only servers that send bulk email (EmailPreferences, set by a
// hosted edition) have them; elsewhere they answer 404.

// categoryInfo describes a bulk email category.
type categoryInfo struct {
	store.EmailPreference
	Label       string `json:"label"`
	Description string `json:"description"`
}

var categoryDescriptions = map[string]string{
	store.CategoryMarketing:         "Product updates: what changed in each release, new features, occasional news from Stackurity.",
	store.CategoryVulnerabilityNews: "A digest of notable new vulnerabilities and exploited software, not specific to your organisation.",
}

// lockedCategory is email that cannot be turned off here, and why.
type lockedCategory struct {
	Label       string `json:"label"`
	Description string `json:"description"`
}

var lockedCategories = []lockedCategory{
	{"Account and security", "Sign-up and email confirmation, password reset, two-factor authentication, sign-in alerts and invitations. " +
		"They are needed to use and protect your account, so they cannot be turned off."},
	{"Billing", "Receipts, failed payments, trial and plan changes, and notices before data is deleted. They are part of your contract."},
	{"Your organisation's notifications", "Alerts, summaries and incidents about your own servers and software. Change who gets them, " +
		"and which, under Settings → Integrations."},
}

func (s *Server) emailPrefsOff(w http.ResponseWriter) bool {
	if !s.EmailPreferences {
		writeError(w, 404, "not_found", "no such endpoint")
		return true
	}
	return false
}

func describePrefs(prefs []store.EmailPreference) []categoryInfo {
	out := make([]categoryInfo, 0, len(prefs))
	for _, p := range prefs {
		out = append(out, categoryInfo{EmailPreference: p, Label: notify.BulkCategoryLabel(p.Category), Description: categoryDescriptions[p.Category]})
	}
	return out
}

// prefsChange is a change of one or both categories; nil leaves one as it is.
type prefsChange struct {
	Marketing         *bool `json:"marketing"`
	VulnerabilityNews *bool `json:"vulnerability_news"`
}

func (c prefsChange) each(f func(category string, subscribed bool) error) error {
	if c.Marketing != nil {
		if err := f(store.CategoryMarketing, *c.Marketing); err != nil {
			return err
		}
	}
	if c.VulnerabilityNews != nil {
		return f(store.CategoryVulnerabilityNews, *c.VulnerabilityNews)
	}
	return nil
}

// applyPrefs records the changes and audits each one as a platform event
// (not in the organisation's log: it is the person's own choice).
func (s *Server) applyPrefs(r *http.Request, userID int64, email string, c prefsChange, source, actorType string) error {
	return c.each(func(category string, subscribed bool) error {
		changed, err := s.Store.SetEmailPreference(r.Context(), userID, category, subscribed, source)
		if err != nil || !changed {
			return err
		}
		action := "email.unsubscribed_category"
		if subscribed {
			action = "email.subscribed_category"
		}
		_ = s.Store.Audit(tenant.System(r.Context()), store.Actor{Type: actorType, ID: userID, Name: email, RemoteAddr: clientIP(r)},
			action, "user", itoa(userID), map[string]any{"category": category, "source": source})
		return nil
	})
}

func prefsAnswer(prefs []store.EmailPreference) map[string]any {
	return map[string]any{"categories": describePrefs(prefs), "locked": lockedCategories}
}

// myEmailPreferences: the signed-in person's choices.
func (s *Server) myEmailPreferences(w http.ResponseWriter, r *http.Request) {
	if s.emailPrefsOff(w) {
		return
	}
	p := principal(r)
	if p.User == nil {
		writeError(w, 403, "forbidden", "only people have email preferences")
		return
	}
	prefs, err := s.Store.EmailPreferences(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, prefsAnswer(prefs))
}

// setMyEmailPreferences changes the signed-in person's choices.
func (s *Server) setMyEmailPreferences(w http.ResponseWriter, r *http.Request) {
	if s.emailPrefsOff(w) {
		return
	}
	p := principal(r)
	if p.User == nil {
		writeError(w, 403, "forbidden", "only people have email preferences")
		return
	}
	var c prefsChange
	if err := decode(r, &c); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.applyPrefs(r, p.User.ID, p.User.Email, c, store.EmailSourceSettings, "user"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.myEmailPreferences(w, r)
}

// prefsLink checks a signed link's token. On failure it has answered:
// 410 link_expired (signed, too old: sign in instead) or link_invalid.
func (s *Server) prefsLink(w http.ResponseWriter, r *http.Request, token string) (notify.PrefsClaim, *store.User, bool) {
	key, err := notify.PrefsKey(r.Context(), s.Store)
	if err != nil {
		s.fail(w, r, err)
		return notify.PrefsClaim{}, nil, false
	}
	c, err := notify.ParsePrefsToken(key, strings.TrimSpace(token), time.Now())
	if errors.Is(err, notify.ErrPrefsTokenExpired) {
		writeError(w, 410, "link_expired", "this link has expired; sign in and open Your account to change your email preferences")
		return c, nil, false
	}
	if err != nil {
		writeError(w, 410, "link_invalid", "this link is not valid")
		return c, nil, false
	}
	u, err := s.Store.GetUser(tenant.System(r.Context()), c.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 410, "link_invalid", "this link is not valid")
		return c, nil, false
	}
	if err != nil {
		s.fail(w, r, err)
		return c, nil, false
	}
	return c, u, true
}

// maskEmail shows enough of an address for its owner to recognise it, and
// little to anyone a link was forwarded to.
func maskEmail(e string) string {
	local, domain, ok := strings.Cut(e, "@")
	if !ok || local == "" {
		return "***"
	}
	return string([]rune(local)[:1]) + "***@" + domain
}

type prefsTokenRequest struct {
	Token string `json:"token"`
	prefsChange
}

// linkEmailPreferences opens the preference page from an email's link:
// for a preference link, both categories; for an unsubscribe link, its
// category. Nothing changes.
func (s *Server) linkEmailPreferences(w http.ResponseWriter, r *http.Request) {
	if s.emailPrefsOff(w) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	c, u, ok := s.prefsLink(w, r, req.Token)
	if !ok {
		return
	}
	s.answerLinkPrefs(w, r, c, u)
}

func (s *Server) answerLinkPrefs(w http.ResponseWriter, r *http.Request, c notify.PrefsClaim, u *store.User) {
	prefs, err := s.Store.EmailPreferences(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if c.Kind == notify.PrefsKindUnsubscribe {
		for _, p := range prefs {
			if p.Category == c.Category {
				prefs = []store.EmailPreference{p}
				break
			}
		}
	}
	out := prefsAnswer(prefs)
	out["kind"], out["email"] = map[string]string{notify.PrefsKindUnsubscribe: "unsubscribe", notify.PrefsKindCentre: "preferences"}[c.Kind], maskEmail(u.Email)
	if c.Kind == notify.PrefsKindUnsubscribe {
		out["category"] = c.Category
	}
	writeJSON(w, 200, out)
}

// updateLinkEmailPreferences changes preferences from an email's link. An
// unsubscribe link can only turn its own category off; a preference link
// can change both.
func (s *Server) updateLinkEmailPreferences(w http.ResponseWriter, r *http.Request) {
	if s.emailPrefsOff(w) {
		return
	}
	var req prefsTokenRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	c, u, ok := s.prefsLink(w, r, req.Token)
	if !ok {
		return
	}
	if c.Kind == notify.PrefsKindUnsubscribe {
		allowed := true
		_ = req.prefsChange.each(func(category string, subscribed bool) error {
			allowed = allowed && category == c.Category && !subscribed
			return nil
		})
		if !allowed {
			writeError(w, 403, "forbidden", "this link can only unsubscribe you from "+notify.BulkCategoryLabel(c.Category)+
				"; open Email preferences from the email, or sign in, to change anything else")
			return
		}
	}
	if err := s.applyPrefs(r, u.ID, u.Email, req.prefsChange, store.EmailSourceLink, "anonymous"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.answerLinkPrefs(w, r, c, u)
}

// oneClickEmailPreferences is a mail client's one-click unsubscribe
// (RFC 8058) from a bulk email's List-Unsubscribe header: the token is in
// the address, the body says List-Unsubscribe=One-Click. It only ever turns
// the token's category off, answers without redirecting anywhere, and
// says the same for a category already off.
func (s *Server) oneClickEmailPreferences(w http.ResponseWriter, r *http.Request) {
	if s.emailPrefsOff(w) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	// RFC 8058: the mail client posts List-Unsubscribe=One-Click, as a
	// URL-encoded or multipart form. Anything else (a prefetch, a stray
	// POST) changes nothing.
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		_ = r.ParseMultipartForm(4096)
	} else {
		_ = r.ParseForm()
	}
	if r.PostFormValue("List-Unsubscribe") != "One-Click" {
		writeError(w, 400, "one_click_required", "a one-click unsubscribe posts List-Unsubscribe=One-Click (RFC 8058)")
		return
	}
	c, u, ok := s.prefsLink(w, r, r.URL.Query().Get("t"))
	if !ok {
		return
	}
	if c.Kind != notify.PrefsKindUnsubscribe {
		writeError(w, 410, "link_invalid", "this link is not valid")
		return
	}
	off := false
	ch := prefsChange{}
	switch c.Category {
	case store.CategoryMarketing:
		ch.Marketing = &off
	case store.CategoryVulnerabilityNews:
		ch.VulnerabilityNews = &off
	}
	if err := s.applyPrefs(r, u.ID, u.Email, ch, store.EmailSourceHeader, "anonymous"); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "unsubscribed", "category": c.Category})
}
