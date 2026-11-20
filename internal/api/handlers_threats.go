package api

// Threats and threat notices (docs/threat-notices.md). GET /threats is the
// catalogue this server uses (embedded in the release, merged with the
// signed feed): public intelligence, the same in every workspace. GET
// /threat-notices is the organisation's notices, with the caller's banner
// state; organisation-wide security and admin roles only, as they speak
// about every asset. Nothing here contacts anything.

import (
	"net/http"
	"time"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/threats"
	"github.com/stackurity/stackurity/internal/updates"
)

// threatOut is a catalogue entry as the API gives it.
type threatOut struct {
	threats.Threat
	// HasCheck: this server runs a release with the threat's check.
	HasCheck bool `json:"has_check"`
}

func (s *Server) threatCatalogue(r *http.Request) (*threats.Catalogue, error) {
	if s.Threats == nil {
		return threats.Merge(threats.Embedded(), nil), nil
	}
	return s.Threats.Current(r.Context())
}

// hasThreatCheck: Stackurity Cloud always has it once deployed; a
// self-hosted server compares its release with the threat's min_version.
func (s *Server) hasThreatCheck(t threats.Threat) bool {
	return t.HasCheck(updates.Running(s.Version))
}

// listThreats: GET /threats, the threat catalogue.
func (s *Server) listThreats(w http.ResponseWriter, r *http.Request) {
	c, err := s.threatCatalogue(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]threatOut, 0, len(c.Threats))
	for _, t := range c.Threats {
		items = append(items, threatOut{Threat: t, HasCheck: s.hasThreatCheck(t)})
	}
	writeJSON(w, 200, map[string]any{"schema": c.Schema, "serial": c.Serial, "generated_at": c.GeneratedAt, "threats": items})
}

// noticeNeed is a missing connection, with its Help page.
type noticeNeed struct {
	Connection string `json:"connection"`
	Label      string `json:"label"`
	Required   bool   `json:"required"`
	Checks     string `json:"checks"`
	Help       string `json:"help"`
	// Outdated: assets connected this way whose collector is older than
	// the check, so they are not checked yet.
	Outdated int `json:"outdated"`
}

// noticeAction is the banner's one button.
type noticeAction struct {
	Label string `json:"label"`
	Link  string `json:"link"`
}

type noticeOut struct {
	store.ThreatNotice
	Name       string        `json:"name"`
	Kind       string        `json:"kind"`
	Severity   string        `json:"severity"`
	Summary    string        `json:"summary"`
	Sources    []string      `json:"sources"`
	MinVersion string        `json:"min_version"`
	Title      string        `json:"title"`
	Lines      []string      `json:"lines"`
	Needs      []noticeNeed  `json:"missing_connections"`
	Action     *noticeAction `json:"action"`
}

// listThreatNotices: GET /threat-notices.
func (s *Server) listThreatNotices(w http.ResponseWriter, r *http.Request) {
	c, err := s.threatCatalogue(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.Store.ListThreatNotices(r.Context(), userID(principal(r)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	running := updates.Running(s.Version)
	items := make([]noticeOut, 0, len(list))
	for _, n := range list {
		t, ok := c.Get(n.ThreatID)
		if !ok {
			continue // retired from the catalogue
		}
		o := noticeOut{ThreatNotice: n, Name: t.Name, Kind: t.Kind, Severity: t.Severity, Summary: t.Summary, Sources: t.Sources,
			MinVersion: t.MinVersion, Needs: []noticeNeed{}}
		facts := notify.NoticeFacts{Verdict: n.Verdict, Findings: n.Findings, Assets: n.Assets, Signals: n.Signals, Connected: n.Connected,
			Outdated: n.Outdated, Running: running}
		for _, need := range t.Needs {
			for _, m := range n.Missing {
				if m == need.Connection {
					facts.Missing = append(facts.Missing, need)
					o.Needs = append(o.Needs, noticeNeed{Connection: need.Connection, Label: threats.ConnectionLabel(need.Connection),
						Required: need.Required, Checks: need.Checks, Help: need.Help, Outdated: n.Outdated[need.Connection]})
				}
			}
		}
		// The same words as the email, with dashboard-relative links.
		m := notify.ThreatNoticeMessage("", t, facts, time.Time{})
		o.Title, o.Lines = m.Title, m.Summary
		switch n.Verdict {
		case threats.Found:
			o.Action = &noticeAction{Label: "See findings", Link: notify.ThreatFindingsPath(t)}
		case threats.NeedsConnection:
			if len(o.Needs) > 0 {
				o.Action = &noticeAction{Label: "Connect", Link: o.Needs[0].Help}
				if o.Needs[0].Outdated > 0 {
					o.Action.Label = "Update"
				}
			}
		case threats.Upgrade:
			o.Action = &noticeAction{Label: "Upgrade", Link: "/help/backups-upgrades"}
		}
		items = append(items, o)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// dismissThreatNotice: POST /threat-notices/{id}/dismiss hides the banner
// for the caller, for the notice's current verdict.
func (s *Server) dismissThreatNotice(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	u := userID(p)
	if u <= 0 {
		s.fail(w, r, badRequest("only a signed-in person can hide a notice"))
		return
	}
	if err := s.Store.DismissThreatNotice(r.Context(), id, u); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "threat_notice.dismiss", "threat_notice", itoa(id), nil)
	w.WriteHeader(http.StatusNoContent)
}
