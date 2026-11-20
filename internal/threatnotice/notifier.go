package threatnotice

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/threats"
	"github.com/stackurity/stackurity/internal/updates"
)

// Every is how often each organisation's verdicts are worked out again.
const Every = 30 * time.Minute

// Window is how long after a threat is added an organisation that has no
// notice yet gets one. Later (a new organisation, months on) the threat is
// still in threat_check and list_threat_notices, but no notice is sent.
const Window = 30 * 24 * time.Hour

// CopySettle is how long after the last new notice of a threat the
// operator's copy waits, so the first pass over every organisation is done.
const CopySettle = 2 * time.Hour

// Notifier works out and delivers threat notices.
type Notifier struct {
	Store      *store.Store
	Catalogues *Catalogues
	// Dispatcher queues the notice for notification routes; nil: none.
	Dispatcher *notify.Dispatcher
	// Mail sends the email to administrators and the security team (the
	// account mailer); nil: no email (recorded as no_mailer).
	Mail    notify.Mailer
	BaseURL string
	// Running is this server's comparable release ("" for a development
	// build, which counts as having every check).
	Running string
	// Cloud: Stackurity Cloud, which runs the latest release and never
	// says "upgrade".
	Cloud bool
	// CopyTo is the operator's address for one summary per threat
	// (Stackurity Cloud only, STACKURITY_THREAT_NOTICE_COPY_TO).
	CopyTo string
	Log    *slog.Logger
	Now    func() time.Time

	seenMu     sync.Mutex
	seenSerial int64
}

func (n *Notifier) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

// Run works out the verdict of every threat for the organisation in ctx,
// records it, and delivers a notice that is new or now found.
func (n *Notifier) Run(ctx context.Context) error {
	cat, err := n.Catalogues.Current(ctx)
	if err != nil {
		return err
	}
	if err := n.recordSeen(ctx, cat); err != nil {
		return err
	}
	versions, err := n.Store.ThreatConnectionVersions(ctx)
	if err != nil {
		return err
	}
	firstSeen, err := n.Store.ThreatsFirstSeen(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range cat.Threats {
		if err := n.one(ctx, t, versions, firstSeen[t.ID]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// recordSeen adds the catalogue's threats to threats_seen once per serial
// (notices refer to them).
func (n *Notifier) recordSeen(ctx context.Context, cat *threats.Catalogue) error {
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	if n.seenSerial == cat.Serial && cat.Serial != 0 {
		return nil
	}
	if err := recordSeen(ctx, n.Store, cat); err != nil {
		return err
	}
	n.seenSerial = cat.Serial
	return nil
}

// UpgradeHold is how long after this installation first knew a threat an
// "upgrade" notice waits. During a rolling upgrade to the release that has
// the check, a replica still on the older release would otherwise tell
// every organisation to upgrade minutes before it is done.
const UpgradeHold = 24 * time.Hour

// connectionCounts splits the assets of each connection by whether their
// latest complete collection came from a collector with the threat's
// check: a server whose agent is older than min_version was not checked,
// so it does not make the threat "covered". A collection that recorded no
// version counts as older.
func connectionCounts(t threats.Threat, versions []store.ConnectionVersion) (conns, outdated map[string]int) {
	conns, outdated = map[string]int{}, map[string]int{}
	for _, v := range versions {
		if v.Version != "" && t.CollectorHasCheck(updates.Running(v.Version)) {
			conns[v.Connection] += v.Assets
		} else {
			outdated[v.Connection] += v.Assets
		}
	}
	return conns, outdated
}

func (n *Notifier) one(ctx context.Context, t threats.Threat, versions []store.ConnectionVersion, firstSeen time.Time) error {
	prev, err := n.Store.GetThreatNotice(ctx, t.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if prev == nil && n.now().Sub(t.Published()) > Window {
		return nil
	}
	findings, assets, signals, assetIDs, err := n.Store.ThreatEvidence(ctx, t.Detects.ConfigRules, t.Detects.CVEs, t.Detects.SignalRules)
	if err != nil {
		return err
	}
	conns, outdated := connectionCounts(t, versions)
	a, ok := threats.Assess(t, threats.Evidence{Findings: findings, Assets: assets, Signals: signals}, conns, outdated, n.Running, n.Cloud)
	if !ok {
		return nil
	}
	if prev == nil && a.Verdict == threats.Upgrade && (firstSeen.IsZero() || n.now().Sub(firstSeen) < UpgradeHold) {
		return nil // a rolling upgrade may be under way
	}
	mode := store.NoticeQuiet
	switch {
	case prev == nil || threats.Worsened(prev.NotifiedVerdict, a.Verdict):
		mode = store.NoticeTell
	case prev.NotifiedVerdict == threats.Found && a.Verdict != threats.Found:
		// Fixed: a later "found" is news again.
		mode = store.NoticeReset
	}
	missing := make([]string, 0, len(a.Missing))
	for _, m := range a.Missing {
		missing = append(missing, m.Connection)
	}
	saved, err := n.Store.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: t.ID, Verdict: a.Verdict, Findings: findings,
		Assets: assets, Connected: a.Connected, Outdated: a.Outdated, Signals: signals, Missing: missing}, mode)
	if err != nil {
		return err
	}
	// Deliver a notice just told, or one whose delivery a crash, a restart
	// or a failed email cut short, while its verdict is still the one told.
	if mode == store.NoticeReset || saved.Verdict != saved.NotifiedVerdict || (saved.EmailAt != nil && saved.ChannelsAt != nil) {
		return nil
	}
	if mode == store.NoticeTell {
		_ = n.Store.Audit(ctx, store.Actor{Type: "system", Name: "Threat notices"}, "threat_notice.sent", "threat", t.ID,
			map[string]any{"verdict": a.Verdict, "findings": findings, "assets": assets, "missing": missing})
		if n.Log != nil {
			ws, _ := tenant.Workspace(ctx)
			n.Log.Info("threat notice", "workspace", ws, "threat", t.ID, "verdict", a.Verdict)
		}
	}
	facts := notify.NoticeFacts{Verdict: a.Verdict, Findings: findings, Assets: assets, Signals: signals, Connected: a.Connected,
		Outdated: a.Outdated, Missing: a.Missing, Running: n.Running}
	return n.deliver(ctx, t, saved, facts, assetIDs)
}

func (n *Notifier) deliver(ctx context.Context, t threats.Threat, saved *store.ThreatNotice, facts notify.NoticeFacts, assetIDs []int64) error {
	at := n.now().UTC()
	if saved.EmailAt == nil {
		result, count := n.email(ctx, t, facts, at)
		if err := n.Store.ThreatNoticeEmailed(ctx, saved.ID, result, count); err != nil {
			return err
		}
	}
	if saved.ChannelsAt == nil {
		queued := 0
		if n.Dispatcher != nil {
			var err error
			queued, err = n.Dispatcher.QueueThreatNotice(ctx, saved.ID, facts.Verdict, saved.BannerAt, assetIDs, func(assets int) notify.Message {
				f := facts
				if assets >= 0 {
					// A project's or an asset's route hears about its own
					// assets only.
					f.Assets, f.Findings = assets, 0
				}
				return notify.ThreatNoticeMessage(n.BaseURL, t, f, at)
			})
			if err != nil {
				return err
			}
		}
		if err := n.Store.ThreatNoticeQueued(ctx, saved.ID, queued); err != nil {
			return err
		}
	}
	return nil
}

// email sends the notice to the organisation's administrators and security
// team. It returns the result recorded on the notice and the recipients.
func (n *Notifier) email(ctx context.Context, t threats.Threat, facts notify.NoticeFacts, at time.Time) (string, int) {
	if n.Mail == nil {
		return "no_mailer", 0
	}
	users, err := n.Store.ListUsers(ctx)
	if err != nil {
		if n.Log != nil {
			n.Log.Error("threat notice: listing administrators", "threat", t.ID, "err", err)
		}
		return "failed", 0
	}
	var to []string
	for _, u := range users {
		if !u.Disabled && (u.Role == auth.RoleAdmin || u.Role == auth.RoleSecurity) && strings.Contains(u.Email, "@") {
			to = append(to, u.Email)
		}
	}
	if len(to) == 0 {
		return "no_recipients", 0
	}
	if err := n.Mail.SendMail(ctx, to, notify.ThreatNoticeMessage(n.BaseURL, t, facts, at)); err != nil {
		if n.Log != nil {
			n.Log.Error("threat notice email not sent", "threat", t.ID, "err", err)
		}
		return "failed", len(to)
	}
	return "sent", len(to)
}

// SendCopies sends the operator one summary per threat whose notices went
// out (Stackurity Cloud with CopyTo set; a no-op otherwise). It names no
// organisation and no asset: counts per verdict and one example, rendered
// from counts. System scope.
func (n *Notifier) SendCopies(ctx context.Context) error {
	if !n.Cloud || n.CopyTo == "" || n.Mail == nil {
		return nil
	}
	ctx = tenant.System(ctx)
	cat, err := n.Catalogues.Current(ctx)
	if err != nil {
		return err
	}
	due, err := n.Store.ThreatCopiesDue(ctx, CopySettle)
	if err != nil {
		return err
	}
	for _, d := range due {
		t, ok := cat.Get(d.ThreatID)
		if !ok {
			continue
		}
		claimed, err := n.Store.ClaimThreatCopy(ctx, d.ThreatID, d.Counts)
		if err != nil || !claimed {
			if err != nil {
				return err
			}
			continue
		}
		ex := d.Example
		facts := notify.NoticeFacts{Verdict: ex.Verdict, Findings: ex.Findings, Assets: ex.Assets, Signals: ex.Signals, Connected: ex.Connected,
			Outdated: ex.Outdated, Running: n.Running}
		for _, need := range t.Needs {
			for _, m := range ex.Missing {
				if m == need.Connection {
					facts.Missing = append(facts.Missing, need)
				}
			}
		}
		at := n.now().UTC()
		msg := notify.ThreatNoticeCopyMessage(t, d.Counts, notify.ThreatNoticeMessage(n.BaseURL, t, facts, at), at)
		if err := n.Mail.SendMail(ctx, []string{n.CopyTo}, msg); err != nil {
			_ = n.Store.ReleaseThreatCopy(ctx, d.ThreatID)
			return err
		}
		if n.Log != nil {
			n.Log.Info("threat notice copy sent", "threat", d.ThreatID, "counts", d.Counts)
		}
	}
	return nil
}
