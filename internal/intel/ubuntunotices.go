package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
)

// Ubuntu's own security notices (USNs), read from ubuntu.com, fill the days
// before OSV carries a notice. OSV's per-CVE Ubuntu records (UBUNTU-CVE-…)
// can say "all versions, no fix" for days after the notice that fixed the
// CVE is out, and OSV can lag the notice itself: on 23 November 2026
// USN-9182-1 (nginx, published 20 November) was on ubuntu.com but in neither
// OSV nor Canonical's OSV export. The matcher takes a free-channel USN's
// fixed version over a UBUNTU-CVE record's "no fix" (ubuntuUSNFixes); this
// feed gives it the notices OSV has not caught up with.
//
// What is stored, and what is not:
//   - Only notices OSV has not delivered: a USN already stored from another
//     feed is left alone, and when OSV later delivers one this feed stored,
//     OSV's record replaces it (advisories are keyed by id; the last writer
//     wins, and this feed never writes over another feed's record).
//   - Only the free channels: each release's source packages, for releases
//     whose support tag is LTS or none (interim releases). Ubuntu Pro (ESM)
//     and FIPS fixes are skipped: the matcher never takes a fix from them in
//     place of a "no fix" (ubuntuUSNFixes), and OSV carries them as before.
//   - The records are a fix source only. matchAdvisories never matches them
//     on their own, so a notice read here never opens a finding: it can only
//     supply the fixed version of a CVE an OSV record already reports.
//
// The list (GET /security/notices.json?limit=N&offset=M&order=newest) is
// read newest first until a notice older than the cursor less an overlap
// (Ubuntu revises notices after publishing them), on the first sync until
// ubuntuNoticesFirstWindow back: OSV covers older history.

// FeedUbuntuNotices reads Ubuntu Security Notices from ubuntu.com.
const FeedUbuntuNotices = "notices:Ubuntu"

const (
	ubuntuNoticesPage = 20       // notices per request
	ubuntuNoticesMax  = 64 << 20 // per page; a page of kernel notices is a few MB
	// ubuntuNoticesPages caps one sync, so a source that never reaches the
	// cursor (a changed order, a mirror that ignores offset) cannot loop.
	ubuntuNoticesPages = 60
	// ubuntuNoticesFirstWindow is how far back the first sync reads.
	ubuntuNoticesFirstWindow = 30 * 24 * time.Hour
	// ubuntuNoticesOverlap is re-read before the newest notice seen, for
	// notices revised after they were first published.
	ubuntuNoticesOverlap = 24 * time.Hour
)

var usnID = regexp.MustCompile(`^USN-\d{1,6}-\d{1,3}$`)

// ubuntuNotice is the part of a notice in ubuntu.com's JSON that is read.
type ubuntuNotice struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Hidden    bool     `json:"is_hidden"`
	Title     string   `json:"title"`
	Summary   string   `json:"summary"`
	Published string   `json:"published"`
	CVEs      []string `json:"cves_ids"`
	Releases  []struct {
		Codename   string `json:"codename"`
		Version    string `json:"version"`
		SupportTag string `json:"support_tag"`
	} `json:"releases"`
	Packages map[string][]struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		IsSource bool   `json:"is_source"`
	} `json:"release_packages"`
}

type ubuntuNoticePage struct {
	Notices []json.RawMessage `json:"notices"`
	Total   int               `json:"total_results"`
}

// ubuntuNoticesCursor is the feed's cursor: the newest notice read.
type ubuntuNoticesCursor struct {
	Newest time.Time `json:"newest"`
}

// parseUSNTime reads ubuntu.com's timestamps, which carry no zone
// ("2026-11-20T03:15:31.773953"): they are UTC.
func parseUSNTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unreadable time %q", s)
}

// ubuntuNoticeRecord converts a notice to the OSV shape OSV gives a USN:
// upstream names the UBUNTU-CVE records it fixes, and each free-channel
// release's source package has the range introduced 0, fixed at the
// notice's version. ok is false for a notice with nothing usable.
func ubuntuNoticeRecord(n ubuntuNotice) (v *osv.Vulnerability, published time.Time, ok bool, err error) {
	published, err = parseUSNTime(n.Published)
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("%s: %w", n.ID, err)
	}
	if !usnID.MatchString(n.ID) || n.Hidden || (n.Type != "" && n.Type != "USN") {
		return nil, published, false, nil
	}
	v = &osv.Vulnerability{ID: n.ID, Published: published, Modified: published, Summary: n.Title,
		References:       []osv.Reference{{Type: "ADVISORY", URL: "https://ubuntu.com/security/notices/" + n.ID}},
		DatabaseSpecific: json.RawMessage(`{"source":"ubuntu.com security notices"}`)}
	for _, c := range n.CVEs {
		if strings.HasPrefix(c, "CVE-") && !slices.Contains(v.Upstream, "UBUNTU-"+c) {
			v.Upstream = append(v.Upstream, "UBUNTU-"+c)
		}
	}
	if len(v.Upstream) == 0 {
		return nil, published, false, nil // fixes no CVE: nothing for ubuntuUSNFixes
	}
	for _, rel := range n.Releases {
		eco, free := ubuntuReleaseEcosystem(rel.Version, rel.SupportTag)
		if !free {
			continue
		}
		seen := map[string]bool{}
		for _, p := range n.Packages[rel.Codename] {
			if !p.IsSource || p.Name == "" || p.Version == "" || seen[p.Name] {
				continue
			}
			lv := strings.ToLower(p.Version)
			if strings.Contains(lv, "+esm") || strings.Contains(lv, "fips") {
				continue // a Pro build listed on a free release
			}
			seen[p.Name] = true
			v.Affected = append(v.Affected, osv.Affected{
				Package: osv.Package{Ecosystem: eco, Name: p.Name},
				Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: p.Version}}}},
			})
		}
	}
	if len(v.Affected) == 0 {
		return nil, published, false, nil
	}
	return v, published, true, nil
}

// ubuntuReleaseEcosystem is OSV's ecosystem for a release's free updates
// ("Ubuntu:22.04:LTS", "Ubuntu:26.10"). free is false for a release whose
// only updates are Ubuntu Pro's (support tag ESM) or one that cannot be read.
func ubuntuReleaseEcosystem(version, tag string) (eco string, free bool) {
	if _, err := strconv.ParseFloat(version, 64); err != nil || !strings.Contains(version, ".") {
		return "", false
	}
	switch tag {
	case "LTS":
		return "Ubuntu:" + version + ":LTS", true
	case "":
		return "Ubuntu:" + version, true
	}
	return "", false
}

func (s *Syncer) syncUbuntuNotices(ctx context.Context, feed, cursor string) (*SyncResult, string, error) {
	var cur ubuntuNoticesCursor
	if cursor != "" {
		if err := json.Unmarshal([]byte(cursor), &cur); err != nil {
			cur = ubuntuNoticesCursor{} // read as a first sync
		}
	}
	stop := s.clock().Add(-ubuntuNoticesFirstWindow)
	if !cur.Newest.IsZero() {
		stop = cur.Newest.Add(-ubuntuNoticesOverlap)
	}
	base := s.f.cfg.UbuntuNoticesURL
	res := &SyncResult{Packages: map[store.PackageRef]bool{}}
	newest := cur.Newest
	read := 0
	for page := 0; page < ubuntuNoticesPages; page++ {
		if ctx.Err() != nil {
			return nil, cursor, ctx.Err()
		}
		u, err := url.Parse(base)
		if err != nil {
			return nil, cursor, fmt.Errorf("STACKURITY_UBUNTU_NOTICES_URL: %w", err)
		}
		q := u.Query()
		q.Set("limit", strconv.Itoa(ubuntuNoticesPage))
		q.Set("offset", strconv.Itoa(page*ubuntuNoticesPage))
		q.Set("order", "newest")
		u.RawQuery = q.Encode()
		b, err := s.f.download(ctx, u.String(), ubuntuNoticesMax)
		if err != nil {
			return nil, cursor, err
		}
		var p ubuntuNoticePage
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, cursor, fmt.Errorf("Ubuntu notices page %d: %w", page, err)
		}
		var batch []*osv.Vulnerability
		reached := len(p.Notices) < ubuntuNoticesPage
		for _, raw := range p.Notices {
			var n ubuntuNotice
			if err := json.Unmarshal(raw, &n); err != nil {
				return nil, cursor, fmt.Errorf("Ubuntu notices page %d: %w", page, err)
			}
			v, published, ok, err := ubuntuNoticeRecord(n)
			if err != nil {
				s.Log.Warn("Ubuntu notice not read", "err", err)
				continue
			}
			read++
			if published.After(newest) {
				newest = published
			}
			if published.Before(stop) {
				reached = true
				continue
			}
			if ok {
				batch = append(batch, v)
			}
		}
		if err := s.storeUbuntuNotices(ctx, feed, batch, res); err != nil {
			return nil, cursor, err
		}
		if reached {
			next, _ := json.Marshal(ubuntuNoticesCursor{Newest: newest})
			s.Log.Info("Ubuntu notices read", "notices", read, "stored", res.Changed)
			return res, string(next), nil
		}
	}
	// The cap was reached before the cursor: keep what was stored, and the
	// old cursor, so the next sync reads the same window again.
	res.Warning = fmt.Sprintf("read %d pages of Ubuntu notices without reaching %s", ubuntuNoticesPages, stop.Format(time.DateOnly))
	return res, cursor, nil
}

// storeUbuntuNotices stores the notices no other feed holds: OSV's copy of
// a USN, once there, is the one kept. The check is not in the upsert's
// transaction: if OSV stores the same notice in that instant, this copy
// replaces it until OSV next changes the record, which is harmless (both
// describe the same notice) and rare enough not to lock for.
func (s *Syncer) storeUbuntuNotices(ctx context.Context, feed string, batch []*osv.Vulnerability, res *SyncResult) error {
	if len(batch) == 0 {
		return nil
	}
	ids := make([]string, len(batch))
	for i, v := range batch {
		ids[i] = v.ID
	}
	feeds, err := s.Store.AdvisoryFeeds(ctx, ids)
	if err != nil {
		return err
	}
	var mine []*osv.Vulnerability
	for _, v := range batch {
		if f, ok := feeds[v.ID]; ok && f != feed {
			continue
		}
		mine = append(mine, v)
	}
	if len(mine) == 0 {
		return nil
	}
	n, err := s.Store.UpsertAdvisories(ctx, feed, mine)
	if err != nil {
		return err
	}
	res.Changed += n
	if n > 0 {
		for _, v := range mine {
			for _, a := range v.Affected {
				res.Packages[store.PackageRef{BaseEcosystem: "Ubuntu", Name: a.Package.Name}] = true
			}
		}
	}
	return nil
}
