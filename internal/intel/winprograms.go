package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// FeedWindowsPrograms holds advisories for the programs of the curated
// Windows program catalogue (internal/winprograms) installed on a Windows
// host, read from each program's source: Mozilla's advisories for Firefox
// and Thunderbird, NVD for the others. (Edge and the .NET runtimes come
// from Microsoft's Security Update Guide, through FeedMSRC.) Programs
// outside the catalogue are never looked up.
const FeedWindowsPrograms = "programs:Windows"

// DefaultNVDURL is NVD's CVE API.
const DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// programsCursor records, per catalogued program, when its advisories were
// last read completely and when last read at all.
type programsCursor struct {
	Catalogue string                   `json:"catalogue,omitempty"`
	Programs  map[string]programCursor `json:"programs"`
}

type programCursor struct {
	Full time.Time `json:"full"` // every CVE naming the program read
	Read time.Time `json:"read"` // the end of the last read, full or incremental
	// Unfixed counts, at the last complete read, the CVEs NVD names the
	// program in with no fixed version or no version bound at all: they are
	// not matched, and the program's rows say so.
	Unfixed int `json:"unfixed,omitempty"`
}

// programsUnfixed reads the unfixed counts from the feed's cursor.
func programsUnfixed(cursor string) map[string]int {
	var c programsCursor
	if json.Unmarshal([]byte(cursor), &c) != nil {
		return nil
	}
	out := map[string]int{}
	for id, pc := range c.Programs {
		out[id] = pc.Unfixed
	}
	return out
}

func (s *Syncer) catalogue() *winprograms.Catalogue {
	if s.programs != nil {
		return s.programs
	}
	return winprograms.Default()
}

// installedPrograms returns the catalogued programs with a source that are
// installed on any Windows host of the installation (system scope, so one
// workspace's refresh does not narrow what is read for the others).
func (s *Syncer) installedPrograms(ctx context.Context) ([]*winprograms.Program, error) {
	rows, err := s.Store.WindowsPrograms(tenant.System(ctx))
	if err != nil {
		return nil, err
	}
	cat := s.catalogue()
	seen := map[string]bool{}
	var out []*winprograms.Program
	for _, r := range rows {
		id := cat.Identify(r.Name, r.Publisher, r.Version)
		if id.Program == nil || id.Program.Source == nil || seen[id.Program.ID] ||
			(id.Program.Source.Type != winprograms.SourceNVD && id.Program.Source.Type != winprograms.SourceMozilla) {
			continue
		}
		seen[id.Program.ID] = true
		out = append(out, id.Program)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Syncer) syncWindowsPrograms(ctx context.Context, feed, cursor string) (*SyncResult, string, error) {
	progs, err := s.installedPrograms(ctx)
	if err != nil {
		return nil, "", err
	}
	var cur programsCursor
	if cursor != "" {
		_ = json.Unmarshal([]byte(cursor), &cur) // unusable: read everything
	}
	next := programsCursor{Catalogue: s.catalogue().Version(), Programs: map[string]programCursor{}}
	for id, c := range cur.Programs {
		next.Programs[id] = c
	}
	res := &SyncResult{Packages: map[store.PackageRef]bool{}, Full: true, Ecosystems: map[string]bool{}}
	var failed []string
	// Mozilla's advisories are one small archive, read once per sync for
	// every Mozilla program.
	var mozilla []mfsaDoc
	var mozillaErr error
	mozillaRead := false
	for _, p := range progs {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		now := s.clock()
		pc := next.Programs[p.ID]
		// A catalogue change can change what a program's CVEs are read as
		// (its CPEs, editions, version rule), so every program is read
		// completely again.
		full := pc.Full.IsZero() || now.Sub(pc.Full) >= nvdFullRead || now.Sub(pc.Read) >= nvdIncrMax || cur.Catalogue != next.Catalogue
		var err error
		if p.Source.Type == winprograms.SourceMozilla {
			if !mozillaRead {
				mozilla, mozillaErr = s.mozillaDocs(ctx)
				mozillaRead = true
			}
			full = true // the archive is always read completely
			err = mozillaErr
			if err == nil {
				err = s.storeProgram(ctx, feed, p, mozillaPrefix(p.ID), mozillaRecords(p, mozilla), nil, true, now, res)
			}
		} else {
			var unfixed int
			unfixed, err = s.syncProgram(ctx, feed, p, full, pc.Read, now, res)
			if err == nil && full {
				pc.Unfixed = unfixed
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			s.Log.Warn("Windows program advisories not read", "program", p.ID, "err", err)
			failed = append(failed, p.Label+": "+err.Error())
			continue
		}
		pc.Read = now
		if full {
			pc.Full = now
		}
		next.Programs[p.ID] = pc
	}
	if len(progs) > 0 && len(failed) == len(progs) {
		// Nothing could be read (NVD down, a broken mirror): the feed fails
		// and keeps its cursor and data.
		return nil, "", fmt.Errorf("no Windows program's advisories could be read: %s", strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		// One program must not hold up the others: what was read is stored
		// and re-evaluated; the failed programs keep what is stored and are
		// read again next time.
		res.Warning = fmt.Sprintf("advisories of %d Windows programs could not be read and are kept as last read: %s",
			len(failed), strings.Join(failed, "; "))
	}
	// A program's own ecosystem is listed once its advisories have been
	// read completely, so a program never read is "not evaluated" rather
	// than clean. One whose later reads fail keeps what was read, as a
	// failed document or release does for the other feeds, and the feed's
	// warning and staleness say the data is old.
	for id, pc := range next.Programs {
		if !pc.Full.IsZero() {
			res.Ecosystems[winprograms.Ecosystem+":"+id] = true
		}
	}
	b, _ := json.Marshal(next)
	return res, string(b), nil
}

// syncProgram reads one program's CVEs: every one naming its CPE products
// (full), or those modified since the last read, and stores them.
func (s *Syncer) syncProgram(ctx context.Context, feed string, p *winprograms.Program, full bool, lastRead, now time.Time, res *SyncResult) (int, error) {
	anomalies := nvdAnomalies{}
	byCVE := map[string]*osv.Vulnerability{}
	listed := map[string]bool{}  // CVEs NVD returned, usable or not
	unfixed := map[string]bool{} // CVEs named with no fix and no bound only
	var since time.Time
	if !full {
		since = lastRead.Add(-nvdOverlap)
	}
	for _, cpe := range p.Source.CPEs {
		err := s.nvdQuery(ctx, cpe, since, now, func(c nvdCVE) error {
			listed[c.ID] = true
			open := anomalies[nvdStartOnly] + anomalies[nvdUnbounded]
			if v := nvdRecord(p, c, anomalies); v != nil {
				byCVE[c.ID] = v
			} else if anomalies[nvdStartOnly]+anomalies[nvdUnbounded] > open {
				unfixed[c.ID] = true
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	if len(anomalies) > 0 {
		s.Log.Info("NVD configurations not used", "program", p.ID, "skipped", anomalies.String())
	}
	vulns := make([]*osv.Vulnerability, 0, len(byCVE))
	for _, v := range byCVE {
		vulns = append(vulns, v)
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID })
	for id := range byCVE {
		delete(unfixed, id) // read through another of its CPEs
	}
	return len(unfixed), s.storeProgram(ctx, feed, p, nvdPrefix(p.ID), vulns, listed, full, now, res)
}

// storeProgram stores one program's advisories (ids starting with prefix)
// and withdraws those no longer listed: on a full read, every stored one
// the source no longer names; on an incremental read, those in listed (the
// CVEs the source returned as changed) that are no longer usable.
func (s *Syncer) storeProgram(ctx context.Context, feed string, p *winprograms.Program, prefix string, vulns []*osv.Vulnerability,
	listed map[string]bool, full bool, now time.Time, res *SyncResult) error {
	byCVE := map[string]*osv.Vulnerability{}
	for _, v := range vulns {
		byCVE[v.Aliases[0]] = v
	}
	stored, err := s.Store.AdvisoryIDs(ctx, feed, prefix)
	if err != nil {
		return err
	}
	if full && len(stored) > 0 && (len(vulns) == 0 || 2*len(vulns) < len(stored)) {
		// Sources revise what they say, but never drop most of a
		// program's CVEs: an answer that lost more than half is refused and
		// the stored advisories kept.
		return fmt.Errorf("the source lists %d usable CVEs where %d are stored; refusing an answer that lost more than half of them (the stored ones are kept)",
			len(vulns), len(stored))
	}
	for i := 0; i < len(vulns); i += osvBatch {
		batch := vulns[i:min(i+osvBatch, len(vulns))]
		n, err := s.Store.UpsertAdvisories(ctx, feed, batch)
		if err != nil {
			return err
		}
		res.Changed += n
	}
	// Withdrawn: on a full read, every stored CVE NVD no longer names (or
	// names only in ways that are not used); on an incremental read, those
	// NVD returned (modified) that are no longer usable. A rejected CVE is
	// returned by neither, and is withdrawn by the next full read.
	var gone []*osv.Vulnerability
	for _, id := range stored {
		cve := strings.TrimPrefix(id, prefix)
		if byCVE[cve] != nil || (!full && !listed[cve]) {
			continue
		}
		gone = append(gone, &osv.Vulnerability{ID: id, Aliases: []string{cve}, Modified: now, Withdrawn: &now,
			Summary: "the source no longer lists " + cve + " for " + p.Label})
	}
	if len(gone) > 0 {
		n, err := s.Store.UpsertAdvisories(ctx, feed, gone)
		if err != nil {
			return err
		}
		res.Changed += n
	}
	return nil
}
