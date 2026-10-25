package intel

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// Feed names.
const (
	FeedKEV       = "kev:cisa"
	FeedEndOfLife = "lifecycle:endoflife"
	FeedNpm       = "releases:npm"
	FeedPackagist = "releases:packagist"
)

func OSVFeed(baseEcosystem string) string { return "osv:" + baseEcosystem }

// FeedAmazonLinux reads Amazon Linux security advisories (ALAS) from the
// distribution's own repositories; OSV does not carry them.
const FeedAmazonLinux = "alas:Amazon Linux"

// VulnFeed names the feed that holds advisories for a base ecosystem.
func VulnFeed(baseEcosystem string) string {
	if baseEcosystem == "Amazon Linux" {
		return FeedAmazonLinux
	}
	return OSVFeed(baseEcosystem)
}

// feedEcosystem returns the base ecosystem a vulnerability feed covers.
func feedEcosystem(feed string) (string, bool) {
	if feed == FeedAmazonLinux {
		return "Amazon Linux", true
	}
	return strings.CutPrefix(feed, "osv:")
}

type Syncer struct {
	Store *store.Store
	Log   *slog.Logger
	// Changed, if set, is called after a sync has stored its records and
	// before the feed's cursor moves past them, to queue re-evaluation of
	// what they affect. If it fails, the sync fails and keeps its cursor, so
	// the next attempt fetches the same records and calls Changed again: an
	// error or a crash in between cannot lose the re-evaluation.
	Changed func(ctx context.Context, feed string, res *SyncResult) error
	f       *fetcher
}

func NewSyncer(s *store.Store, log *slog.Logger, cfg Config) *Syncer {
	return &Syncer{Store: s, Log: log, f: newFetcher(cfg)}
}

// SyncResult tells the caller which packages changed so it can re-evaluate
// only what is affected.
type SyncResult struct {
	Changed  int
	Packages map[store.PackageRef]bool
	Full     bool // everything in the ecosystem should be re-evaluated
}

// Sync refreshes one feed and records the outcome on the feed row.
func (s *Syncer) Sync(ctx context.Context, name string) (*SyncResult, error) {
	feed, err := s.Store.GetFeed(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := s.Store.FeedAttempt(ctx, name); err != nil {
		return nil, err
	}
	var res *SyncResult
	cursor := feed.Cursor
	switch {
	case strings.HasPrefix(name, "osv:"):
		res, cursor, err = s.syncOSV(ctx, name, strings.TrimPrefix(name, "osv:"), feed.Cursor)
	case name == FeedAmazonLinux:
		res, err = s.syncAmazonLinux(ctx, name)
	case name == FeedKEV:
		res, err = s.syncKEV(ctx)
	case name == FeedEndOfLife:
		res, err = s.syncEndOfLife(ctx)
	case isReleaseFeed(name):
		res, err = s.syncReleases(ctx, name)
	default:
		err = fmt.Errorf("unknown feed %q", name)
	}
	if err == nil && s.Changed != nil {
		if cerr := s.Changed(ctx, name, res); cerr != nil {
			err = fmt.Errorf("queue re-evaluation: %w", cerr)
		}
	}
	changed := 0
	if res != nil {
		changed = res.Changed
	}
	if rerr := s.Store.FeedResult(context.WithoutCancel(ctx), name, cursor, changed, err); rerr != nil && err == nil {
		err = rerr
	}
	return res, err
}

// --- OSV

const osvBatch = 500

func (s *Syncer) syncOSV(ctx context.Context, feed, eco, cursor string) (*SyncResult, string, error) {
	base := strings.TrimSuffix(s.f.cfg.OSVBaseURL, "/") + "/" + url.PathEscape(eco)
	if cursor != "" {
		res, newCursor, err := s.osvIncremental(ctx, feed, base, cursor)
		if !errors.Is(err, errTooManyChanges) {
			return res, newCursor, err
		}
		s.Log.Info("many changes since last sync; downloading full archive", "feed", feed)
	}
	return s.osvFull(ctx, feed, base)
}

var errTooManyChanges = errors.New("too many changes for incremental sync")

// osvFull downloads <eco>/all.zip to disk and streams its records.
func (s *Syncer) osvFull(ctx context.Context, feed, base string) (*SyncResult, string, error) {
	start := time.Now().UTC()
	resp, err := s.f.get(ctx, base+"/all.zip", nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(s.f.cfg.WorkDir, "osv-*.zip")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	const maxArchive = 4 << 30
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, "", fmt.Errorf("download %s/all.zip: %w", base, err)
	}
	if n > maxArchive {
		return nil, "", errors.New("OSV archive exceeds 4 GiB")
	}
	zr, err := zip.NewReader(tmp, n)
	if err != nil {
		return nil, "", err
	}
	res := &SyncResult{Full: true, Packages: map[store.PackageRef]bool{}}
	var batch []*osv.Vulnerability
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		touched, err := s.Store.UpsertAdvisories(ctx, feed, batch)
		for p := range touched {
			res.Packages[p] = true
		}
		res.Changed += len(batch)
		batch = batch[:0]
		return err
	}
	for _, zf := range zr.File {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		if !strings.HasSuffix(zf.Name, ".json") || zf.UncompressedSize64 > 64<<20 {
			continue
		}
		v, err := readZipVuln(zf)
		if err != nil {
			s.Log.Warn("skipping unreadable OSV record", "feed", feed, "file", zf.Name, "err", err)
			continue
		}
		batch = append(batch, v)
		if len(batch) >= osvBatch {
			if err := flush(); err != nil {
				return nil, "", err
			}
		}
	}
	if err := flush(); err != nil {
		return nil, "", err
	}
	// The cursor is the download start: modified_id.csv entries after this
	// are picked up incrementally next time.
	return res, start.Format(time.RFC3339Nano), nil
}

func readZipVuln(zf *zip.File) (*osv.Vulnerability, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var v osv.Vulnerability
	if err := json.NewDecoder(io.LimitReader(rc, 64<<20)).Decode(&v); err != nil {
		return nil, err
	}
	if v.ID == "" {
		return nil, errors.New("record without id")
	}
	return &v, nil
}

// osvIncremental reads modified_id.csv (newest first) until it reaches the
// cursor, then fetches each changed record.
func (s *Syncer) osvIncremental(ctx context.Context, feed, base, cursor string) (*SyncResult, string, error) {
	since, err := time.Parse(time.RFC3339Nano, cursor)
	if err != nil {
		return nil, "", errTooManyChanges // unusable cursor: start over
	}
	resp, err := s.f.get(ctx, base+"/modified_id.csv", nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	r := csv.NewReader(bufio.NewReader(resp.Body))
	r.FieldsPerRecord = 2
	newest := since
	var ids []string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("parse modified_id.csv: %w", err)
		}
		ts, err := time.Parse(time.RFC3339Nano, rec[0])
		if err != nil {
			continue
		}
		if !ts.After(since) {
			break // sorted newest first
		}
		if ts.After(newest) {
			newest = ts
		}
		ids = append(ids, rec[1])
		if len(ids) > s.f.cfg.IncrementalLimit {
			return nil, "", errTooManyChanges
		}
	}
	res := &SyncResult{Packages: map[store.PackageRef]bool{}}
	if len(ids) == 0 {
		return res, cursor, nil
	}
	vulns := make([]*osv.Vulnerability, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			b, err := s.f.download(ctx, base+"/"+url.PathEscape(id)+".json", 64<<20)
			if err != nil {
				errs[i] = err
				return
			}
			var v osv.Vulnerability
			if err := json.Unmarshal(b, &v); err != nil {
				errs[i] = err
				return
			}
			vulns[i] = &v
		}(i, id)
	}
	wg.Wait()
	var got []*osv.Vulnerability
	for i, v := range vulns {
		if errs[i] != nil {
			var se *statusError
			if errors.As(errs[i], &se) && se.Status == 404 {
				continue // record moved or removed upstream
			}
			// Keep the old cursor so the failed records are retried.
			return nil, "", fmt.Errorf("fetch %s: %w", ids[i], errs[i])
		}
		got = append(got, v)
	}
	for i := 0; i < len(got); i += osvBatch {
		end := min(i+osvBatch, len(got))
		touched, err := s.Store.UpsertAdvisories(ctx, feed, got[i:end])
		if err != nil {
			return nil, "", err
		}
		for p := range touched {
			res.Packages[p] = true
		}
	}
	res.Changed = len(got)
	return res, newest.Format(time.RFC3339Nano), nil
}

// --- CISA KEV

func (s *Syncer) syncKEV(ctx context.Context) (*SyncResult, error) {
	b, err := s.f.download(ctx, s.f.cfg.KEVURL, 64<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			Vendor     string `json:"vendorProject"`
			Product    string `json:"product"`
			Name       string `json:"vulnerabilityName"`
			Added      string `json:"dateAdded"`
			Due        string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse KEV: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return nil, errors.New("KEV catalogue is empty; refusing to clear existing data")
	}
	seen := map[string]bool{}
	var rows [][]any
	for _, v := range doc.Vulnerabilities {
		if !strings.HasPrefix(v.CVE, "CVE-") || seen[v.CVE] {
			continue
		}
		seen[v.CVE] = true
		rows = append(rows, []any{v.CVE, v.Vendor, v.Product, v.Name, parseDate(v.Added), parseDate(v.Due), strings.EqualFold(v.Ransomware, "Known")})
	}
	if err := s.Store.ReplaceKnownExploited(ctx, rows); err != nil {
		return nil, err
	}
	_ = s.Store.SetFeedRecords(ctx, FeedKEV, int64(len(rows)))
	return &SyncResult{Changed: len(rows), Full: true}, nil
}

func parseDate(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
}

// --- endoflife.date

type eolProduct struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Links struct {
		HTML string `json:"html"`
	} `json:"links"`
	Identifiers []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"identifiers"`
	Releases []struct {
		Name        string  `json:"name"`
		Label       string  `json:"label"`
		ReleaseDate string  `json:"releaseDate"`
		IsLTS       bool    `json:"isLts"`
		EOASFrom    *string `json:"eoasFrom"`
		IsEOL       bool    `json:"isEol"`
		EOLFrom     *string `json:"eolFrom"`
		Latest      *struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"latest"`
	} `json:"releases"`
}

func (s *Syncer) syncEndOfLife(ctx context.Context) (*SyncResult, error) {
	b, err := s.f.download(ctx, s.f.cfg.EndOfLifeURL, 128<<20)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Result []eolProduct `json:"result"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse endoflife.date: %w", err)
	}
	if len(doc.Result) == 0 {
		return nil, errors.New("endoflife.date returned no products; refusing to clear existing data")
	}
	var products, cycles [][]any
	for _, p := range doc.Result {
		purls := []string{}
		for _, id := range p.Identifiers {
			if id.Type == "purl" {
				purls = append(purls, strings.ToLower(id.ID))
			}
		}
		products = append(products, []any{p.Name, p.Label, purls, p.Links.HTML})
		seen := map[string]bool{}
		for _, r := range p.Releases {
			if r.Name == "" || seen[r.Name] {
				continue
			}
			seen[r.Name] = true
			latest, latestDate := "", (*time.Time)(nil)
			if r.Latest != nil {
				latest, latestDate = r.Latest.Name, parseDate(r.Latest.Date)
			}
			var support, eol *time.Time
			if r.EOASFrom != nil {
				support = parseDate(*r.EOASFrom)
			}
			if r.EOLFrom != nil {
				eol = parseDate(*r.EOLFrom)
			}
			cycles = append(cycles, []any{p.Name, r.Name, r.Label, parseDate(r.ReleaseDate), r.IsLTS, support, eol, r.IsEOL, latest, latestDate})
		}
	}
	if err := s.Store.ReplaceLifecycle(ctx, products, cycles); err != nil {
		return nil, err
	}
	_ = s.Store.SetFeedRecords(ctx, FeedEndOfLife, int64(len(products)))
	return &SyncResult{Changed: len(products), Full: true}, nil
}

// --- registries

// npm and Packagist lookups; syncReleases and the other registries are in
// releases.go.

func (s *Syncer) npmRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	name := c.Name
	if c.Namespace != "" {
		name = c.Namespace + "/" + c.Name
	}
	u := strings.TrimSuffix(s.f.cfg.NpmRegistry, "/") + "/" + url.PathEscape(name)
	r := store.Release{Source: FeedNpm, SourceURL: "https://www.npmjs.com/package/" + name}
	// The full document carries publish times; it is large for popular
	// packages, so it is size-capped.
	b, err := s.f.download(ctx, u, 64<<20)
	if err != nil {
		return r, err
	}
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
		Time     map[string]string `json:"time"`
		Versions map[string]struct {
			Deprecated any `json:"deprecated"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return r, err
	}
	r.Latest = doc.DistTags["latest"]
	r.LatestStable = latestStableSemver(keys(doc.Versions), r.Latest)
	var stable []string
	for v := range doc.Versions {
		if !version.SemverPrerelease(v) {
			stable = append(stable, v)
		}
	}
	r.StableVersions = sortedVersions(version.CompareSemver, stable)
	r.VersionDates = map[string]string{}
	for v, t := range doc.Time {
		if v == "created" || v == "modified" {
			continue
		}
		if _, ok := doc.Versions[v]; ok {
			r.VersionDates[v] = t
		}
	}
	if t, err := time.Parse(time.RFC3339, doc.Time[r.LatestStable]); err == nil {
		r.LatestPublished = &t
	}
	if v, ok := doc.Versions[r.Latest]; ok {
		if msg, ok := v.Deprecated.(string); ok {
			r.Deprecated = msg
		}
	}
	return r, nil
}

func (s *Syncer) packagistRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	name := c.Namespace + "/" + c.Name
	r := store.Release{Source: FeedPackagist, SourceURL: "https://packagist.org/packages/" + name}
	b, err := s.f.download(ctx, strings.TrimSuffix(s.f.cfg.PackagistURL, "/")+"/p2/"+name+".json", 32<<20)
	if err != nil {
		return r, err
	}
	var doc struct {
		Packages map[string][]struct {
			Version string `json:"version"`
			Time    string `json:"time"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return r, err
	}
	r.VersionDates = map[string]string{}
	var stable []string
	for _, v := range doc.Packages[name] {
		ver := strings.TrimPrefix(v.Version, "v")
		r.VersionDates[ver] = v.Time
		if r.Latest == "" {
			r.Latest = ver // p2 lists newest first
		}
		if isStableComposer(ver) {
			stable = append(stable, ver)
		}
	}
	r.LatestStable = latestComposer(stable)
	r.StableVersions = sortedVersions(version.CompareComposer, stable)
	if t, err := time.Parse(time.RFC3339, r.VersionDates[r.LatestStable]); err == nil {
		r.LatestPublished = &t
	}
	return r, nil
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
