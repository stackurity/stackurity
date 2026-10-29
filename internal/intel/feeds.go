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
	"slices"
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
	FeedEPSS      = "epss:first"
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
	switch baseEcosystem {
	case "Amazon Linux":
		return FeedAmazonLinux
	case "Windows":
		return FeedMSRC
	}
	return OSVFeed(baseEcosystem)
}

func osvBase(feed string) string {
	b, _ := feedEcosystem(feed)
	return b
}

// feedEcosystem returns the base ecosystem a vulnerability feed covers.
func feedEcosystem(feed string) (string, bool) {
	switch feed {
	case FeedAmazonLinux:
		return "Amazon Linux", true
	case FeedMSRC:
		return "Windows", true
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
	// Tests: batchLimits overrides osvBatch and osvBatchBytes; onBatch sees
	// each batch of OSV records before it is stored.
	batchLimits func() (count int, bytes int64)
	onBatch     func(count int, bytes int64)
	// now, in tests, is the time the Windows updates window is read at.
	now func() time.Time
}

func (s *Syncer) clock() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func NewSyncer(s *store.Store, log *slog.Logger, cfg Config) *Syncer {
	return &Syncer{Store: s, Log: log, f: newFetcher(cfg)}
}

// SyncResult tells the caller which packages changed so it can re-evaluate
// only what is affected.
type SyncResult struct {
	// Changed counts the records whose stored data changed (for a
	// vulnerability feed, advisories written; unchanged ones are skipped).
	Changed int
	// Packages lists the packages of the feed's ecosystem whose advisory
	// data changed and that no successful sync has handed to
	// re-evaluation yet: their components are re-evaluated.
	Packages map[store.PackageRef]bool
	// Full means the sync read the source's complete data (an archive, not
	// the changes since the cursor), so Ecosystems is complete.
	Full bool
	// All asks for every component of the feed's ecosystem to be
	// re-evaluated, not only Packages: the feed's coverage changed (a
	// release was added or dropped), or it was stale or had never synced,
	// so every finding's feed state changes.
	All bool
	// Ecosystems seen in the records read, e.g. "Debian:12".
	Ecosystems map[string]bool
	// Warning is a problem the sync worked around (a source document it
	// could not read and kept as last read): the sync succeeds and the feed
	// shows the warning as its last error until a sync without one.
	Warning string
}

// noteEcosystems records the ecosystem strings of base that vs name.
func (r *SyncResult) noteEcosystems(base string, vs []*osv.Vulnerability) {
	if r.Ecosystems == nil {
		r.Ecosystems = map[string]bool{}
	}
	for _, v := range vs {
		for _, a := range v.Affected {
			if a.Package.Ecosystem != "" && osv.BaseEcosystem(a.Package.Ecosystem) == base {
				r.Ecosystems[a.Package.Ecosystem] = true
			}
		}
	}
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
	case name == FeedMSRC:
		res, cursor, err = s.syncMSRC(ctx, name, feed.Cursor)
	case name == FeedKEV:
		res, err = s.syncKEV(ctx)
	case name == FeedEPSS:
		res, err = s.syncEPSS(ctx)
	case name == FeedEndOfLife:
		res, err = s.syncEndOfLife(ctx)
	case isReleaseFeed(name):
		res, err = s.syncReleases(ctx, name)
	default:
		err = fmt.Errorf("unknown feed %q", name)
	}
	var pending *store.Pending
	if base, vuln := feedEcosystem(name); vuln && err == nil && res != nil {
		pending, err = s.collectPending(ctx, feed, base, res)
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
	if err == nil && res != nil && res.Warning != "" {
		if werr := s.Store.FeedWarning(context.WithoutCancel(ctx), name, res.Warning); werr != nil {
			err = werr
		}
	}
	if base, ok := feedEcosystem(name); ok && err == nil {
		// Re-evaluation of the pending packages is queued: they are done.
		// If this fails or the server dies first, the next sync queues
		// them again.
		if cerr := s.Store.ClearPending(context.WithoutCancel(ctx), base, pending); cerr != nil {
			s.Log.Warn("clearing packages queued for re-evaluation", "feed", name, "err", cerr)
		}
	}
	if base, ok := feedEcosystem(name); ok && err == nil && res != nil {
		// Which releases the feed covers, so a release it has nothing for
		// is reported as not evaluated rather than clean.
		if rerr := s.Store.UpdateFeedEcosystems(ctx, name, base, keys(res.Ecosystems), res.Full); rerr != nil {
			err = rerr
		}
	}
	return res, err
}

// collectPending sets what a vulnerability feed's sync re-evaluates: the
// packages of its ecosystem whose advisory data changed and have not been
// handed to re-evaluation yet (recorded with the advisories, so records
// written by an interrupted attempt, or by another feed's sync of an
// advisory that also covers this ecosystem, are included although this
// sync found them unchanged), or everything when the feed's coverage or
// state changed. feed is the feed as it was before the sync.
func (s *Syncer) collectPending(ctx context.Context, feed *store.Feed, base string, res *SyncResult) (*store.Pending, error) {
	pending, err := s.Store.PendingPackages(ctx, base)
	if err != nil {
		return nil, err
	}
	if res.Packages == nil {
		res.Packages = map[store.PackageRef]bool{}
	}
	for p := range pending.Packages {
		res.Packages[p] = true
	}
	switch {
	case feed.LastSuccess == nil || feed.Stale || feed.Ecosystems == nil:
		res.All = true
	case res.Full:
		res.All = !sameSet(feed.Ecosystems, res.Ecosystems)
	default:
		for e := range res.Ecosystems {
			if !slices.Contains(feed.Ecosystems, e) {
				res.All = true
			}
		}
	}
	return pending, nil
}

func sameSet(list []string, set map[string]bool) bool {
	n := 0
	for _, e := range list {
		if !set[e] {
			return false
		}
		n++
	}
	return n == len(set)
}

// --- OSV

// OSV records are stored in batches of at most osvBatch records and about
// osvBatchBytes of JSON, and an incremental sync has at most osvFetchers
// records in flight, so a sync holds a bounded amount of advisory data
// whatever the number or size of the records that changed. Record sizes vary
// by three orders of magnitude: an Ubuntu kernel record can list every
// kernel flavour and run to several megabytes, and when Ubuntu republished
// 4,815 records (2.1 GB of JSON) the sync that held them all at once ran the
// server out of memory.
const (
	osvBatch      = 500
	osvBatchBytes = 16 << 20
	osvFetchers   = 8
)

// osvBatcher collects records and stores them a batch at a time.
type osvBatcher struct {
	ctx      context.Context
	s        *Syncer
	feed     string
	res      *SyncResult
	maxCount int
	maxBytes int64
	batch    []*osv.Vulnerability
	bytes    int64
}

func (s *Syncer) newBatcher(ctx context.Context, feed string, res *SyncResult) *osvBatcher {
	b := &osvBatcher{ctx: ctx, s: s, feed: feed, res: res, maxCount: osvBatch, maxBytes: osvBatchBytes}
	if s.batchLimits != nil {
		b.maxCount, b.maxBytes = s.batchLimits()
	}
	return b
}

// add queues a record of size bytes (its JSON), storing the batch when it
// is full.
func (b *osvBatcher) add(v *osv.Vulnerability, size int64) error {
	b.batch = append(b.batch, v)
	b.bytes += size
	if len(b.batch) >= b.maxCount || b.bytes >= b.maxBytes {
		return b.flush()
	}
	return nil
}

func (b *osvBatcher) flush() error {
	if len(b.batch) == 0 {
		return nil
	}
	if b.s.onBatch != nil {
		b.s.onBatch(len(b.batch), b.bytes)
	}
	n, err := b.s.Store.UpsertAdvisories(b.ctx, b.feed, b.batch)
	if err != nil {
		return err
	}
	b.res.noteEcosystems(osvBase(b.feed), b.batch)
	b.res.Changed += n
	// The records are not kept: clear the slots so they can be collected.
	clear(b.batch)
	b.batch, b.bytes = b.batch[:0], 0
	return nil
}

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
	b := s.newBatcher(ctx, feed, res)
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
		if err := b.add(v, int64(zf.UncompressedSize64)); err != nil {
			return nil, "", err
		}
	}
	if err := b.flush(); err != nil {
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
	// The records are fetched osvFetchers at a time and stored as batches
	// fill, never all held at once. A failure keeps the old cursor, so the
	// next sync fetches them all again; those already stored are unchanged
	// then, and the packages they touched are still queued for
	// re-evaluation (collectPending).
	b := s.newBatcher(ctx, feed, res)
	type fetched struct {
		v    *osv.Vulnerability
		size int64
		err  error
	}
	window := make([]fetched, osvFetchers)
	for start := 0; start < len(ids); start += osvFetchers {
		part := ids[start:min(start+osvFetchers, len(ids))]
		var wg sync.WaitGroup
		for i, id := range part {
			wg.Add(1)
			go func() {
				defer wg.Done()
				raw, err := s.f.download(ctx, base+"/"+url.PathEscape(id)+".json", 64<<20)
				if err != nil {
					window[i] = fetched{err: err}
					return
				}
				var v osv.Vulnerability
				if err := json.Unmarshal(raw, &v); err != nil {
					window[i] = fetched{err: err}
					return
				}
				window[i] = fetched{v: &v, size: int64(len(raw))}
			}()
		}
		wg.Wait()
		for i, f := range window[:len(part)] {
			window[i] = fetched{}
			if f.err != nil {
				var se *statusError
				if errors.As(f.err, &se) && se.Status == 404 {
					continue // record moved or removed upstream
				}
				return nil, "", fmt.Errorf("fetch %s: %w", part[i], f.err)
			}
			if err := b.add(f.v, f.size); err != nil {
				return nil, "", err
			}
		}
	}
	if err := b.flush(); err != nil {
		return nil, "", err
	}
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
