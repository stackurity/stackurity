package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
)

// Amazon Linux publishes its security advisories (ALAS) as updateinfo.xml in
// each package repository. Amazon Linux 2023 has one core repository.
// Amazon Linux 2 has a core repository plus "extras" topics, each a separate
// repository for one version line of a product (kernel-5.10, php8.2,
// postgresql14). Extras packages share names with other lines (kernel 4.14
// in core, 5.10 and 5.15 in extras), so an extras advisory is limited to its
// own line: a kernel-5.10 fix never marks a 4.14 kernel affected. Topics
// without a version in their name cannot be limited that way and are not
// read; their packages are matched against core advisories only.

type alasRepo struct {
	release string // "2" or "2023"
	topic   string // extras topic, "" for core
	stream  string // version line of an extras topic, e.g. "5.10"
	mirror  string // mirror.list URL
}

// topicStream is the trailing version of an extras topic name.
var topicStream = regexp.MustCompile(`(\d+(?:\.\d+)*)$`)

func (s *Syncer) syncAmazonLinux(ctx context.Context, feed string) (*SyncResult, error) {
	base := strings.TrimSuffix(s.f.cfg.AmazonLinuxURL, "/")
	repos := []alasRepo{
		{release: "2023", mirror: base + "/al2023/core/mirrors/latest/x86_64/mirror.list"},
		{release: "2", mirror: base + "/2/core/latest/x86_64/mirror.list"},
	}
	topics, err := s.amazonLinuxTopics(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("Amazon Linux 2 extras catalogue: %w", err)
	}
	repos = append(repos, topics...)

	byID := map[string]*osv.Vulnerability{}
	var order []string
	var failed []string
	for _, r := range repos {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		vulns, err := s.readUpdateInfo(ctx, base, r)
		if err != nil {
			if r.topic == "" {
				return nil, fmt.Errorf("Amazon Linux %s core repository: %w", r.release, err)
			}
			s.Log.Warn("Amazon Linux extras topic unreadable", "topic", r.topic, "err", err)
			failed = append(failed, r.topic)
			continue
		}
		for _, v := range vulns {
			if cur, ok := byID[v.ID]; ok {
				cur.Affected = append(cur.Affected, v.Affected...)
				continue
			}
			byID[v.ID] = v
			order = append(order, v.ID)
		}
	}

	res := &SyncResult{Full: true, Packages: map[store.PackageRef]bool{}}
	for i := 0; i < len(order); i += osvBatch {
		end := min(i+osvBatch, len(order))
		batch := make([]*osv.Vulnerability, 0, end-i)
		for _, id := range order[i:end] {
			batch = append(batch, byID[id])
		}
		touched, err := s.Store.UpsertAdvisories(ctx, feed, batch)
		if err != nil {
			return nil, err
		}
		for p := range touched {
			res.Packages[p] = true
		}
		res.Changed += len(batch)
	}
	_ = s.Store.SetFeedRecords(ctx, feed, int64(len(order)))
	if len(failed) > 0 {
		// What was read is stored; the feed reports the failure and retries.
		return res, fmt.Errorf("%d Amazon Linux 2 extras topics could not be read: %s", len(failed), strings.Join(failed, ", "))
	}
	return res, nil
}

// amazonLinuxTopics lists the Amazon Linux 2 extras topics whose name ends
// in a version.
func (s *Syncer) amazonLinuxTopics(ctx context.Context, base string) ([]alasRepo, error) {
	b, err := s.f.download(ctx, base+"/2/extras-catalog-x86_64-v2.json", 8<<20)
	if err != nil {
		return nil, err
	}
	var cat struct {
		Topics []struct {
			Name string `json:"n"`
		} `json:"topics"`
	}
	if err := json.Unmarshal(b, &cat); err != nil {
		return nil, err
	}
	var out []alasRepo
	for _, t := range cat.Topics {
		m := topicStream.FindString(t.Name)
		if m == "" || strings.ContainsAny(t.Name, "/?#") {
			continue
		}
		out = append(out, alasRepo{release: "2", topic: t.Name, stream: m,
			mirror: base + "/2/extras/" + url.PathEscape(t.Name) + "/latest/x86_64/mirror.list"})
	}
	return out, nil
}

// readUpdateInfo follows mirror.list -> repodata/repomd.xml -> updateinfo
// and converts the security updates.
func (s *Syncer) readUpdateInfo(ctx context.Context, base string, r alasRepo) ([]*osv.Vulnerability, error) {
	ml, err := s.f.download(ctx, r.mirror, 64<<10)
	if err != nil {
		return nil, err
	}
	repo := firstLine(ml)
	if !sameHost(repo, base) {
		return nil, fmt.Errorf("mirror list points outside %s: %q", base, repo)
	}
	repo = strings.TrimSuffix(repo, "/") + "/"
	md, err := s.f.download(ctx, repo+"repodata/repomd.xml", 4<<20)
	if err != nil {
		return nil, err
	}
	var repomd struct {
		Data []struct {
			Type     string `xml:"type,attr"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(md, &repomd); err != nil {
		return nil, fmt.Errorf("parse repomd.xml: %w", err)
	}
	href := ""
	for _, d := range repomd.Data {
		if d.Type == "updateinfo" {
			href = d.Location.Href
		}
	}
	if href == "" {
		return nil, nil // a repository that never had an advisory
	}
	if strings.Contains(href, "..") || strings.Contains(href, "://") {
		return nil, fmt.Errorf("repomd.xml has an unusable updateinfo location (%q)", href)
	}
	resp, err := s.f.get(ctx, repo+href, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body io.Reader = io.LimitReader(resp.Body, 256<<20)
	if strings.HasSuffix(href, ".gz") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		body = gz
	}
	return parseUpdateInfo(io.LimitReader(body, 1<<30), r)
}

func firstLine(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}

func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host && ua.Host != ""
}

type updateInfo struct {
	Type     string `xml:"type,attr"`
	ID       string `xml:"id"`
	Title    string `xml:"title"`
	Severity string `xml:"severity"`
	Issued   struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	Updated struct {
		Date string `xml:"date,attr"`
	} `xml:"updated"`
	Description string `xml:"description"`
	References  []struct {
		Href string `xml:"href,attr"`
		ID   string `xml:"id,attr"`
		Type string `xml:"type,attr"`
	} `xml:"references>reference"`
	Packages []struct {
		Name    string `xml:"name,attr"`
		Epoch   string `xml:"epoch,attr"`
		Version string `xml:"version,attr"`
		Release string `xml:"release,attr"`
		Arch    string `xml:"arch,attr"`
	} `xml:"pkglist>collection>package"`
}

// parseUpdateInfo streams <update> elements and returns security updates
// as OSV records for the repository's release.
func parseUpdateInfo(r io.Reader, repo alasRepo) ([]*osv.Vulnerability, error) {
	dec := xml.NewDecoder(r)
	eco := "Amazon Linux:" + repo.release
	var out []*osv.Vulnerability
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse updateinfo: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "update" {
			continue
		}
		var u updateInfo
		if err := dec.DecodeElement(&u, &se); err != nil {
			return nil, fmt.Errorf("parse updateinfo: %w", err)
		}
		if v := alasRecord(u, eco, repo); v != nil {
			out = append(out, v)
		}
	}
}

func alasRecord(u updateInfo, eco string, repo alasRepo) *osv.Vulnerability {
	if u.Type != "security" || !strings.HasPrefix(u.ID, "ALAS") {
		return nil
	}
	v := &osv.Vulnerability{ID: u.ID, Summary: strings.TrimSpace(u.Title), Details: truncate(strings.TrimSpace(u.Description), 8000)}
	v.Published = alasTime(u.Issued.Date)
	v.Modified = alasTime(u.Updated.Date)
	if v.Modified.IsZero() {
		v.Modified = v.Published
	}
	page := "AL2"
	if repo.release == "2023" {
		page = "AL2023"
	}
	v.References = append(v.References, osv.Reference{Type: "ADVISORY", URL: "https://alas.aws.amazon.com/" + page + "/" + url.PathEscape(u.ID) + ".html"})
	for _, ref := range u.References {
		if ref.Type == "cve" && strings.HasPrefix(ref.ID, "CVE-") {
			v.Aliases = append(v.Aliases, ref.ID)
			v.References = append(v.References, osv.Reference{Type: "WEB", URL: "https://www.cve.org/CVERecord?id=" + url.QueryEscape(ref.ID)})
		}
	}
	if sev := strings.TrimSpace(u.Severity); sev != "" {
		v.DatabaseSpecific, _ = json.Marshal(map[string]string{"severity": sev})
	}
	seen := map[string]bool{}
	for _, p := range u.Packages {
		if p.Name == "" || p.Version == "" || p.Release == "" || p.Arch == "src" || seen[p.Name] {
			continue
		}
		epoch := p.Epoch
		if epoch == "" {
			epoch = "0"
		}
		introduced := "0"
		if repo.stream != "" {
			if p.Version != repo.stream && !strings.HasPrefix(p.Version, repo.stream+".") {
				continue // a package outside the topic's version line
			}
			introduced = repo.stream
			if epoch != "0" {
				introduced = epoch + ":" + introduced
			}
		}
		seen[p.Name] = true
		v.Affected = append(v.Affected, osv.Affected{
			Package: osv.Package{Ecosystem: eco, Name: p.Name},
			Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{
				{Introduced: introduced}, {Fixed: epoch + ":" + p.Version + "-" + p.Release},
			}}},
		})
	}
	if len(v.Affected) == 0 {
		return nil
	}
	return v
}

func alasTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
