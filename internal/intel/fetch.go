// Package intel refreshes vulnerability, release and lifecycle data from
// upstream sources and evaluates inventory against it. Refreshing data never
// changes any asset (PRD FR-17: detection is independent of remediation).
package intel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Config holds source locations so installations can point at mirrors or
// offline copies (FR-05).
type Config struct {
	OSVBaseURL       string // https://storage.googleapis.com/osv-vulnerabilities
	KEVURL           string
	EPSSURL          string // https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
	EndOfLifeURL     string // https://endoflife.date/api/v1/products/full
	NpmRegistry      string // https://registry.npmjs.org
	PackagistURL     string // https://repo.packagist.org
	AmazonLinuxURL   string // https://cdn.amazonlinux.com
	OracleLinuxURL   string // https://linux.oracle.com/security/oval (ELSA OVAL files)
	PyPIURL          string // https://pypi.org
	GoProxyURL       string // https://proxy.golang.org
	CratesIndexURL   string // https://index.crates.io (the sparse index)
	RubyGemsURL      string // https://rubygems.org
	NuGetURL         string // https://api.nuget.org/v3/registration5-gz-semver2
	MavenURL         string // https://repo1.maven.org/maven2
	PubURL           string // https://pub.dev
	HexURL           string // https://hex.pm
	MSRCURL          string // https://api.msrc.microsoft.com/cvrf/v3.0 (Security Update Guide)
	MSRCMonths       int    // months of Security Update Guide documents read (DefaultMSRCMonths)
	WorkDir          string // temp space for bulk downloads
	UserAgent        string
	IncrementalLimit int // above this many changed records, re-download the full archive

	// NVD's CVE API, read for the curated Windows program catalogue.
	NVDURL     string        // DefaultNVDURL
	NVDAPIKey  string        // optional; raises NVD's rate limit
	NVDDelay   time.Duration // wait before each request (NVD asks for about 6 s without a key)
	NVDBackoff time.Duration // wait after NVD refuses a request for the rate
	MozillaURL string        // DefaultMozillaURL: Mozilla's security advisories
}

func DefaultConfig() Config {
	return Config{
		OSVBaseURL: "https://storage.googleapis.com/osv-vulnerabilities",
		KEVURL:     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		// FIRST publishes EPSS through Empirical Security, which redirects
		// "current" to the day's file (epss_scores-YYYY-MM-DD.csv.gz).
		EPSSURL:          "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		EndOfLifeURL:     "https://endoflife.date/api/v1/products/full",
		NpmRegistry:      "https://registry.npmjs.org",
		PackagistURL:     "https://repo.packagist.org",
		AmazonLinuxURL:   "https://cdn.amazonlinux.com",
		OracleLinuxURL:   "https://linux.oracle.com/security/oval",
		PyPIURL:          "https://pypi.org",
		GoProxyURL:       "https://proxy.golang.org",
		CratesIndexURL:   "https://index.crates.io",
		RubyGemsURL:      "https://rubygems.org",
		NuGetURL:         "https://api.nuget.org/v3/registration5-gz-semver2",
		MavenURL:         "https://repo1.maven.org/maven2",
		PubURL:           "https://pub.dev",
		HexURL:           "https://hex.pm",
		MSRCURL:          "https://api.msrc.microsoft.com/cvrf/v3.0",
		MSRCMonths:       DefaultMSRCMonths,
		WorkDir:          os.TempDir(),
		UserAgent:        "stackurity",
		IncrementalLimit: 5000,
		NVDURL:           DefaultNVDURL,
		NVDDelay:         6500 * time.Millisecond,
		NVDBackoff:       35 * time.Second,
		MozillaURL:       DefaultMozillaURL,
	}
}

type fetcher struct {
	cfg  Config
	http *http.Client
}

func newFetcher(cfg Config) *fetcher {
	return &fetcher{cfg: cfg, http: &http.Client{Timeout: 30 * time.Minute}}
}

type statusError struct {
	URL    string
	Status int
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

// get performs a GET with retries on transient failures. The caller closes
// the body.
func (f *fetcher) get(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", f.cfg.UserAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := f.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 304 && conditional(headers) {
			return resp, nil
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		lastErr = &statusError{url, resp.StatusCode}
		if resp.StatusCode != 429 && resp.StatusCode < 500 {
			return nil, lastErr // 404 and friends are not transient
		}
	}
	return nil, lastErr
}

func conditional(headers map[string]string) bool {
	return headers["If-None-Match"] != "" || headers["If-Modified-Since"] != ""
}

func (f *fetcher) download(ctx context.Context, url string, max int64) ([]byte, error) {
	b, _, _, err := f.downloadIfChanged(ctx, url, validators{}, max)
	return b, err
}

// validators identify the copy of a file last read, for a conditional GET.
type validators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// downloadIfChanged is download with a conditional GET: when the server
// says the file has not changed since the copy prev describes (HTTP 304),
// it returns unchanged and no body. Otherwise it returns the file and its
// validators, which are empty when the server sends none.
func (f *fetcher) downloadIfChanged(ctx context.Context, url string, prev validators, max int64) (b []byte, next validators, unchanged bool, err error) {
	headers := map[string]string{}
	if prev.ETag != "" {
		headers["If-None-Match"] = prev.ETag
	}
	if prev.LastModified != "" {
		headers["If-Modified-Since"] = prev.LastModified
	}
	resp, err := f.get(ctx, url, headers)
	if err != nil {
		return nil, prev, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 {
		return nil, prev, true, nil
	}
	b, err = io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, prev, false, err
	}
	if int64(len(b)) > max {
		return nil, prev, false, fmt.Errorf("GET %s: response larger than %d bytes", url, max)
	}
	return b, validators{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}, false, nil
}
