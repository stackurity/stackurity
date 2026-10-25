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
	EndOfLifeURL     string // https://endoflife.date/api/v1/products/full
	NpmRegistry      string // https://registry.npmjs.org
	PackagistURL     string // https://repo.packagist.org
	WorkDir          string // temp space for bulk downloads
	UserAgent        string
	IncrementalLimit int // above this many changed records, re-download the full archive
}

func DefaultConfig() Config {
	return Config{
		OSVBaseURL:       "https://storage.googleapis.com/osv-vulnerabilities",
		KEVURL:           "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		EndOfLifeURL:     "https://endoflife.date/api/v1/products/full",
		NpmRegistry:      "https://registry.npmjs.org",
		PackagistURL:     "https://repo.packagist.org",
		WorkDir:          os.TempDir(),
		UserAgent:        "stackurity",
		IncrementalLimit: 5000,
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
		if resp.StatusCode == 200 {
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

func (f *fetcher) download(ctx context.Context, url string, max int64) ([]byte, error) {
	resp, err := f.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", url, max)
	}
	return b, nil
}
