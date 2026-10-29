package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// --- FIRST EPSS

// Size caps for the EPSS file: about 3 MB compressed and 13 MB of CSV for
// 400,000 CVEs in 2026, so these leave room for years of growth while
// stopping a runaway or hostile mirror (a gzip bomb) early.
const epssMaxDownload = 64 << 20

var epssMaxCSV int64 = 256 << 20 // a variable so tests can lower it

// syncEPSS reads FIRST's daily EPSS file (cve,epss,percentile, after a
// "#model_version:...,score_date:..." line) and replaces the stored scores.
// The same file twice (same model and day) changes nothing. Nothing about
// the inventory is sent: it is one bulk download. Scores change priorities
// only, which the next prioritisation reads from the table, so the sync
// queues no re-evaluation.
func (s *Syncer) syncEPSS(ctx context.Context) (*SyncResult, error) {
	b, err := s.f.download(ctx, s.f.cfg.EPSSURL, epssMaxDownload)
	if err != nil {
		return nil, err
	}
	var r io.Reader = bytes.NewReader(b)
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("EPSS file: %w", err)
		}
		defer zr.Close()
		r = zr
	}
	lr := &capReader{r: r, left: epssMaxCSV}
	br := bufio.NewReader(lr)
	model, date, err := readEPSSPreamble(br)
	if err != nil {
		return nil, err
	}
	storedModel, storedDate, err := s.Store.EPSSFile(ctx)
	if err != nil {
		return nil, err
	}
	if model == storedModel && date.Equal(storedDate) {
		return &SyncResult{Full: true}, nil // already stored
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = 3
	cr.ReuseRecord = true
	skipped := 0
	next := func() (*store.EPSSRow, error) {
		for {
			rec, err := cr.Read()
			if err == io.EOF {
				return nil, nil
			}
			if err != nil {
				return nil, fmt.Errorf("EPSS file: %w", err)
			}
			row, ok := parseEPSSRow(rec)
			if !ok {
				skipped++
				continue
			}
			return row, nil
		}
	}
	n, err := s.Store.ReplaceEPSS(ctx, model, date, next)
	if err != nil {
		return nil, err
	}
	if skipped > 0 {
		s.Log.Warn("EPSS rows skipped (not a CVE, or a score outside 0 to 1)", "feed", FeedEPSS, "rows", skipped)
	}
	_ = s.Store.SetFeedRecords(ctx, FeedEPSS, n)
	return &SyncResult{Changed: int(n), Full: true}, nil
}

// readEPSSPreamble reads the model and score date from the comment line and
// checks the column header. EPSS files since model v2 (2022) start with
// "#model_version:v2023.03.01,score_date:2023-03-07T00:00:00+0000".
func readEPSSPreamble(br *bufio.Reader) (model string, date time.Time, err error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", time.Time{}, fmt.Errorf("EPSS file: no header: %w", err)
	}
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if !strings.HasPrefix(line, "#") {
		return "", time.Time{}, errors.New("EPSS file: the first line is not #model_version:...,score_date:...")
	}
	for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
		k, v, _ := strings.Cut(part, ":")
		switch strings.TrimSpace(k) {
		case "model_version":
			model = strings.TrimSpace(v)
		case "score_date":
			v = strings.TrimSpace(v)
			if len(v) >= 10 {
				date, err = time.Parse("2006-01-02", v[:10])
			}
		}
	}
	if model == "" || date.IsZero() || err != nil {
		return "", time.Time{}, fmt.Errorf("EPSS file: unreadable model or score date in %q", truncate(line, 120))
	}
	header, err := br.ReadString('\n')
	if err != nil {
		return "", time.Time{}, fmt.Errorf("EPSS file: no column header: %w", err)
	}
	if strings.TrimSpace(header) != "cve,epss,percentile" {
		return "", time.Time{}, fmt.Errorf("EPSS file: unexpected columns %q (want cve,epss,percentile)", truncate(strings.TrimSpace(header), 120))
	}
	return model, date, nil
}

func parseEPSSRow(rec []string) (*store.EPSSRow, bool) {
	cve := strings.TrimSpace(rec[0])
	if !strings.HasPrefix(cve, "CVE-") || len(cve) > 32 {
		return nil, false
	}
	score, err1 := strconv.ParseFloat(strings.TrimSpace(rec[1]), 32)
	pct, err2 := strconv.ParseFloat(strings.TrimSpace(rec[2]), 32)
	if err1 != nil || err2 != nil || !(score >= 0 && score <= 1) || !(pct >= 0 && pct <= 1) {
		return nil, false
	}
	return &store.EPSSRow{CVE: cve, Score: float32(score), Percentile: float32(pct)}, true
}

// capReader fails once more than left bytes are read, so a decompressed
// stream cannot grow without bound.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, fmt.Errorf("EPSS file larger than %d bytes uncompressed", epssMaxCSV)
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}
