//go:build measure

package intel

// TestMeasureELSA parses Oracle's real ELSA files and reports what each
// gives. It is not part of the normal test run:
//
//	STACKURITY_MEASURE_ELSA=/path/to/oval go test -tags measure -run TestMeasureELSA -v ./internal/intel
//
// /path/to/oval holds com.oracle.elsa-ol<N>.xml.bz2 as published at
// https://linux.oracle.com/security/oval/.

import (
	"compress/bzip2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMeasureELSA(t *testing.T) {
	dir := os.Getenv("STACKURITY_MEASURE_ELSA")
	if dir == "" {
		t.Skip("STACKURITY_MEASURE_ELSA not set")
	}
	for _, rel := range []string{"6", "7", "8", "9", "10"} {
		f, err := os.Open(filepath.Join(dir, "com.oracle.elsa-ol"+rel+".xml.bz2"))
		if err != nil {
			t.Logf("Oracle Linux %s: %v", rel, err)
			continue
		}
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		// Peak heap, sampled while the file is parsed.
		var peak uint64
		done, sampled := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(sampled)
			for {
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				peak = max(peak, m.HeapAlloc)
				select {
				case <-done:
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		}()
		doc, err := parseELSA(bzip2.NewReader(f), rel)
		close(done)
		<-sampled
		f.Close()
		if err != nil {
			t.Fatalf("Oracle Linux %s: %v", rel, err)
		}
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		entries, ksplice, fips, lines, cves := 0, 0, 0, 0, 0
		for _, v := range doc.vulns {
			cves += len(v.Aliases) - 1
			for _, a := range v.Affected {
				entries++
				switch {
				case strings.HasSuffix(a.Package.Ecosystem, ":ksplice"):
					ksplice++
				case strings.HasSuffix(a.Package.Ecosystem, ":fips"):
					fips++
				}
				if a.Ranges[0].Events[0].Introduced != "0" {
					lines++
				}
			}
		}
		t.Logf("Oracle Linux %s: %d advisories, %d CVE aliases, %d entries (%d Ksplice, %d FIPS, %d limited to a line), %d criteria not understood, %s, %d MiB allocated, peak heap %d MiB",
			rel, len(doc.vulns), cves, entries, ksplice, fips, lines, doc.anomalies, time.Since(start).Round(time.Millisecond),
			(after.TotalAlloc-before.TotalAlloc)>>20, (peak-min(peak, before.HeapAlloc))>>20)
	}
}
