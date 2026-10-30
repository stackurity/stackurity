//go:build measure

package intel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// TestMeasureWindowsPrograms reads NVD answers saved under
// $STACKURITY_NVD_DIR (one JSON array of {"cve": ...} per CPE product,
// named cpe_2.3_a_<vendor>_<product>.json) and reports, per catalogued
// program, what the converter makes of them: usable CVEs, skipped
// configurations, and the newest CVE read. It is how each entry's source
// was checked:
//
//	STACKURITY_NVD_DIR=/path go test -tags measure ./internal/intel -run TestMeasureWindowsPrograms -v
func TestMeasureWindowsPrograms(t *testing.T) {
	dir := os.Getenv("STACKURITY_NVD_DIR")
	if dir == "" {
		t.Skip("STACKURITY_NVD_DIR not set")
	}
	for _, p := range winprograms.Default().Programs() {
		if p.Source == nil || p.Source.Type != winprograms.SourceNVD {
			continue
		}
		anomalies := nvdAnomalies{}
		byCVE := map[string]*osv.Vulnerability{}
		listed, missing := 0, []string{}
		for _, cpe := range p.Source.CPEs {
			f := winprograms.SplitCPE(cpe)
			name := "cpe_2.3_a_" + f[3] + "_" + strings.ReplaceAll(f[4], `\`, "") + ".json"
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				missing = append(missing, name)
				continue
			}
			var items []nvdWrapped
			if err := json.Unmarshal(b, &items); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			for _, it := range items {
				listed++
				if v := nvdRecord(p, it.CVE, anomalies); v != nil {
					byCVE[it.CVE.ID] = v
				}
			}
		}
		var ids []string
		recent, exactOnly, recentExact := 0, 0, 0
		for id, v := range byCVE {
			ids = append(ids, id)
			if v.Published.Year() >= 2024 {
				recent++
			}
			if len(v.Affected[0].Ranges) == 0 {
				exactOnly++
				if v.Published.Year() >= 2024 {
					recentExact++
				}
			}
		}
		sort.Slice(ids, func(i, j int) bool { return byCVE[ids[i]].Published.Before(byCVE[ids[j]].Published) })
		newest := ""
		if len(ids) > 0 {
			v := byCVE[ids[len(ids)-1]]
			newest = v.Aliases[0] + " " + v.Published.Format("2006-01-02")
			if r := v.Affected[0].Ranges; len(r) > 0 {
				newest += " " + strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(func() string { b, _ := json.Marshal(r[0].Events); return string(b) }(), `"`, ""), ",", " "))
			}
		}
		t.Logf("%-22s listed %5d usable %5d (since 2024: %4d, exact versions only: %4d, of them since 2024: %3d) skipped: %s; newest %s; missing files %v",
			p.ID, listed, len(byCVE), recent, exactOnly, recentExact, anomalies.String(), newest, missing)
	}
}
