package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
)

// nvdCatalogueProduct is one product of a curated catalogue whose
// advisories are read from NVD by its CPEs (vendor builds, Java web
// applications).
type nvdCatalogueProduct struct {
	ID, Label string
	Product   nvdProduct
}

// nvdCatalogueKind names a catalogue in what its sync logs and reports.
type nvdCatalogueKind struct {
	Ecosystem string // base ecosystem; a product's own is Ecosystem + ":" + ID
	Catalogue string // catalogue version; a change re-reads every product
	LogMsg    string // "vendor build advisories not read"
	One       string // "vendor build", as in "no vendor build's advisories"
	Many      string // "vendor builds"
}

// syncNVDCatalogue reads, for each product, every CVE NVD names its CPE
// products in (full, weekly or after a catalogue change), or those modified
// since the last read. One product failing does not hold up the others;
// every product failing fails the feed, which keeps its cursor and data.
func (s *Syncer) syncNVDCatalogue(ctx context.Context, feed, cursor string, kind nvdCatalogueKind, prods []nvdCatalogueProduct) (*SyncResult, string, error) {
	var cur programsCursor
	if cursor != "" {
		_ = json.Unmarshal([]byte(cursor), &cur) // unusable: read everything
	}
	next := programsCursor{Catalogue: kind.Catalogue, Programs: map[string]programCursor{}}
	for id, c := range cur.Programs {
		next.Programs[id] = c
	}
	res := &SyncResult{Packages: map[store.PackageRef]bool{}, Full: true, Ecosystems: map[string]bool{}}
	var failed []string
	for _, p := range prods {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		now := s.clock()
		pc := next.Programs[p.ID]
		full := pc.Full.IsZero() || now.Sub(pc.Full) >= nvdFullRead || now.Sub(pc.Read) >= nvdIncrMax || cur.Catalogue != next.Catalogue
		unfixed, err := s.syncProgram(ctx, feed, p.Product, full, pc.Read, now, res)
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			s.Log.Warn(kind.LogMsg, "product", p.ID, "err", err)
			failed = append(failed, p.Label+": "+err.Error())
			continue
		}
		if full {
			pc.Unfixed, pc.Full = unfixed, now
		}
		pc.Read = now
		next.Programs[p.ID] = pc
	}
	if len(prods) > 0 && len(failed) == len(prods) {
		return nil, "", fmt.Errorf("no %s's advisories could be read: %s", kind.One, strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		res.Warning = fmt.Sprintf("advisories of %d %s could not be read and are kept as last read: %s",
			len(failed), kind.Many, strings.Join(failed, "; "))
	}
	// A product's ecosystem is listed once its advisories have been read
	// completely, so one never read is "not evaluated" rather than clean.
	for id, pc := range next.Programs {
		if !pc.Full.IsZero() {
			res.Ecosystems[kind.Ecosystem+":"+id] = true
		}
	}
	b, _ := json.Marshal(next)
	return res, string(b), nil
}
