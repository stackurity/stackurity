package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/vex"
)

// VEX import and export (docs/risk.md, "VEX"). An imported document's
// statements are matched to components on assets here; a not_affected
// statement never suppresses anything by itself: it becomes a request in
// the approval inbox, which a security or admin user approves, unless the
// document came from a source trusted to apply on its own. An approved
// statement becomes ignore rules pinned to the component version (and the
// image digest) it matched, which end by themselves when the asset no
// longer has that version or image.

// Limits on what one import may match.
const (
	// maxStatementMatches is the most component versions one statement may
	// match; a statement that matches more is too broad to act on.
	maxStatementMatches = 5000
	// maxDocumentMatches is the most matches one document may make.
	maxDocumentMatches = 100000
)

// digestMatches is true when the asset (an id expression) is the image
// with digest d (an expression holding sha256:<hex>): by the digest the
// image scanner records, or a reference or package URL pinned to it.
func digestMatches(asset, d string) string {
	return `EXISTS (SELECT 1 FROM assets da WHERE da.id = ` + asset + ` AND (da.attributes->>'digest' = ` + d + `
		OR EXISTS (SELECT 1 FROM asset_identifiers di WHERE di.asset_id = da.id
		  AND (di.value LIKE '%@' || ` + d + ` OR di.value LIKE '%@' || replace(` + d + `, ':', '%3A') || '%'))))`
}

// --- sources

// VEXSource is who VEX comes from and how far it is trusted.
type VEXSource struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	AutoApply bool   `json:"auto_apply"`
	// TokenID pins the source to an API token: only its uploads count as
	// this source's for auto-apply.
	TokenID   *int64 `json:"token_id"`
	TokenName string `json:"token_name"`
	// KeyFingerprint is the SHA-256 of the public key the source's signed
	// documents must verify with ("" when it has none).
	KeyFingerprint string    `json:"key_fingerprint"`
	CreatedByName  string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Documents      int64     `json:"documents"`
	PublicKey      string    `json:"public_key"`
}

// Pinned is true when the source is tied to something a document cannot
// claim by itself: auto-apply needs it.
func (v *VEXSource) Pinned() bool { return v.TokenID != nil || v.KeyFingerprint != "" }

const sourceCols = `v.id, v.name, v.auto_apply, v.token_id, COALESCE(t.name, ''), v.key_fingerprint, v.created_by_name, v.created_at,
	v.updated_at, (SELECT count(*) FROM vex_documents d WHERE d.source_id = v.id), v.public_key`

const sourceFrom = ` FROM vex_sources v LEFT JOIN api_tokens t ON t.id = v.token_id`

func (s *Store) ListVEXSources(ctx context.Context) ([]VEXSource, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+sourceCols+sourceFrom+` ORDER BY v.name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[VEXSource])
}

func (s *Store) GetVEXSource(ctx context.Context, id int64) (*VEXSource, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+sourceCols+sourceFrom+` WHERE v.id = $1`, id)
	if err != nil {
		return nil, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[VEXSource])
	return v, notFound(err)
}

// VEXSourceInput creates or changes a source. Nil fields are left as they
// are; TokenID 0 and PublicKey "" clear the pin.
type VEXSourceInput struct {
	Name           *string
	AutoApply      *bool
	TokenID        *int64
	PublicKey      *string
	KeyFingerprint string // of PublicKey, computed by the caller
}

// SaveVEXSource creates (id 0) or changes a source. A source may apply
// on its own only while it is pinned to a key or a token.
func (s *Store) SaveVEXSource(ctx context.Context, id int64, in VEXSourceInput, actor Actor) (*VEXSource, error) {
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" || len(n) > 100 {
			return nil, fmt.Errorf("a source needs a name of at most 100 characters: %w", ErrInvalid)
		}
		in.Name = &n
	}
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if in.TokenID != nil && *in.TokenID > 0 {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM api_tokens WHERE id = $1 AND revoked_at IS NULL)`, *in.TokenID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no such active API token: %w", ErrInvalid)
			}
		}
		if id == 0 {
			if in.Name == nil {
				return fmt.Errorf("a source needs a name: %w", ErrInvalid)
			}
			if err := tx.QueryRow(ctx, `INSERT INTO vex_sources (name, created_by_name) VALUES ($1, $2) RETURNING id`,
				*in.Name, actor.Name).Scan(&id); err != nil {
				if isUnique(err) {
					return fmt.Errorf("%w: a source with that name exists", ErrConflict)
				}
				return err
			}
		}
		var tok any = nil
		setTok := in.TokenID != nil
		if setTok && *in.TokenID > 0 {
			tok = *in.TokenID
		}
		var key any = nil
		if in.PublicKey != nil {
			key = strings.TrimSpace(*in.PublicKey)
		}
		tag, err := tx.Exec(ctx, `UPDATE vex_sources SET name = COALESCE($2, name), auto_apply = COALESCE($3, auto_apply),
			token_id = CASE WHEN $4 THEN $5::bigint ELSE token_id END,
			public_key = COALESCE($6, public_key), key_fingerprint = CASE WHEN $6::text IS NULL THEN key_fingerprint ELSE $7 END,
			updated_at = now() WHERE id = $1`, id, in.Name, in.AutoApply, setTok, tok, key, in.KeyFingerprint)
		if err != nil {
			if isUnique(err) {
				return fmt.Errorf("%w: a source with that name exists", ErrConflict)
			}
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		var auto, pinned bool
		if err := tx.QueryRow(ctx, `SELECT auto_apply, token_id IS NOT NULL OR key_fingerprint <> '' FROM vex_sources WHERE id = $1`, id).
			Scan(&auto, &pinned); err != nil {
			return err
		}
		if auto && !pinned {
			return fmt.Errorf("a source applies statements on its own only when it is pinned to a public key or an API token "+
				"(anyone can write any author into a document): %w", ErrInvalid)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.GetVEXSource(ctx, id)
}

// DeleteVEXSource removes a source; its documents keep its name.
func (s *Store) DeleteVEXSource(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM vex_sources WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func isUnique(err error) bool {
	var pe interface{ SQLState() string }
	return errors.As(err, &pe) && pe.SQLState() == "23505"
}

// --- documents

// VEXDocument is an imported document.
type VEXDocument struct {
	ID             int64      `json:"id"`
	SourceID       *int64     `json:"source_id"`
	SourceName     string     `json:"source"`
	Format         string     `json:"format"`
	DocID          string     `json:"doc_id"`
	Author         string     `json:"author"`
	DocVersion     string     `json:"doc_version"`
	DocTimestamp   *time.Time `json:"doc_timestamp"`
	Filename       string     `json:"filename"`
	SHA256         string     `json:"sha256"`
	Size           int        `json:"size"`
	Signature      string     `json:"signature"`
	KeyFingerprint string     `json:"key_fingerprint"`
	ScopeAssetID   *int64     `json:"scope_asset_id"`
	ScopeProjectID *int64     `json:"scope_project_id"`
	AutoApplied    bool       `json:"auto_applied"`
	Via            string     `json:"via"`
	Statements     int        `json:"statements"`
	Matched        int        `json:"matched"`
	ImportedByName string     `json:"imported_by"`
	ImportedAt     time.Time  `json:"imported_at"`
	// Pending counts its not_affected statements waiting for a decision.
	Pending int `json:"pending"`
}

const docCols = `d.id, d.source_id, d.source_name, d.format, d.doc_id, d.author, d.doc_version, d.doc_timestamp, d.filename, d.sha256,
	d.size, d.signature, d.key_fingerprint, d.scope_asset_id, d.scope_project_id, d.auto_applied, d.via, d.statements, d.matched,
	d.imported_by_name, d.imported_at,
	(SELECT count(*) FROM vex_statements st JOIN ignore_requests r ON r.vex_statement_id = st.id WHERE st.document_id = d.id AND r.status = 'pending')::int`

func (s *Store) ListVEXDocuments(ctx context.Context, p Page) ([]VEXDocument, int64, error) {
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM vex_documents`).Scan(&total); err != nil {
		return nil, 0, err
	}
	p = p.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+docCols+` FROM vex_documents d ORDER BY d.imported_at DESC, d.id DESC LIMIT $1 OFFSET $2`, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[VEXDocument])
	return out, total, err
}

func (s *Store) GetVEXDocument(ctx context.Context, id int64) (*VEXDocument, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+docCols+` FROM vex_documents d WHERE d.id = $1`, id)
	if err != nil {
		return nil, err
	}
	d, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[VEXDocument])
	return d, notFound(err)
}

// VEXProblem is a product (or a whole statement) that was not matched,
// and why: unmatched (nothing here is that product), ambiguous (it could
// be more than one thing, so it is not applied) or invalid.
type VEXProblem struct {
	Product string `json:"product"`
	Kind    string `json:"kind"`
	Reason  string `json:"reason"`
}

// VEXStatement is an imported statement and what became of it.
type VEXStatement struct {
	ID              int64           `json:"id"`
	DocumentID      int64           `json:"document_id"`
	SourceName      string          `json:"source"`
	Vulnerability   string          `json:"vulnerability"`
	Aliases         []string        `json:"aliases"`
	Status          string          `json:"status"`
	Justification   string          `json:"justification"`
	OriginalState   string          `json:"original_state"`
	OriginalJust    string          `json:"original_justification"`
	ImpactStatement string          `json:"impact_statement"`
	ActionStatement string          `json:"action_statement"`
	StatusNotes     string          `json:"status_notes"`
	Products        json.RawMessage `json:"products"`
	Problems        []VEXProblem    `json:"problems"`
	EffectiveAt     time.Time       `json:"effective_at"`
	RequestID       *int64          `json:"request_id"`
	RequestStatus   string          `json:"request_status"`
	// Matches counts the component versions it matched, Assets the assets
	// they are on, and Findings the open findings it covers now.
	Matches  int64 `json:"matches"`
	Assets   int64 `json:"assets"`
	Findings int64 `json:"findings"`
}

// VEXStatementFilter selects a document's statements.
type VEXStatementFilter struct {
	DocumentID int64
	// Outcome: matched, unmatched, pending (approval) or "" for all.
	Outcome string
	Page
}

func (s *Store) ListVEXStatements(ctx context.Context, f VEXStatementFilter) ([]VEXStatement, int64, error) {
	w := &where{}
	w.add("st.document_id = ?", f.DocumentID)
	switch f.Outcome {
	case "":
	case "matched":
		w.conds = append(w.conds, "EXISTS (SELECT 1 FROM vex_matches m WHERE m.statement_id = st.id)")
	case "unmatched":
		w.conds = append(w.conds, "NOT EXISTS (SELECT 1 FROM vex_matches m WHERE m.statement_id = st.id)")
	case "pending":
		w.conds = append(w.conds, "EXISTS (SELECT 1 FROM ignore_requests r WHERE r.vex_statement_id = st.id AND r.status = 'pending')")
	default:
		return nil, 0, fmt.Errorf("outcome must be matched, unmatched or pending: %w", ErrInvalid)
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM vex_statements st`+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT st.id, st.document_id, st.source_name, st.vulnerability, st.aliases, st.status, st.justification,
		st.original_state, st.original_justification, st.impact_statement, st.action_statement, st.status_notes, st.products, st.problems,
		st.effective_at, st.request_id, COALESCE(r.status, ''),
		(SELECT count(*) FROM vex_matches m WHERE m.statement_id = st.id),
		(SELECT count(DISTINCT m.asset_id) FROM vex_matches m WHERE m.statement_id = st.id),
		(SELECT count(DISTINCT f.id) FROM vex_matches m JOIN findings f ON f.asset_id = m.asset_id AND f.component_id = m.component_id
		   AND f.key = m.key AND f.kind = 'vulnerability' AND f.status = 'open'
		 JOIN inventory i ON i.id = f.inventory_id AND i.version = m.version WHERE m.statement_id = st.id)
		FROM vex_statements st LEFT JOIN ignore_requests r ON r.id = st.request_id`+w.sql()+
		fmt.Sprintf(` ORDER BY st.id LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[VEXStatement])
	return out, total, err
}

// --- import

// VEXImport is one document to import and how far it is trusted.
type VEXImport struct {
	Doc        *vex.Document
	Filename   string
	SHA256     string
	Size       int
	Source     *VEXSource // nil: no source named
	SourceName string     // shown for documents without a source
	// Signature: none, verified (with the source's key) or unverified.
	Signature      string
	KeyFingerprint string
	// ScopeAssets limits matching to these assets (nil: every asset of the
	// workspace). ScopeAssetID / ScopeProjectID record what the person chose.
	ScopeAssets    []int64
	ScopeAssetID   *int64
	ScopeProjectID *int64
	// AutoApply approves its not_affected statements on import: the API
	// sets it only for a trusted source whose every pin held.
	AutoApply bool
	Via       string // vex (an upload) or sbom (VEX embedded in an SBOM)
	MaxDays   int
}

// VEXImportResult says what an import did.
type VEXImportResult struct {
	Document VEXDocument `json:"document"`
	// Statements by outcome: matched (applied to at least one component
	// version), unmatched (nothing here, ambiguous, or invalid).
	Statements int `json:"statements"`
	Matched    int `json:"matched"`
	Unmatched  int `json:"unmatched"`
	// Pending: not_affected statements now waiting in the approval inbox;
	// AutoApproved: approved on import (a trusted source); Ignored: the
	// findings those ignored now; Ended: earlier VEX ignore rules a newer
	// affected or under_investigation statement ended.
	Pending      int          `json:"pending"`
	AutoApproved int          `json:"auto_approved"`
	Ignored      int          `json:"ignored"`
	Ended        int          `json:"ended"`
	Problems     []VEXProblem `json:"problems"`
	// AutoApplyRefused says why a trusted source's document did not apply
	// on its own at all ("" when it did, or the source is not trusted).
	AutoApplyRefused string `json:"auto_apply_refused,omitempty"`
	// OutsideSubject counts not_affected statements of a trusted source left
	// for approval (wholly or in part) because they matched assets the
	// signed attestation is not about, or a bare package anywhere.
	OutsideSubject int `json:"outside_subject,omitempty"`
	// Skipped counts CycloneDX vulnerabilities without an analysis.
	Skipped int `json:"skipped"`
}

// vexTuple is one component version on one asset a product matched.
type vexTuple struct {
	asset, component int64
	version, digest  string
	// pinned: the product itself named the asset (an image digest, an
	// application or BOM, or the one asset the import was scoped to), or
	// the import was limited to an asset or project; false for a bare
	// package matched anywhere in the workspace.
	pinned bool
}

type invRow struct {
	asset, component int64
	key, version     string
	purl, name       string
	bomRef           string
}

// vexMatcher resolves a document's products against this workspace's
// assets and inventory, loaded in a few queries for the whole document.
type vexMatcher struct {
	scope       map[int64]bool // nil: every asset
	single      int64          // the one asset the import is scoped to
	byDigest    map[string][]int64
	bySerial    map[string][]int64
	byAssetPurl map[string][]int64
	inv         map[string][]invRow // component purl key -> rows
	byName      map[string][]invRow // lower component name -> rows (CPE)
	byBOMRef    map[string][]invRow // bom-ref -> rows
	keys        map[string][]string // statement vulnerability -> finding keys
}

var cpeRE = regexp.MustCompile(`^cpe:(?:2\.3:[aho\*\-]|/[aho]):([^:]*):([^:]*):?([^:]*)`)

// parseCPE returns a CPE's vendor, product and version ("" for any).
func parseCPE(c string) (vendor, product, version string) {
	m := cpeRE.FindStringSubmatch(strings.ToLower(c))
	if m == nil {
		return "", "", ""
	}
	clean := func(s string) string {
		s = strings.ReplaceAll(s, `\`, "")
		if s == "*" || s == "-" {
			return ""
		}
		return s
	}
	return clean(m[1]), clean(m[2]), clean(m[3])
}

// purlParts returns a package URL's component key (as components store
// it), version and qualifiers.
func purlParts(p string) (key, version string, q map[string]string, ok bool) {
	k, _, _, _, err := model.ComponentKey(p)
	if err != nil {
		return "", "", nil, false
	}
	pu, err := packageurl.FromString(p)
	if err != nil {
		return "", "", nil, false
	}
	return k, pu.Version, pu.Qualifiers.Map(), true
}

// altKeys are the spellings of a component key the collectors may have
// stored: PyPI names compare normalised (PEP 503).
var pep503 = regexp.MustCompile(`[-_.]+`)

func altKeys(key string) []string {
	out := []string{key}
	if strings.HasPrefix(key, "pkg:pypi/") {
		n := pep503.ReplaceAllString(strings.ToLower(strings.TrimPrefix(key, "pkg:pypi/")), "-")
		if k := "pkg:pypi/" + n; k != key {
			out = append(out, k)
		}
	}
	return out
}

func sameVersion(a, b string) bool {
	return a == b || strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// qualifiersAgree: a product's distro or arch, when both name one, must be
// the inventory row's.
func qualifiersAgree(want map[string]string, rowPurl string) bool {
	if len(want) == 0 {
		return true
	}
	pu, err := packageurl.FromString(rowPurl)
	if err != nil {
		return true
	}
	have := pu.Qualifiers.Map()
	for _, k := range []string{"distro", "arch"} {
		if w, h := want[k], have[k]; w != "" && h != "" && !strings.EqualFold(w, h) {
			return false
		}
	}
	return true
}

func (m *vexMatcher) inScope(asset int64) bool { return m.scope == nil || m.scope[asset] }

func (m *vexMatcher) filterScope(ids []int64) []int64 {
	var out []int64
	for _, id := range ids {
		if m.inScope(id) {
			out = append(out, id)
		}
	}
	return out
}

// load reads everything the document's products and vulnerabilities could
// match.
func (m *vexMatcher) load(ctx context.Context, tx pgx.Tx, doc *vex.Document) error {
	digests, serials, assetPurls, comps, names, refs, vulns := map[string]bool{}, map[string]bool{}, map[string]bool{},
		map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	var visit func(p vex.Product, top bool)
	visit = func(p vex.Product, top bool) {
		if p.Problem != "" {
			return
		}
		if p.Digest != "" {
			digests[p.Digest] = true
		}
		if p.Serial != "" {
			serials[p.Serial] = true
		}
		if p.Purl != "" {
			if top {
				assetPurls[p.Purl] = true
			}
			if k, _, _, ok := purlParts(p.Purl); ok {
				for _, a := range altKeys(k) {
					comps[a] = true
				}
			}
		}
		if p.CPE != "" {
			if _, prod, _ := parseCPE(p.CPE); prod != "" {
				names[prod] = true
				names[strings.ReplaceAll(prod, "_", "-")] = true
			}
		}
		if p.BOMRef != "" {
			refs[p.BOMRef] = true
		}
		for _, sp := range p.Subcomponents {
			visit(sp, false)
		}
	}
	for _, st := range doc.Statements {
		if st.Problem != "" {
			continue
		}
		vulns[st.Vulnerability] = true
		for _, a := range st.Aliases {
			vulns[a] = true
		}
		for _, p := range st.Products {
			visit(p, true)
		}
	}
	// Assets: images by digest, SBOM assets by serial number, applications
	// by the package URL their SBOM gave them.
	m.byDigest, m.bySerial, m.byAssetPurl = map[string][]int64{}, map[string][]int64{}, map[string][]int64{}
	if len(digests) > 0 {
		ds := keysOf(digests)
		rows, err := tx.Query(ctx, `SELECT d, a.id FROM unnest($1::text[]) d JOIN assets a ON a.merged_into IS NULL
			AND (a.attributes->>'digest' = d OR EXISTS (SELECT 1 FROM asset_identifiers i WHERE i.asset_id = a.id
			  AND (i.value LIKE '%@' || d OR i.value LIKE '%@' || replace(d, ':', '%3A') || '%')))`, ds)
		if err != nil {
			return err
		}
		if err := collectPairs(rows, m.byDigest); err != nil {
			return err
		}
	}
	if len(serials) > 0 || len(assetPurls) > 0 {
		rows, err := tx.Query(ctx, `SELECT i.scheme, i.value, COALESCE(a.merged_into, a.id) FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id
			WHERE (i.scheme = 'sbom-serial' AND i.value = ANY($1)) OR (i.scheme = 'purl' AND i.value = ANY($2))`, keysOf(serials), keysOf(assetPurls))
		if err != nil {
			return err
		}
		for rows.Next() {
			var scheme, value string
			var id int64
			if err := rows.Scan(&scheme, &value, &id); err != nil {
				rows.Close()
				return err
			}
			if scheme == "sbom-serial" {
				m.bySerial[value] = append(m.bySerial[value], id)
			} else {
				m.byAssetPurl[value] = append(m.byAssetPurl[value], id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	// Inventory rows of the named components, by key, CPE product name and
	// bom-ref (current rows on current assets only).
	m.inv, m.byName, m.byBOMRef = map[string][]invRow{}, map[string][]invRow{}, map[string][]invRow{}
	if len(comps) > 0 || len(names) > 0 || len(refs) > 0 {
		rows, err := tx.Query(ctx, `SELECT i.asset_id, i.component_id, c.purl_key, i.version, i.purl, lower(c.name), COALESCE(i.evidence->>'bom_ref', '')
			FROM inventory i JOIN components c ON c.id = i.component_id JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
			WHERE i.removed_at IS NULL AND (c.purl_key = ANY($1) OR lower(c.name) = ANY($2) OR i.evidence->>'bom_ref' = ANY($3))`,
			keysOf(comps), keysOf(names), keysOf(refs))
		if err != nil {
			return err
		}
		n := 0
		for rows.Next() {
			var r invRow
			if err := rows.Scan(&r.asset, &r.component, &r.key, &r.version, &r.purl, &r.name, &r.bomRef); err != nil {
				rows.Close()
				return err
			}
			if !m.inScope(r.asset) {
				continue
			}
			if n++; n > 4*maxDocumentMatches {
				rows.Close()
				return fmt.Errorf("the document names components installed in more than %d places; import it for one asset or project: %w",
					4*maxDocumentMatches, ErrInvalid)
			}
			if comps[r.key] {
				m.inv[r.key] = append(m.inv[r.key], r)
			}
			if names[r.name] {
				m.byName[r.name] = append(m.byName[r.name], r)
			}
			if r.bomRef != "" && refs[r.bomRef] {
				m.byBOMRef[r.bomRef] = append(m.byBOMRef[r.bomRef], r)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	// Finding keys: an advisory's group key (the CVE when it has one) for
	// every id or alias a statement names.
	m.keys = map[string][]string{}
	if len(vulns) > 0 {
		ids := keysOf(vulns)
		rows, err := tx.Query(ctx, `SELECT a.id, a.group_key, a.aliases FROM advisories a WHERE a.id = ANY($1) OR a.aliases && $1`, ids)
		if err != nil {
			return err
		}
		groups := map[string]map[string]bool{}
		add := func(id, g string) {
			if vulns[id] {
				if groups[id] == nil {
					groups[id] = map[string]bool{}
				}
				groups[id][g] = true
			}
		}
		for rows.Next() {
			var id, g string
			var al []string
			if err := rows.Scan(&id, &g, &al); err != nil {
				rows.Close()
				return err
			}
			add(id, g)
			for _, a := range al {
				add(a, g)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, st := range doc.Statements {
			if st.Problem != "" {
				continue
			}
			set := map[string]bool{}
			for _, id := range append([]string{st.Vulnerability}, st.Aliases...) {
				for g := range groups[id] {
					set[g] = true
				}
			}
			if len(set) == 0 {
				// No advisory known yet: findings are keyed by the CVE or
				// advisory id itself.
				set[st.Vulnerability] = true
			}
			m.keys[st.Vulnerability] = append(m.keys[st.Vulnerability], keysOf(set)...)
			sort.Strings(m.keys[st.Vulnerability])
			m.keys[st.Vulnerability] = dedupeStrings(m.keys[st.Vulnerability])
		}
	}
	return nil
}

func dedupeStrings(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func collectPairs(rows pgx.Rows, into map[string][]int64) error {
	defer rows.Close()
	for rows.Next() {
		var k string
		var id int64
		if err := rows.Scan(&k, &id); err != nil {
			return err
		}
		into[k] = append(into[k], id)
	}
	return rows.Err()
}

// productAssets resolves a product that names an asset: an image by
// digest, an SBOM by serial number, an application by package URL, or the
// document's own subject standing for the one asset the import is scoped
// to. named is false when the product does not name an asset at all.
func (m *vexMatcher) productAssets(p vex.Product) (assets []int64, digest string, named bool) {
	switch {
	case p.Digest != "":
		return m.filterScope(m.byDigest[p.Digest]), p.Digest, true
	case p.Serial != "" && len(m.bySerial[p.Serial]) > 0:
		return m.filterScope(m.bySerial[p.Serial]), "", true
	case p.Purl != "" && len(m.byAssetPurl[p.Purl]) > 0:
		return m.filterScope(m.byAssetPurl[p.Purl]), "", true
	case p.Root || p.Serial != "" || len(p.Subcomponents) > 0:
		// A product that holds components but is none of our assets can
		// only be the asset the person scoped the import to.
		if m.single != 0 {
			return []int64{m.single}, "", true
		}
		return nil, "", true
	}
	return nil, "", false
}

// componentRows matches a package (a package URL, CPE or bom-ref) among the
// inventory rows of the given assets (nil: anywhere in scope). pinned: the
// assets are fixed by the product (an image digest, an application), so a
// package URL without a version may stand for the one version an asset has.
func (m *vexMatcher) componentRows(c vex.Product, assets []int64, pinned bool) ([]invRow, *VEXProblem) {
	on := map[int64]bool{}
	for _, a := range assets {
		on[a] = true
	}
	keep := func(r invRow) bool { return assets == nil || on[r.asset] }
	label := c.Label()
	switch {
	case c.Problem != "":
		return nil, &VEXProblem{label, "unmatched", c.Problem}
	case c.Purl != "":
		key, version, q, ok := purlParts(c.Purl)
		if !ok {
			return nil, &VEXProblem{label, "unmatched", "not a valid package URL"}
		}
		if version == "" && !pinned {
			return nil, &VEXProblem{label, "ambiguous", "no version: it would cover every version of the package"}
		}
		var out []invRow
		perAsset := map[int64]map[string]bool{}
		for _, k := range altKeys(key) {
			for _, r := range m.inv[k] {
				if !keep(r) || !qualifiersAgree(q, r.purl) || (version != "" && !sameVersion(version, r.version)) {
					continue
				}
				out = append(out, r)
				if perAsset[r.asset] == nil {
					perAsset[r.asset] = map[string]bool{}
				}
				perAsset[r.asset][r.version] = true
			}
		}
		if version == "" {
			for _, vs := range perAsset {
				if len(vs) > 1 {
					return nil, &VEXProblem{label, "ambiguous", "no version, and an asset has more than one version of the package"}
				}
			}
		}
		if len(out) == 0 && c.BOMRef != "" {
			return m.bomRefRows(c, keep, label)
		}
		if len(out) == 0 {
			return nil, &VEXProblem{label, "unmatched", "no asset in scope has this package at this version"}
		}
		return out, nil
	case c.CPE != "":
		vendor, product, version := parseCPE(c.CPE)
		if product == "" {
			return nil, &VEXProblem{label, "unmatched", "not a CPE Stackurity can read"}
		}
		if version == "" {
			return nil, &VEXProblem{label, "ambiguous", "the CPE names no version"}
		}
		var out []invRow
		kinds := map[string]bool{}
		for _, n := range dedupeStrings([]string{product, strings.ReplaceAll(product, "_", "-")}) {
			for _, r := range m.byName[n] {
				if keep(r) && sameVersion(version, r.version) {
					out = append(out, r)
					kinds[r.key] = true
				}
			}
		}
		if len(kinds) > 1 {
			// The vendor rarely appears in a package URL, so two packages of
			// the same name and version are two candidates.
			_ = vendor
			return nil, &VEXProblem{label, "ambiguous", fmt.Sprintf("the CPE fits %d different packages", len(kinds))}
		}
		if len(out) == 0 {
			return nil, &VEXProblem{label, "unmatched", "no asset in scope has a package of this name at this version"}
		}
		return out, nil
	case c.BOMRef != "":
		return m.bomRefRows(c, keep, label)
	}
	return nil, &VEXProblem{label, "unmatched", "no package URL, CPE or reference"}
}

func (m *vexMatcher) bomRefRows(c vex.Product, keep func(invRow) bool, label string) ([]invRow, *VEXProblem) {
	var out []invRow
	for _, r := range m.byBOMRef[c.BOMRef] {
		if keep(r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, &VEXProblem{label, "unmatched", "no component with this bom-ref was imported for the product"}
	}
	return out, nil
}

// match resolves one product to component versions on assets.
func (m *vexMatcher) match(ctx context.Context, tx pgx.Tx, p vex.Product, keys []string) ([]vexTuple, []VEXProblem, error) {
	if p.Problem != "" {
		return nil, []VEXProblem{{p.Label(), "unmatched", p.Problem}}, nil
	}
	assets, digest, named := m.productAssets(p)
	var tuples []vexTuple
	var problems []VEXProblem
	switch {
	case named && len(assets) == 0:
		why := "no asset in scope is this product"
		if p.Digest != "" {
			why = "no image in scope has this digest"
		} else if p.Root || p.Serial != "" || len(p.Subcomponents) > 0 {
			why = "the product is not an asset here; import the document for the asset it describes (asset_id)"
		}
		return nil, []VEXProblem{{p.Label(), "unmatched", why}}, nil
	case named && len(p.Subcomponents) == 0:
		// The whole image or application: every component version with a
		// finding for the vulnerability.
		rows, err := tx.Query(ctx, `SELECT DISTINCT f.asset_id, f.component_id, i.version FROM findings f JOIN inventory i ON i.id = f.inventory_id
			WHERE f.asset_id = ANY($1) AND f.kind = 'vulnerability' AND f.key = ANY($2) AND i.removed_at IS NULL`, assets, keys)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			t := vexTuple{digest: digest, pinned: true}
			if err := rows.Scan(&t.asset, &t.component, &t.version); err != nil {
				rows.Close()
				return nil, nil, err
			}
			tuples = append(tuples, t)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
		if len(tuples) == 0 {
			problems = append(problems, VEXProblem{p.Label(), "unmatched", "the product has no finding for this vulnerability (yet)"})
		}
	case named:
		for _, sc := range p.Subcomponents {
			rows, prob := m.componentRows(sc, assets, true)
			if prob != nil {
				prob.Product = p.Label() + " › " + prob.Product
				problems = append(problems, *prob)
				continue
			}
			for _, r := range rows {
				tuples = append(tuples, vexTuple{asset: r.asset, component: r.component, version: r.version, digest: digest, pinned: true})
			}
		}
	default:
		// A package on its own: that version wherever it is installed in
		// scope.
		rows, prob := m.componentRows(p, nil, false)
		if prob != nil {
			problems = append(problems, *prob)
			break
		}
		for _, r := range rows {
			tuples = append(tuples, vexTuple{asset: r.asset, component: r.component, version: r.version, pinned: m.scope != nil})
		}
	}
	return tuples, problems, nil
}

// ImportVEX records a document, matches its statements and, for each
// matched not_affected statement, asks for approval (or, for a trusted
// source, approves it). Newer affected or under_investigation statements
// end the VEX ignore rules they contradict.
func (s *Store) ImportVEX(ctx context.Context, in VEXImport, actor Actor) (*VEXImportResult, error) {
	doc := in.Doc
	res := &VEXImportResult{Statements: len(doc.Statements), Skipped: doc.Skipped, Problems: []VEXProblem{}}
	now := time.Now().UTC()
	via := in.Via
	if via == "" {
		via = "vex"
	}
	sourceName := in.SourceName
	var sourceID *int64
	if in.Source != nil {
		sourceID, sourceName = &in.Source.ID, in.Source.Name
	}
	if sourceName == "" {
		sourceName = doc.Author
	}
	if sourceName == "" {
		sourceName = "unknown"
	}
	type stRow struct {
		id      int64
		st      vex.Statement
		matches []vexTuple
		keys    []string
		eff     time.Time
	}
	var docID int64
	var requests, autoRequests []int64
	var toEnd []int64
	auto := in.AutoApply
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		m := &vexMatcher{}
		if in.ScopeAssets != nil {
			m.scope = map[int64]bool{}
			for _, a := range in.ScopeAssets {
				m.scope[a] = true
			}
			if len(in.ScopeAssets) == 1 {
				m.single = in.ScopeAssets[0]
			}
		}
		if err := m.load(ctx, tx, doc); err != nil {
			return err
		}
		docTime := now
		if doc.Timestamp != nil && doc.Timestamp.Before(now) {
			docTime = *doc.Timestamp
		}
		// A trusted source applies on its own only with a document no older
		// than the newest already imported from it: an old signed document
		// uploaded again (a replay) must not bring back what a newer one
		// changed. Without a timestamp nobody can tell, so it waits too.
		if auto && sourceID != nil {
			var newest *time.Time
			if err := tx.QueryRow(ctx, `SELECT max(doc_timestamp) FROM vex_documents WHERE source_id = $1`, *sourceID).Scan(&newest); err != nil {
				return err
			}
			switch {
			case doc.Timestamp == nil:
				auto, res.AutoApplyRefused = false, "the document has no timestamp, so it cannot be told from an older one: its statements wait for approval"
			case newest != nil && doc.Timestamp.Before(*newest):
				auto, res.AutoApplyRefused = false, "the document is older than one already imported from this source (a replay?): its statements wait for approval"
			}
		}
		// What a trusted source may apply on its own: with a signed
		// attestation, only the assets it is about (its subjects' digests);
		// without one, only what the product itself pins or the import was
		// limited to. Everything else waits for approval.
		subjectAssets := map[int64]bool{}
		withSubjects := false
		if auto {
			var ds []string
			for _, sub := range doc.Subjects {
				if sub.SHA256 != "" {
					ds = append(ds, sub.SHA256)
				}
			}
			if len(ds) > 0 {
				withSubjects = true
				rows, err := tx.Query(ctx, `SELECT DISTINCT a.id FROM unnest($1::text[]) d JOIN assets a ON a.merged_into IS NULL
					AND (a.attributes->>'digest' = d OR EXISTS (SELECT 1 FROM asset_identifiers i WHERE i.asset_id = a.id
					  AND (i.value LIKE '%@' || d OR i.value LIKE '%@' || replace(d, ':', '%3A') || '%')))`, ds)
				if err != nil {
					return err
				}
				ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
				if err != nil {
					return err
				}
				for _, id := range ids {
					subjectAssets[id] = true
				}
			} else if doc.Envelope != nil {
				// A signed attestation about nothing in particular.
				withSubjects = true
			}
		}
		autoMay := func(t vexTuple) bool {
			if !auto {
				return false
			}
			if withSubjects {
				return subjectAssets[t.asset] && m.inScope(t.asset)
			}
			return t.pinned
		}
		if err := tx.QueryRow(ctx, `INSERT INTO vex_documents (source_id, source_name, format, doc_id, author, doc_version, doc_timestamp,
			filename, sha256, size, signature, key_fingerprint, scope_asset_id, scope_project_id, auto_applied, via, statements,
			imported_by, imported_by_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING id`,
			sourceID, sourceName, doc.Format, doc.ID, doc.Author, doc.Version, doc.Timestamp, in.Filename, in.SHA256, in.Size,
			in.Signature, in.KeyFingerprint, in.ScopeAssetID, in.ScopeProjectID, false, via, len(doc.Statements),
			userIDOnly(actor), actor.Name).Scan(&docID); err != nil {
			return err
		}
		var sts []stRow
		total := 0
		for _, st := range doc.Statements {
			r := stRow{st: st, eff: docTime}
			// A statement's own time decides which statement about a
			// component is the latest; a time in the future counts as now,
			// so a document cannot make itself newer than later ones.
			if st.Timestamp != nil && st.Timestamp.Before(now) {
				r.eff = *st.Timestamp
			}
			var problems []VEXProblem
			if st.Problem != "" {
				problems = append(problems, VEXProblem{st.Vulnerability, "invalid", st.Problem})
			} else {
				r.keys = m.keys[st.Vulnerability]
				seen := map[vexTuple]bool{}
				for _, p := range st.Products {
					ts, ps, err := m.match(ctx, tx, p, r.keys)
					if err != nil {
						return err
					}
					problems = append(problems, ps...)
					for _, t := range ts {
						if !seen[t] {
							seen[t] = true
							r.matches = append(r.matches, t)
						}
					}
				}
				if len(r.matches)*len(r.keys) > maxStatementMatches {
					problems = append(problems, VEXProblem{st.Vulnerability, "ambiguous",
						fmt.Sprintf("matches %d component versions: too broad to apply; import it for one asset or project", len(r.matches))})
					r.matches = nil
				}
			}
			total += len(r.matches) * len(r.keys)
			if total > maxDocumentMatches {
				return fmt.Errorf("the document matches more than %d component versions; import it for one asset or project: %w",
					maxDocumentMatches, ErrInvalid)
			}
			if len(r.matches) > 0 {
				res.Matched++
			} else {
				res.Unmatched++
			}
			for _, p := range problems {
				if len(res.Problems) < 200 {
					res.Problems = append(res.Problems, p)
				}
			}
			status := st.Status
			if !vex.ValidStatus(status) {
				status = "invalid"
			}
			prods, _ := json.Marshal(st.Products)
			probs, _ := json.Marshal(nonNilProblems(problems))
			if err := tx.QueryRow(ctx, `INSERT INTO vex_statements (document_id, source_name, vulnerability, aliases, status, justification,
				original_state, original_justification, impact_statement, action_statement, status_notes, products, problems, effective_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`, docID, sourceName, st.Vulnerability,
				nonNilStrings(st.Aliases), status, st.Justification, st.OriginalState, st.OriginalJustification, st.ImpactStatement,
				st.ActionStatement, st.StatusNotes, prods, probs, r.eff).Scan(&r.id); err != nil {
				return err
			}
			sts = append(sts, r)
		}
		var copyRows [][]any
		for _, r := range sts {
			for _, t := range r.matches {
				for _, k := range r.keys {
					copyRows = append(copyRows, []any{r.id, t.asset, t.component, t.version, t.digest, k})
				}
			}
		}
		if len(copyRows) > 0 {
			// COPY cannot write a table with row-level security: the rows
			// go through a temporary table.
			if _, err := tx.Exec(ctx, `CREATE TEMP TABLE vex_in (statement_id bigint, asset_id bigint, component_id bigint,
				version text, digest text, key text) ON COMMIT DROP`); err != nil {
				return err
			}
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vex_in"},
				[]string{"statement_id", "asset_id", "component_id", "version", "digest", "key"}, pgx.CopyFromRows(copyRows)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO vex_matches (statement_id, asset_id, component_id, version, digest, key)
				SELECT statement_id, asset_id, component_id, version, digest, key FROM vex_in ON CONFLICT DO NOTHING`); err != nil {
				return err
			}
		}
		// Approval requests for matched not_affected statements, with the
		// open findings they cover now.
		var naIDs []int64
		for _, r := range sts {
			if r.st.Problem == "" && r.st.Status == vex.StatusNotAffected && len(r.matches) > 0 {
				naIDs = append(naIDs, r.id)
			}
		}
		type stAsset struct{ statement, asset int64 }
		findingIDs := map[stAsset][]int64{}
		if len(naIDs) > 0 {
			rows, err := tx.Query(ctx, `SELECT DISTINCT m.statement_id, f.asset_id, f.id FROM vex_matches m
				JOIN findings f ON f.asset_id = m.asset_id AND f.component_id = m.component_id AND f.key = m.key
				  AND f.kind = 'vulnerability' AND f.status = 'open'
				JOIN inventory i ON i.id = f.inventory_id AND i.version = m.version
				WHERE m.statement_id = ANY($1) ORDER BY 1, 3`, naIDs)
			if err != nil {
				return err
			}
			for rows.Next() {
				var k stAsset
				var fid int64
				if err := rows.Scan(&k.statement, &k.asset, &fid); err != nil {
					rows.Close()
					return err
				}
				findingIDs[k] = append(findingIDs[k], fid)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		// makeRequest asks for approval of a statement on some of the assets
		// it matched (all of them when assets is nil).
		makeRequest := func(r stRow, matches []vexTuple, limit []int64) (int64, error) {
			var fids []int64
			seenAsset := map[int64]bool{}
			for _, t := range matches {
				if !seenAsset[t.asset] {
					seenAsset[t.asset] = true
					fids = append(fids, findingIDs[stAsset{r.id, t.asset}]...)
				}
			}
			fids = dedupe(fids)
			if len(fids) > maxRequestIssues {
				fids = fids[:maxRequestIssues]
			}
			var assetID *int64
			if len(seenAsset) == 1 {
				one := matches[0].asset
				assetID = &one
			}
			title := fmt.Sprintf("VEX: %s not affected (%s), %d component version(s)", r.st.Vulnerability, sourceName, len(matches))
			var reqID int64
			err := tx.QueryRow(ctx, `INSERT INTO ignore_requests (finding_ids, title, asset_id, reason, note, scope, expiry,
				requested_by, requested_by_name, vex_statement_id, vex_assets) VALUES ($1,$2,$3,$4,$5,'asset','never',$6,$7,$8,$9) RETURNING id`,
				nonNilIDs(fids), title, assetID, vex.IgnoreReason(r.st), vexNote(sourceName, r.st), userIDOnly(actor),
				actor.Name+" (VEX import)", r.id, limit).Scan(&reqID)
			return reqID, err
		}
		for _, r := range sts {
			if r.st.Problem != "" || r.st.Status != vex.StatusNotAffected || len(r.matches) == 0 {
				continue
			}
			var mine, rest []vexTuple
			for _, t := range r.matches {
				if autoMay(t) {
					mine = append(mine, t)
				} else {
					rest = append(rest, t)
				}
			}
			assetsOf := func(ts []vexTuple) []int64 {
				var out []int64
				for _, t := range ts {
					out = append(out, t.asset)
				}
				return dedupe(out)
			}
			var reqID int64
			var err error
			switch {
			case len(mine) == 0:
				if reqID, err = makeRequest(r, r.matches, nil); err != nil {
					return err
				}
				requests = append(requests, reqID)
				if auto {
					res.OutsideSubject++
				}
			case len(rest) == 0:
				if reqID, err = makeRequest(r, r.matches, nil); err != nil {
					return err
				}
				requests, autoRequests = append(requests, reqID), append(autoRequests, reqID)
			default:
				// Split: the trusted part applies, the rest waits.
				a, err := makeRequest(r, mine, assetsOf(mine))
				if err != nil {
					return err
				}
				if reqID, err = makeRequest(r, rest, assetsOf(rest)); err != nil {
					return err
				}
				requests, autoRequests = append(requests, a, reqID), append(autoRequests, a)
				res.OutsideSubject++
			}
			if _, err := tx.Exec(ctx, `UPDATE vex_statements SET request_id = $2 WHERE id = $1`, r.id, reqID); err != nil {
				return err
			}
		}
		if len(autoRequests) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE vex_documents SET auto_applied = true WHERE id = $1`, docID); err != nil {
				return err
			}
		}
		// Earlier VEX ignore rules that a newer affected or
		// under_investigation statement contradicts end (after the commit,
		// one at a time, as ending locks findings).
		rows, err := tx.Query(ctx, `SELECT DISTINCT e.id FROM finding_exceptions e JOIN vex_statements os ON os.id = e.vex_statement_id
			JOIN vex_matches m ON m.asset_id = e.asset_id AND m.component_id = e.component_id AND m.key = e.key AND m.version = e.version
			JOIN vex_statements ns ON ns.id = m.statement_id
			WHERE e.ended_at IS NULL AND ns.document_id = $1 AND ns.status IN ('affected', 'under_investigation')
			  AND (ns.effective_at, ns.id) > (os.effective_at, os.id) ORDER BY e.id`, docID)
		if err != nil {
			return err
		}
		if toEnd, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE vex_documents SET matched = $2 WHERE id = $1`, docID, res.Matched)
		return err
	})
	if err != nil {
		return nil, err
	}
	res.Pending = len(requests)
	sys := Actor{Type: "system", Name: "VEX: " + sourceName}
	for _, id := range toEnd {
		if _, err := s.endPinnedRule(ctx, id, sys, "vex_superseded",
			"a newer VEX statement says the vulnerability affects this component or is under investigation"); err != nil &&
			!errors.Is(err, ErrConflict) {
			return nil, err
		}
		res.Ended++
	}
	if len(autoRequests) > 0 {
		auto := Actor{Type: "system", Name: "VEX source " + sourceName + " (auto-apply)"}
		for _, id := range autoRequests {
			r, err := s.DecideIgnoreRequest(ctx, id, true, "applied on import: the source is trusted to apply on its own", in.MaxDays, auto)
			if err != nil {
				return nil, err
			}
			res.AutoApproved++
			res.Ignored += r.Applied
			_ = s.Audit(ctx, auto, "ignore_request.approve", "ignore_request", fmt.Sprint(id), map[string]any{
				"auto_apply": true, "source": sourceName, "vex_document_id": docID, "vex_statement_id": r.VEXStatementID,
				"sha256": in.SHA256, "filename": in.Filename, "applied": r.Applied, "signature": in.Signature})
		}
		res.Pending -= res.AutoApproved
	}
	d, err := s.GetVEXDocument(ctx, docID)
	if err != nil {
		return nil, err
	}
	res.Document = *d
	return res, nil
}

func nonNilProblems(p []VEXProblem) []VEXProblem {
	if p == nil {
		return []VEXProblem{}
	}
	return p
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilIDs(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}

// vexNote is the reason an ignore rule made from a statement gives.
func vexNote(source string, st vex.Statement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "VEX from %s: not affected", source)
	if st.Justification != "" {
		fmt.Fprintf(&b, " (%s)", st.Justification)
	}
	if st.ImpactStatement != "" {
		b.WriteString(": " + st.ImpactStatement)
	}
	n := b.String()
	if len(n) > 2000 {
		n = n[:2000]
	}
	return n
}

// approveVEX applies an approved not_affected statement inside the
// decision's transaction: one ignore rule per matched component version
// and finding key, pinned to that version and, for an image named by
// digest, that digest. A component a newer affected or
// under_investigation statement speaks about is skipped. It returns how
// many findings the rules ignored.
func approveVEX(ctx context.Context, tx pgx.Tx, statementID int64, r *IgnoreRequest, actor Actor) (int, error) {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM vex_statements WHERE id = $1`, statementID).Scan(&status); err != nil {
		return 0, notFound(err)
	}
	if status != vex.StatusNotAffected {
		return 0, fmt.Errorf("%w: only a not_affected statement can be approved", ErrInvalidAction)
	}
	type match struct {
		asset, component int64
		version, digest  string
		key              string
	}
	rows, err := tx.Query(ctx, `SELECT m.asset_id, m.component_id, m.version, m.digest, m.key FROM vex_matches m
		JOIN vex_statements s ON s.id = m.statement_id
		WHERE m.statement_id = $1 AND ($2::bigint[] IS NULL OR m.asset_id = ANY($2))
		  AND NOT EXISTS (SELECT 1 FROM vex_matches n JOIN vex_statements ns ON ns.id = n.statement_id
		  WHERE n.asset_id = m.asset_id AND n.component_id = m.component_id AND n.version = m.version AND n.key = m.key
		    AND ns.status IN ('affected', 'under_investigation') AND (ns.effective_at, ns.id) > (s.effective_at, s.id))
		ORDER BY 1, 2, 3, 5`, statementID, r.VEXAssets)
	if err != nil {
		return 0, err
	}
	var ms []match
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.asset, &m.component, &m.version, &m.digest, &m.key); err != nil {
			rows.Close()
			return 0, err
		}
		ms = append(ms, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(ms) == 0 {
		return 0, nil
	}
	// Everything the rules may change is locked first, in id order (see
	// lockIssueFindings).
	if _, err := tx.Exec(ctx, `SELECT f.id FROM findings f JOIN vex_matches m ON m.asset_id = f.asset_id AND m.component_id = f.component_id
		AND m.key = f.key WHERE m.statement_id = $1 AND ($2::bigint[] IS NULL OR m.asset_id = ANY($2)) AND f.kind = 'vulnerability'
		ORDER BY f.id FOR UPDATE OF f`, statementID, r.VEXAssets); err != nil {
		return 0, err
	}
	applied := 0
	for _, m := range ms {
		// An earlier VEX rule for the same component version is replaced;
		// what it ignored follows the new rule.
		rs, err := tx.Query(ctx, `UPDATE finding_exceptions SET ended_at = now(), ended_by_name = $6, ended_reason = 'replaced'
			WHERE ended_at IS NULL AND kind = 'vulnerability' AND key = $1 AND component_id = $2 AND asset_id = $3 AND version = $4
			  AND digest = $5 AND vex_statement_id IS NOT NULL RETURNING id`, m.key, m.component, m.asset, m.version, m.digest, actor.Name)
		if err != nil {
			return 0, err
		}
		replaced, err := pgx.CollectRows(rs, pgx.RowTo[int64])
		if err != nil {
			return 0, err
		}
		var rule int64
		if err := tx.QueryRow(ctx, `INSERT INTO finding_exceptions (kind, key, component_id, asset_id, reason, note, expires_at, until_fix,
			created_by, created_by_name, request_id, vex_statement_id, version, digest)
			VALUES ('vulnerability', $1, $2, $3, $4, $5, NULL, false, $6, $7, $8, $9, $10, $11) RETURNING id`,
			m.key, m.component, m.asset, r.Reason, r.Note, userIDOnly(actor), actor.Name, r.ID, statementID, m.version, m.digest).Scan(&rule); err != nil {
			return 0, err
		}
		if len(replaced) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE findings SET exception_id = $2, ignore_reason = $3, state_reason = $4
				WHERE exception_id = ANY($1) AND state = 'risk_accepted'`, replaced, rule, r.Reason, r.Note); err != nil {
				return 0, err
			}
		}
		n, err := applyExceptions(ctx, tx, rule, "")
		if err != nil {
			return 0, err
		}
		applied += int(n)
	}
	return applied, nil
}

// endPinnedRule ends one rule in its own transaction.
func (s *Store) endPinnedRule(ctx context.Context, id int64, actor Actor, reason, note string) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		n, err = endRule(ctx, tx, id, actor, reason, note)
		return err
	})
	return n, err
}

// EndStaleVEXRules ends the ignore rules made from VEX statements whose
// asset no longer has the component at the version they were made for
// (upgraded or removed) or, for an image named by digest, is no longer
// that image. The findings they ignored return to new. The dispatcher runs
// it each cycle; it returns how many rules ended.
func (s *Store) EndStaleVEXRules(ctx context.Context) (int, error) {
	rows, err := s.Pool.Query(ctx, `SELECT e.id, e.version, e.digest FROM finding_exceptions e
		WHERE e.ended_at IS NULL AND (e.version <> '' OR e.digest <> '') AND e.asset_id IS NOT NULL AND (
		  NOT EXISTS (SELECT 1 FROM inventory i WHERE i.asset_id = e.asset_id AND i.component_id = e.component_id
		    AND i.version = e.version AND i.removed_at IS NULL)
		  OR (e.digest <> '' AND NOT `+digestMatches("e.asset_id", "e.digest")+`))
		ORDER BY e.id LIMIT 1000`)
	if err != nil {
		return 0, err
	}
	type stale struct {
		id              int64
		version, digest string
	}
	var list []stale
	for rows.Next() {
		var x stale
		if err := rows.Scan(&x.id, &x.version, &x.digest); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	sys := Actor{Type: "system", Name: "VEX"}
	n := 0
	for _, x := range list {
		reopened, err := s.endPinnedRule(ctx, x.id, sys, "no_longer_matches",
			"the VEX statement no longer matches: the component version or the image changed")
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return n, err
		}
		n++
		_ = s.Audit(ctx, sys, "ignore_rule.end", "ignore_rule", fmt.Sprint(x.id), map[string]any{
			"reason": "no_longer_matches", "version": x.version, "digest": x.digest, "reopened": reopened})
	}
	return n, nil
}

// --- on findings and requests

// FindingVEX is the latest VEX statement about a finding's component
// version and vulnerability.
type FindingVEX struct {
	StatementID     int64     `json:"statement_id"`
	DocumentID      int64     `json:"document_id"`
	Source          string    `json:"source"`
	Status          string    `json:"status"`
	Justification   string    `json:"justification"`
	ImpactStatement string    `json:"impact_statement"`
	ActionStatement string    `json:"action_statement"`
	StatusNotes     string    `json:"status_notes"`
	Vulnerability   string    `json:"vulnerability"`
	EffectiveAt     time.Time `json:"effective_at"`
	RequestID       *int64    `json:"request_id"`
	// RequestStatus: pending, approved or declined for a not_affected
	// statement ("" otherwise, or when the caller cannot see the inbox).
	RequestStatus string `json:"request_status"`
	// Applied: the finding is ignored by a rule made from this statement.
	Applied bool `json:"applied"`
}

// fillFindingVEX sets VEX on each finding a statement covers. A declined
// not_affected statement is not shown.
func (s *Store) fillFindingVEX(ctx context.Context, fs []*Finding) error {
	ids := make([]int64, 0, len(fs))
	for _, f := range fs {
		if f.Kind == "vulnerability" {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT ON (f.id) f.id, st.id, st.document_id, st.source_name, st.status, st.justification,
		st.impact_statement, st.action_statement, st.status_notes, st.vulnerability, st.effective_at, r.id, COALESCE(r.status, ''),
		COALESCE(e.vex_statement_id = st.id AND f.state = 'risk_accepted', false)
		FROM findings f JOIN inventory i ON i.id = f.inventory_id
		JOIN vex_matches m ON m.asset_id = f.asset_id AND m.component_id = f.component_id AND m.key = f.key AND m.version = i.version
		JOIN vex_statements st ON st.id = m.statement_id
		LEFT JOIN LATERAL (SELECT q.id, q.status FROM ignore_requests q WHERE q.vex_statement_id = st.id
		  AND (q.vex_assets IS NULL OR f.asset_id = ANY(q.vex_assets)) ORDER BY q.id DESC LIMIT 1) r ON true
		LEFT JOIN finding_exceptions e ON e.id = f.exception_id
		WHERE f.id = ANY($1) AND (m.digest = '' OR `+digestMatches("f.asset_id", "m.digest")+`)
		  AND NOT (st.status = 'not_affected' AND COALESCE(r.status, '') = 'declined')
		ORDER BY f.id, COALESCE(e.vex_statement_id = st.id AND f.state = 'risk_accepted', false) DESC, st.effective_at DESC, st.id DESC`, ids)
	if err != nil {
		return err
	}
	byID := map[int64]*FindingVEX{}
	for rows.Next() {
		var fid int64
		v := &FindingVEX{}
		if err := rows.Scan(&fid, &v.StatementID, &v.DocumentID, &v.Source, &v.Status, &v.Justification, &v.ImpactStatement,
			&v.ActionStatement, &v.StatusNotes, &v.Vulnerability, &v.EffectiveAt, &v.RequestID, &v.RequestStatus, &v.Applied); err != nil {
			rows.Close()
			return err
		}
		byID[fid] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, f := range fs {
		f.VEX = byID[f.ID]
	}
	return nil
}

// RequestVEX is what a VEX request in the approval inbox is about.
type RequestVEX struct {
	StatementID     int64        `json:"statement_id"`
	DocumentID      int64        `json:"document_id"`
	Source          string       `json:"source"`
	Vulnerability   string       `json:"vulnerability"`
	Justification   string       `json:"justification"`
	ImpactStatement string       `json:"impact_statement"`
	Filename        string       `json:"filename"`
	SHA256          string       `json:"sha256"`
	Signature       string       `json:"signature"`
	Author          string       `json:"author"`
	Matches         int64        `json:"matches"`
	Assets          int64        `json:"assets"`
	Problems        []VEXProblem `json:"problems"`
}

func (s *Store) fillRequestVEX(ctx context.Context, rs []*IgnoreRequest) error {
	var ids []int64
	for _, r := range rs {
		if r.VEXStatementID != nil {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	// Counts are of what the request itself covers (a trusted source's
	// statement can be split into the part that applied and the rest).
	rows, err := s.Pool.Query(ctx, `SELECT q.id, st.id, st.document_id, st.source_name, st.vulnerability, st.justification, st.impact_statement,
		d.filename, d.sha256, d.signature, d.author,
		(SELECT count(*) FROM vex_matches m WHERE m.statement_id = st.id AND (q.vex_assets IS NULL OR m.asset_id = ANY(q.vex_assets))),
		(SELECT count(DISTINCT m.asset_id) FROM vex_matches m WHERE m.statement_id = st.id AND (q.vex_assets IS NULL OR m.asset_id = ANY(q.vex_assets))),
		st.problems
		FROM ignore_requests q JOIN vex_statements st ON st.id = q.vex_statement_id JOIN vex_documents d ON d.id = st.document_id
		WHERE q.id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	byID := map[int64]*RequestVEX{}
	for rows.Next() {
		v := &RequestVEX{}
		var rid int64
		if err := rows.Scan(&rid, &v.StatementID, &v.DocumentID, &v.Source, &v.Vulnerability, &v.Justification, &v.ImpactStatement,
			&v.Filename, &v.SHA256, &v.Signature, &v.Author, &v.Matches, &v.Assets, &v.Problems); err != nil {
			rows.Close()
			return err
		}
		byID[rid] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range rs {
		if r.VEXStatementID != nil {
			r.VEX = byID[r.ID]
		}
	}
	return nil
}

// PendingVEXRequests lists the pending requests a document's import made.
func (s *Store) PendingVEXRequests(ctx context.Context, documentID int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.id FROM ignore_requests r JOIN vex_statements st ON st.id = r.vex_statement_id
		WHERE st.document_id = $1 AND r.status = 'pending' ORDER BY r.id`, documentID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// --- export

// VEXExportRow is one decision to export: a vulnerability's status in a
// component version on an asset.
type VEXExportRow struct {
	Key             string
	Sources         []string
	AssetID         int64
	AssetName       string
	AssetKind       string
	Digest          string
	AssetPurl       string
	Purl            string
	Version         string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	StatusNotes     string
	FalsePositive   bool
	At              time.Time
}

// VEXExport returns the decisions to export for one asset (assetID > 0)
// or every asset the caller can see (narrowed to a project by row-level
// security): open findings ignored as a false positive or mitigated
// (with the statement's own justification when a VEX statement made the
// rule), and the latest imported affected, fixed or under_investigation
// statement about other open findings.
//
// People's notes and mitigations are free text written for colleagues:
// they are written into the document only with notes; otherwise a rule
// made by a person carries its justification alone.
func (s *Store) VEXExport(ctx context.Context, assetID int64, notes bool) ([]VEXExportRow, error) {
	cond := ""
	args := []any{}
	if assetID > 0 {
		cond = " AND f.asset_id = $1"
		args = append(args, assetID)
	}
	const assetInfo = `a.name, a.kind, COALESCE(a.attributes->>'digest', ''),
		COALESCE((SELECT ai.value FROM asset_identifiers ai WHERE ai.asset_id = a.id AND ai.scheme = 'purl' ORDER BY ai.value LIMIT 1), '')`
	rows, err := s.Pool.Query(ctx, `SELECT f.key, f.sources, f.asset_id, `+assetInfo+`, i.purl, i.version,
		'not_affected', COALESCE(st.justification, ''), COALESCE(st.impact_statement, ''), e.reason, e.note, e.mitigation,
		e.created_at, st.id IS NOT NULL
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL JOIN inventory i ON i.id = f.inventory_id
		JOIN finding_exceptions e ON e.id = f.exception_id
		LEFT JOIN vex_statements st ON st.id = e.vex_statement_id
		WHERE f.kind = 'vulnerability' AND f.status = 'open' AND f.state = 'risk_accepted' AND e.ended_at IS NULL
		  AND e.reason IN ('false_positive', 'mitigated')`+cond+`
		ORDER BY f.id LIMIT 50000`, args...)
	if err != nil {
		return nil, err
	}
	var out []VEXExportRow
	seen := map[string]bool{}
	for rows.Next() {
		var r VEXExportRow
		var reason, note, mitigation string
		var fromVEX bool
		if err := rows.Scan(&r.Key, &r.Sources, &r.AssetID, &r.AssetName, &r.AssetKind, &r.Digest, &r.AssetPurl, &r.Purl, &r.Version,
			&r.Status, &r.Justification, &r.ImpactStatement, &reason, &note, &mitigation, &r.At, &fromVEX); err != nil {
			rows.Close()
			return nil, err
		}
		r.FalsePositive = reason == ReasonFalsePositive
		if !fromVEX {
			r.Justification = vex.JustificationFor(reason)
			r.ImpactStatement = ""
			if notes {
				r.ImpactStatement = strings.TrimSpace(note)
				if mitigation != "" {
					r.ImpactStatement = strings.TrimSpace(r.ImpactStatement + " Mitigation: " + mitigation)
				}
			}
		}
		k := fmt.Sprintf("%d %s %s", r.AssetID, r.Purl, r.Key)
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT DISTINCT ON (f.id) f.key, f.sources, f.asset_id, `+assetInfo+`, i.purl, i.version,
		st.status, st.justification, st.impact_statement, st.action_statement, st.status_notes, st.effective_at
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL JOIN inventory i ON i.id = f.inventory_id
		JOIN vex_matches m ON m.asset_id = f.asset_id AND m.component_id = f.component_id AND m.key = f.key AND m.version = i.version
		JOIN vex_statements st ON st.id = m.statement_id
		WHERE f.kind = 'vulnerability' AND f.status = 'open' AND st.status IN ('affected', 'fixed', 'under_investigation')
		  AND (m.digest = '' OR `+digestMatches("f.asset_id", "m.digest")+`)`+cond+`
		ORDER BY f.id, st.effective_at DESC, st.id DESC LIMIT 50000`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r VEXExportRow
		if err := rows.Scan(&r.Key, &r.Sources, &r.AssetID, &r.AssetName, &r.AssetKind, &r.Digest, &r.AssetPurl, &r.Purl, &r.Version,
			&r.Status, &r.Justification, &r.ImpactStatement, &r.ActionStatement, &r.StatusNotes, &r.At); err != nil {
			rows.Close()
			return nil, err
		}
		k := fmt.Sprintf("%d %s %s", r.AssetID, r.Purl, r.Key)
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	rows.Close()
	return out, rows.Err()
}

// ProjectAssetIDs lists a project's current assets.
func (s *Store) ProjectAssetIDs(ctx context.Context, projectID int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT pa.asset_id FROM project_assets pa JOIN assets a ON a.id = pa.asset_id AND a.merged_into IS NULL
		WHERE pa.project_id = $1 ORDER BY 1`, projectID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if ids == nil {
		ids = []int64{}
	}
	return ids, err
}
