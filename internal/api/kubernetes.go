package api

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/stackurity/stackurity/internal/collect/image"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// The Kubernetes reporter (stackurity kubernetes-reporter) runs in a
// cluster and pushes what the kubernetes plugin would pull: a cluster, its
// workloads and the images they run. POST /kubernetes/report takes one
// whole collection, so the server can queue image scans in the reporter's
// order (exposed and widely used images first) under one limit, exactly
// as it does for a plugin run (registerJobs in cmd/stackurity).

// FeatureKubernetesReport, in GET /meta's features, says that the server
// takes POST /kubernetes/report. The reporter falls back to POST /ingest,
// without image scans, on a server that does not list it.
const FeatureKubernetesReport = "kubernetes_report"

// KubernetesCollectorID is the collector every reported batch is stored
// under: the kubernetes plugin's, so a cluster that moves between pull and
// push keeps one inventory history (plugins/kubernetes/kube.CollectorID).
const KubernetesCollectorID = "plugin:kubernetes"

// ImageScanFresh is how long a successful scan of an image reported running
// in a cluster is reused. Running images are pinned to a digest, so their
// content cannot change; a rescan only picks up scanner improvements.
const ImageScanFresh = 7 * 24 * time.Hour

// maxKubernetesBatches bounds one report: a cluster, up to 2000 images and
// its workloads.
const maxKubernetesBatches = 5000

// limitKubernetesReport bounds reports per token. The reporter sends one an
// hour by default; this leaves room for restarts and shorter intervals
// while bounding the image scans one token can ask for.
var limitKubernetesReport = rateLimit{30, time.Hour}

// The identifier schemes a report may use (plugins/kubernetes/kube).
var kubernetesSchemes = map[model.AssetKind]map[string]bool{
	model.AssetCluster:  {"k8s-cluster": true, "k8s-cluster-name": true},
	model.AssetWorkload: {"k8s-workload": true},
	model.AssetImage:    {"image-ref": true},
}

type kubernetesReport struct {
	Batches []*model.ObservationBatch `json:"batches"`
	// ImageScans is the most image scans this report may queue (default
	// DefaultImageScans, at most MaxImageScans; 0 queues none).
	ImageScans *int `json:"image_scans"`
}

// KubernetesReportResult is the answer to POST /kubernetes/report.
type KubernetesReportResult struct {
	ClusterAssetID int64 `json:"cluster_asset_id"`
	Assets         int   `json:"assets"`
	NewAssets      int   `json:"new_assets"`
	// Refused names the assets left out at the monitored-asset limit.
	Refused    []string             `json:"refused"`
	Images     int                  `json:"images"`
	ImageScans store.ImageScanStats `json:"image_scans"`
}

func (s *Server) kubernetesReport(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var tokenID int64
	subject := ""
	switch {
	case p.Token != nil:
		tokenID = p.Token.ID
		subject = "token:" + strconv.FormatInt(tokenID, 10)
	case p.User != nil:
		subject = "user:" + strconv.FormatInt(p.User.ID, 10)
	}
	// A host-bound token reports for its own host only.
	if bound, err := s.boundAsset(r); err != nil {
		s.fail(w, r, err)
		return
	} else if bound != nil {
		writeError(w, 403, "forbidden", "this token is bound to a host; a cluster reports with its own token")
		return
	}
	if s.limited(w, r, "too many Kubernetes reports with this token; wait before the next one", limitHit{"kubernetes-report", subject, limitKubernetesReport}) {
		return
	}
	rd, err := s.body(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req kubernetesReport
	dec := json.NewDecoder(rd)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.fail(w, r, badRequest("invalid report JSON: "+err.Error()))
		return
	}
	limit := DefaultImageScans
	if req.ImageScans != nil {
		limit = *req.ImageScans
	}
	switch {
	case len(req.Batches) == 0:
		s.fail(w, r, badRequest("a report has at least the cluster's batch"))
		return
	case len(req.Batches) > maxKubernetesBatches:
		s.fail(w, r, badRequest(fmt.Sprintf("a report has at most %d batches", maxKubernetesBatches)))
		return
	case limit < 0 || limit > MaxImageScans:
		s.fail(w, r, badRequest("image_scans must be between 0 and "+strconv.Itoa(MaxImageScans)))
		return
	}
	for i, b := range req.Batches {
		if err := checkKubernetesBatch(b); err != nil {
			s.fail(w, r, badRequest(fmt.Sprintf("batch %d: %v", i, err)))
			return
		}
	}
	if req.Batches[0].Asset.Kind != model.AssetCluster {
		s.fail(w, r, badRequest("the first batch must be the cluster"))
		return
	}
	ctx := reportSource(r, tokenID)
	results, refused, err := s.Store.IngestAll(ctx, req.Batches, tokenID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := KubernetesReportResult{Refused: refused}
	if out.Refused == nil {
		out.Refused = []string{}
	}
	for _, res := range results {
		if res == nil {
			continue
		}
		out.Assets++
		if res.NewAsset {
			out.NewAssets++
		}
	}
	if results[0] != nil {
		out.ClusterAssetID = results[0].AssetID
	}
	out.Images, out.ImageScans, err = QueueReportedImages(ctx, s.Store, req.Batches, results, 0, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

// checkKubernetesBatch validates one reported batch and stamps it with the
// kubernetes collector. Only the kinds and identities the collection
// reports are taken.
func checkKubernetesBatch(b *model.ObservationBatch) error {
	if b == nil {
		return errors.New("empty batch")
	}
	b.Collector.ID, b.Collector.Method = KubernetesCollectorID, "agent"
	if err := b.Validate(); err != nil {
		return err
	}
	schemes, ok := kubernetesSchemes[b.Asset.Kind]
	if !ok {
		return fmt.Errorf("asset kind %q is not reported from a cluster", b.Asset.Kind)
	}
	for _, id := range b.Asset.Identifiers {
		if !schemes[id.Scheme] {
			return fmt.Errorf("identifier scheme %q is not used for a %s", id.Scheme, b.Asset.Kind)
		}
	}
	return nil
}

// QueueReportedImages queues image scans for the batches that only name an
// image (image.ReferenceOnly: the images a cluster runs), in the order
// given, at most limit of them. results are the batches' ingest results
// (nil where the asset was refused); integrationID is the integration that
// collected them, or 0 for the reporter. It returns how many images there
// were and what was queued.
func QueueReportedImages(ctx context.Context, st *store.Store, batches []*model.ObservationBatch, results []*store.IngestResult,
	integrationID int64, limit int) (int, store.ImageScanStats, error) {
	var scans []store.ImageScan
	for i, b := range batches {
		if results[i] == nil {
			continue
		}
		if ic, ok := image.ReferenceOnly(b); ok {
			scans = append(scans, store.ImageScan{AssetID: results[i].AssetID, Image: ic.Image, Platform: ic.Platform, IntegrationID: integrationID})
		}
	}
	if len(scans) == 0 || limit <= 0 {
		return len(scans), store.ImageScanStats{}, nil
	}
	stats, err := st.QueueImageScans(ctx, scans, limit, ImageScanFresh)
	return len(scans), stats, err
}

// --- GET /install/kubernetes.yaml

//go:embed install/kubernetes.yaml
var kubernetesManifest string

var kubernetesManifestTmpl = template.Must(template.New("kubernetes.yaml").Parse(kubernetesManifest))

var (
	clusterNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	k8sNamespace  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// KubernetesManifestParams is what the reporter manifest is made from.
type KubernetesManifestParams struct {
	Server      string
	Image       string
	ClusterName string
	// Namespaces: only these, with a Role in each instead of the
	// cluster-wide ClusterRole.
	Namespaces []string
}

// HTTP reports whether the server is reached over plain HTTP, which the
// reporter refuses unless told otherwise.
func (p KubernetesManifestParams) HTTP() bool { return strings.HasPrefix(p.Server, "http://") }

// RenderKubernetesManifest returns the reporter's manifest. Every value is
// checked here (or by the caller, for Server), since the template writes
// them into YAML unquoted.
func RenderKubernetesManifest(p KubernetesManifestParams) ([]byte, error) {
	var buf bytes.Buffer
	if err := kubernetesManifestTmpl.Execute(&buf, p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// installKubernetes serves the reporter's manifest for this server: the
// namespace, service account, read-only RBAC and Deployment. It holds no
// secret: the enrollment code goes into a Secret the install command
// creates (kubectl create secret), so it never appears in a URL, in this
// server's or a proxy's access log, or in a cached response.
//
// Query: cluster (the cluster asset's name) and namespaces (comma
// separated: Roles in those namespaces only, instead of a ClusterRole).
func (s *Server) installKubernetes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k := range q {
		if k != "cluster" && k != "namespaces" {
			writeError(w, 400, "bad_request", "unknown parameter "+strconv.Quote(k)+"; the enrollment code goes in a Secret, never in this URL")
			return
		}
	}
	p := KubernetesManifestParams{Server: s.publicURL(r), Image: s.reporterImage(), ClusterName: q.Get("cluster")}
	if p.ClusterName != "" && !clusterNameRE.MatchString(p.ClusterName) {
		writeError(w, 400, "bad_request", "cluster may contain letters, digits, '.', '_' and '-' (up to 100)")
		return
	}
	if ns := strings.TrimSpace(q.Get("namespaces")); ns != "" {
		seen := map[string]bool{}
		for _, n := range strings.Split(ns, ",") {
			n = strings.TrimSpace(n)
			if !k8sNamespace.MatchString(n) {
				writeError(w, 400, "bad_request", "namespaces must be a comma-separated list of namespace names")
				return
			}
			if !seen[n] {
				seen[n] = true
				p.Namespaces = append(p.Namespaces, n)
			}
		}
		if len(p.Namespaces) > 100 {
			writeError(w, 400, "bad_request", "at most 100 namespaces; use the cluster-wide manifest or the Helm chart")
			return
		}
	}
	// publicURL may come from the Host header; refuse anything that could
	// break out of the YAML value.
	if strings.ContainsAny(p.Server, " \t\r\n\"'#{}[],&*!|>%@`\\") {
		writeError(w, 400, "bad_request", "this server's URL cannot be written into a manifest; set STACKURITY_BASE_URL")
		return
	}
	body, err := RenderKubernetesManifest(p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(body)
}

// reporterImage is the image the manifest runs: this server's release, or
// latest for a development build.
func (s *Server) reporterImage() string {
	v := strings.TrimPrefix(s.Version, "v")
	if !regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`).MatchString(v) {
		v = "latest"
	}
	return "ghcr.io/stackurity/stackurity:" + v
}
