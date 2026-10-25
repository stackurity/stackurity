package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/pkg/plugin"
)

var collector = plugin.Collector{ID: "kubernetes"}

// Identifier schemes. A cluster is identified by the UID of its kube-system
// namespace, which survives renames and kubeconfig changes.
const (
	schemeCluster     = "k8s-cluster"
	schemeClusterName = "k8s-cluster-name" // only when the UID is unreadable
	schemeWorkload    = "k8s-workload"
	schemeImage       = "image-ref" // the same scheme the image scanner uses
)

// maxImageRelations leaves room for the runs_on relation within the
// server's per-batch limit (16).
const maxImageRelations = 15

// maxNamespaceItems keeps the cluster's coverage under the server's limit.
const maxNamespaceItems = 900

// batches turns a snapshot into the cluster, its images and its workloads,
// in that order so each relation's target exists when it is ingested.
func (s *snapshot) batches() []*plugin.ObservationBatch {
	clusterID := plugin.Identifier{Scheme: schemeCluster, Value: s.clusterUID}
	clusterKey := s.clusterUID
	if s.clusterUID == "" {
		clusterID = plugin.Identifier{Scheme: schemeClusterName, Value: s.name}
		clusterKey = "name:" + s.name
	}
	nodeArch := map[string]string{}
	for _, n := range s.nodes {
		nodeArch[n.Metadata.Name] = n.Status.NodeInfo.OperatingSystem + "/" + n.Status.NodeInfo.Architecture
	}

	images := map[string]*imageInfo{}
	var wbs []*plugin.ObservationBatch
	exposed := 0
	ws := s.workloads()
	for _, w := range ws {
		env := s.environment(w.ns)
		e := s.exposureOf(w)
		if e.level == "external" {
			exposed++
		}
		cis := s.imagesOf(w)
		platform := ""
		for _, p := range w.pods {
			if a := nodeArch[p.Spec.NodeName]; a != "" && a != "/" {
				platform = a
				break
			}
		}
		b := plugin.NewBatch(collector, plugin.AssetRef{
			Kind:        plugin.AssetWorkload,
			Name:        fmt.Sprintf("%s/%s/%s/%s", s.name, w.ns, strings.ToLower(w.kind), w.name),
			Environment: env,
			Identifiers: []plugin.Identifier{{Scheme: schemeWorkload, Value: clusterKey + "/" + w.key()}},
		})
		b.Complete = true
		at := map[string]string{
			"cluster": s.name, "namespace": w.ns, "workload_kind": w.kind, "workload_name": w.name,
			"exposure": e.level, "exposed_via": joinLimit(e.via, 2000), "services": joinLimit(e.services, 2000),
			"pods": strconv.Itoa(len(w.pods)),
		}
		if w.counted {
			at["replicas"], at["ready"] = strconv.Itoa(int(w.desired)), strconv.Itoa(int(w.ready))
		}
		if w.schedule != "" {
			at["schedule"] = w.schedule
		}
		if w.spec.ServiceAccountName != "" {
			at["service_account"] = w.spec.ServiceAccountName
		}
		at["host_network"] = strconv.FormatBool(w.spec.HostNetwork)
		at["privileged"] = strconv.FormatBool(privileged(w.spec))
		var secrets []string
		for _, ps := range w.spec.ImagePullSecrets {
			secrets = append(secrets, ps.Name)
		}
		at["image_pull_secrets"] = strings.Join(secrets, ", ")
		b.Asset.Attributes = at

		rels := []plugin.RelationRef{{Kind: "runs_on", To: []plugin.Identifier{clusterID}}}
		var refs []string
		for _, ci := range cis {
			if ci.invalid {
				b.Cover("image:"+ci.container, "unsupported", trim("image reference "+ci.spec+" cannot be inventoried", 300))
				continue
			}
			switch {
			case ci.note == "":
				b.Cover("image:"+ci.container, "checked", "")
			case len(w.pods) == 0:
				b.Cover("image:"+ci.container, "skipped", ci.note)
			default:
				b.Cover("image:"+ci.container, "partial", ci.note)
			}
			for _, ref := range ci.refs {
				refs = append(refs, ref)
				im := images[ref]
				if im == nil {
					_, pinned := resolveRef(ref, "")
					im = &imageInfo{ref: ref, pinned: pinned, tags: map[string]bool{}, env: env}
					images[ref] = im
				}
				im.uses++
				im.tags[ci.spec] = true
				im.exposed = im.exposed || e.level == "external"
				im.pullSecret = im.pullSecret || len(secrets) > 0
				if im.platform == "" {
					im.platform = platform
				}
				if im.env == "" {
					im.env = env
				}
			}
		}
		refs = dedupe(refs)
		at["images"] = joinLimit(refs, 2000)
		if len(refs) > maxImageRelations {
			b.Cover("images", "partial", fmt.Sprintf("%d images; only the first %d are linked", len(refs), maxImageRelations))
			refs = refs[:maxImageRelations]
		} else {
			b.Cover("images", "checked", "")
		}
		for _, ref := range refs {
			rels = append(rels, plugin.RelationRef{Kind: "deployed_as", To: []plugin.Identifier{{Scheme: schemeImage, Value: ref}}})
		}
		b.Relations = rels

		switch pa := s.acc["pods"]; {
		case !pa.readable(w.ns):
			b.Cover("pods", "failed", "pods in namespace "+w.ns+" could not be read; running image digests are unknown")
			b.Complete = false
		default:
			b.Cover("pods", "checked", "")
		}
		if e.level == "unknown" {
			b.Cover("exposure", "partial", "Services or Ingresses in namespace "+w.ns+" could not be read")
		} else {
			b.Cover("exposure", "checked", "")
		}
		wbs = append(wbs, b)
	}

	// Images: those behind exposed workloads and in wide use first, so the
	// most important are inside the limit and scanned first.
	var ims []*imageInfo
	for _, im := range images {
		ims = append(ims, im)
	}
	sort.Slice(ims, func(i, j int) bool {
		a, b := ims[i], ims[j]
		if a.exposed != b.exposed {
			return a.exposed
		}
		if a.pinned != b.pinned {
			return a.pinned
		}
		if a.uses != b.uses {
			return a.uses > b.uses
		}
		return a.ref < b.ref
	})
	dropped := 0
	if len(ims) > s.settings.maxImages() {
		dropped = len(ims) - s.settings.maxImages()
		ims = ims[:s.settings.maxImages()]
	}
	var ibs []*plugin.ObservationBatch
	for _, im := range ims {
		b := plugin.NewBatch(collector, plugin.AssetRef{
			Kind: plugin.AssetImage, Name: im.ref, Environment: im.env,
			Identifiers: []plugin.Identifier{{Scheme: schemeImage, Value: im.ref}},
			Attributes: map[string]string{
				"image": im.ref, "tags": joinLimit(sortedKeys(im.tags), 2000), "pinned": strconv.FormatBool(im.pinned),
				"pull_secret": strconv.FormatBool(im.pullSecret),
			},
		})
		if im.platform != "" {
			b.Asset.Attributes["platform"] = im.platform
		}
		// No observations: the server reads the image's packages with its
		// image scanner (Syft), which reports its own coverage.
		b.Complete = true
		ibs = append(ibs, b)
	}

	cb := s.clusterBatch(clusterID, len(ws), exposed, len(images), dropped)
	return append(append([]*plugin.ObservationBatch{cb}, ibs...), wbs...)
}

func (s *snapshot) environment(ns string) string {
	if l := s.settings.EnvironmentLabel; l != "" {
		if v := s.namespaces[ns].Metadata.Labels[l]; v != "" {
			return v
		}
	}
	return s.settings.Environment
}

func privileged(spec podSpec) bool {
	for _, c := range append(append([]container{}, spec.InitContainers...), spec.Containers...) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

// clusterBatch reports the control plane version, and kubelet, container
// runtime and OS versions grouped across nodes, so lifecycle data applies
// to each. Coverage lists every API or namespace that could not be read.
func (s *snapshot) clusterBatch(id plugin.Identifier, workloads, exposed, images, dropped int) *plugin.ObservationBatch {
	dist, product, provider := distribution(s.version.GitVersion, s.nodes)
	region := ""
	ready := 0
	for _, n := range s.nodes {
		if region == "" {
			region = n.Metadata.Labels["topology.kubernetes.io/region"]
		}
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				ready++
			}
		}
	}
	at := map[string]string{
		"kubernetes_version": s.version.GitVersion, "platform": s.version.Platform, "distribution": dist,
		"workloads": strconv.Itoa(workloads), "exposed_workloads": strconv.Itoa(exposed), "images": strconv.Itoa(images),
	}
	if s.nodesAcc.err == nil && !s.nodesAcc.all {
		at["nodes"], at["nodes_ready"] = strconv.Itoa(len(s.nodes)), strconv.Itoa(ready)
	}
	if s.namespaces != nil {
		at["namespaces"] = strconv.Itoa(len(s.namespaces))
	}
	b := plugin.NewBatch(collector, plugin.AssetRef{
		Kind: plugin.AssetCluster, Name: s.name, Environment: s.settings.Environment, Provider: provider, Region: region,
		Identifiers: []plugin.Identifier{id}, Attributes: at,
	})
	b.Complete = true

	if v := cleanVersion(s.version.GitVersion); v != "" {
		b.Observations = append(b.Observations, plugin.Observation{
			Purl: purl(product, v), Version: v, Location: "control-plane", Confidence: plugin.ConfidenceConfirmed,
			Evidence: map[string]string{"kind": "kubernetes", "component": "control-plane", "git_version": s.version.GitVersion, "source": "/version"},
		})
	}
	b.Cover("control-plane", "checked", "")

	// Group nodes by version so a 500-node cluster is a handful of rows.
	type group struct {
		purl, version, location string
		ev                      map[string]string
		nodes                   []string
	}
	groups := map[string]*group{}
	addNode := func(location, name, version, nodeName string, ev map[string]string) {
		k := location + "|" + name + "|" + version
		g := groups[k]
		if g == nil {
			g = &group{purl: purl(name, version), version: version, location: location, ev: ev}
			groups[k] = g
		}
		g.nodes = append(g.nodes, nodeName)
	}
	unmapped := map[string]bool{}
	for _, n := range s.nodes {
		ni := n.Status.NodeInfo
		if v := cleanVersion(ni.KubeletVersion); v != "" {
			addNode("kubelet", product, v, n.Metadata.Name, map[string]string{"kind": "kubernetes", "component": "kubelet"})
		}
		if p, v := runtimeProduct(ni.ContainerRuntimeVersion); p != "" && v != "" {
			addNode("container-runtime", p, v, n.Metadata.Name, map[string]string{"kind": "kubernetes", "component": "container-runtime"})
		}
		if osID, v := osOf(ni.OSImage); osID != "" {
			addNode("node-os", osID, v, n.Metadata.Name, map[string]string{"kind": "operating-system", "os_image": ni.OSImage})
		} else if ni.OSImage != "" {
			unmapped[ni.OSImage] = true
		}
	}
	for _, k := range sortedKeys(groups) {
		g := groups[k]
		sort.Strings(g.nodes)
		ev := map[string]string{"node_count": strconv.Itoa(len(g.nodes)), "nodes": joinLimit(g.nodes, 1500), "source": "node status"}
		for k, v := range g.ev {
			ev[k] = v
		}
		b.Observations = append(b.Observations, plugin.Observation{
			Purl: g.purl, Version: g.version, Location: g.location, Confidence: plugin.ConfidenceConfirmed, Scope: scopeOf(g.location), Evidence: ev,
		})
	}

	switch {
	case s.nodesAcc.err != nil || s.nodesAcc.all:
		c := s.nodesAcc.coverage("nodes")
		if s.nodesAcc.all {
			c.Reason = "nodes are forbidden; kubelet, runtime and OS versions are unknown"
		}
		b.Coverage = append(b.Coverage, c)
		b.Complete = false // cannot prove node components are gone
	case len(unmapped) > 0:
		b.Cover("nodes", "partial", trim("no lifecycle data for node OS: "+strings.Join(sortedKeys(unmapped), "; "), 500))
	default:
		b.Cover("nodes", "checked", "")
	}
	if s.nsErr != nil {
		b.Cover("namespaces", "failed", trim(s.nsErr.Error(), 300))
	} else {
		b.Cover("namespaces", "checked", "")
	}
	for _, r := range []string{"pods", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs", "services", "ingresses"} {
		b.Coverage = append(b.Coverage, s.acc[r].coverage(r))
	}
	// One item per namespace, so an unreadable one shows by name (its
	// workloads and images are not inventoried) and clears once readable.
	for i, ns := range s.scope {
		if i == maxNamespaceItems {
			b.Cover("namespace:...", "partial", fmt.Sprintf("%d more namespaces are not listed here", len(s.scope)-i))
			break
		}
		if s.acc["pods"].readable(ns) {
			b.Cover("namespace:"+ns, "checked", "")
		} else {
			b.Cover("namespace:"+ns, "failed", "pods are forbidden: workloads and images in this namespace are not inventoried")
		}
	}
	if dropped > 0 {
		b.Cover("images", "partial", fmt.Sprintf("%d images over the max_images limit of %d were not reported", dropped, s.settings.maxImages()))
	} else {
		b.Cover("images", "checked", "")
	}
	return b
}

func scopeOf(location string) string {
	if location == "node-os" {
		return "os"
	}
	return ""
}
