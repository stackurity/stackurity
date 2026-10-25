package store

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// A stack is everything one asset relies on, followed through relations:
// an application's hosts, source repository, images and dependencies; a
// host's workloads; a repository's deployments and where they run. Its
// findings are grouped by layer, so the question "how could this be
// compromised?" has one answer across OS, web server, runtime, data stores
// and libraries.

type StackMember struct {
	AssetID         int64  `json:"asset_id"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Environment     string `json:"environment"`
	InternetExposed *bool  `json:"internet_exposed"`
	Criticality     string `json:"criticality"`
	Status          string `json:"collection_status"`
	Role            string `json:"role"` // self, host, cluster, source, image, dependency, workload, deployment
	Via             string `json:"via"`  // relation kind that brought it in
	From            int64  `json:"from"` // the member it was reached from (0 for self)
	Open            int    `json:"open"`
}

type StackLayer struct {
	Layer      string         `json:"layer"`
	Open       int            `json:"open"`
	BySeverity map[string]int `json:"by_severity"`
	Exploited  int            `json:"known_exploited"`
	Overdue    int            `json:"overdue"`
}

type StackFinding struct {
	Finding
	Layer string `json:"layer"`
}

type Stack struct {
	Root      int64          `json:"root"`
	Members   []StackMember  `json:"members"`
	Layers    []StackLayer   `json:"layers"`
	Findings  []StackFinding `json:"findings"`
	Truncated bool           `json:"truncated"`
}

// Layer order, most exposed first.
var stackLayers = []string{"web_server", "os", "runtime", "data_store", "libraries", "declared", "managed_service", "platform", "other"}

// outgoing relations followed from any member, and the role of the target.
var stackRoles = map[string]string{"runs_on": "host", "built_from": "source", "deployed_as": "image", "depends_on": "dependency", "contains": "dependency"}

const (
	maxStackDepth    = 3
	maxStackMembers  = 200
	maxStackFindings = 5000
)

func (s *Store) GetStack(ctx context.Context, id int64) (*Stack, error) {
	root, err := s.GetAsset(ctx, id)
	if err != nil {
		return nil, err
	}
	st := &Stack{Root: root.ID, Findings: []StackFinding{}}
	members := map[int64]*StackMember{}
	var order []int64
	addMember := func(assetID int64, role, via string, from int64) bool {
		if _, ok := members[assetID]; ok || len(order) >= maxStackMembers {
			return false
		}
		members[assetID] = &StackMember{AssetID: assetID, Role: role, Via: via, From: from}
		order = append(order, assetID)
		return true
	}
	addMember(root.ID, "self", "", 0)

	type edge struct {
		from, to int64
		kind     string
	}
	query := func(sql string, ids []int64) ([]edge, error) {
		rows, err := s.Pool.Query(ctx, sql, ids)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, func(row pgx.CollectableRow) (edge, error) {
			var e edge
			err := row.Scan(&e.from, &e.to, &e.kind)
			return e, err
		})
	}
	const live = ` JOIN assets f ON f.id = r.from_asset AND f.merged_into IS NULL
		JOIN assets t ON t.id = r.to_asset AND t.merged_into IS NULL`

	// What runs on a host, or where a repository is deployed, comes first.
	switch root.Kind {
	case "host", "cluster":
		in, err := query(`SELECT r.to_asset, r.from_asset, r.kind FROM asset_relations r`+live+
			` WHERE r.to_asset = ANY($1) AND r.kind = 'runs_on'`, []int64{root.ID})
		if err != nil {
			return nil, err
		}
		var workloads []int64
		for _, e := range in {
			if addMember(e.to, "workload", "runs_on", root.ID) {
				workloads = append(workloads, e.to)
			}
		}
		// A cluster's workloads bring in the images they run.
		if root.Kind == "cluster" && len(workloads) > 0 {
			out, err := query(`SELECT r.from_asset, r.to_asset, r.kind FROM asset_relations r`+live+
				` WHERE r.from_asset = ANY($1) AND r.kind = 'deployed_as' ORDER BY r.to_asset`, workloads)
			if err != nil {
				return nil, err
			}
			for _, e := range out {
				addMember(e.to, "image", "deployed_as", e.from)
			}
		}
	case "image":
		// Where the image runs: the Kubernetes workloads deployed as it.
		in, err := query(`SELECT r.to_asset, r.from_asset, r.kind FROM asset_relations r`+live+
			` WHERE r.to_asset = ANY($1) AND r.kind = 'deployed_as'`, []int64{root.ID})
		if err != nil {
			return nil, err
		}
		for _, e := range in {
			addMember(e.to, "workload", "deployed_as", root.ID)
		}
	case "repository":
		in, err := query(`SELECT r.to_asset, r.from_asset, r.kind FROM asset_relations r`+live+
			` WHERE r.to_asset = ANY($1) AND r.kind = 'built_from'`, []int64{root.ID})
		if err != nil {
			return nil, err
		}
		var deployed []int64
		for _, e := range in {
			if addMember(e.to, "deployment", "built_from", root.ID) {
				deployed = append(deployed, e.to)
			}
		}
		if len(deployed) > 0 {
			out, err := query(`SELECT r.from_asset, r.to_asset, r.kind FROM asset_relations r`+live+
				` WHERE r.from_asset = ANY($1) AND r.kind = 'runs_on'`, deployed)
			if err != nil {
				return nil, err
			}
			for _, e := range out {
				addMember(e.to, "host", "runs_on", e.from)
			}
		}
	}
	// Then everything the asset itself relies on.
	frontier := []int64{root.ID}
	for depth := 0; depth < maxStackDepth && len(frontier) > 0; depth++ {
		out, err := query(`SELECT r.from_asset, r.to_asset, r.kind FROM asset_relations r`+live+
			` WHERE r.from_asset = ANY($1) AND r.kind IN ('runs_on', 'built_from', 'deployed_as', 'depends_on', 'contains')
			ORDER BY r.kind, r.to_asset`, frontier)
		if err != nil {
			return nil, err
		}
		frontier = nil
		for _, e := range out {
			if addMember(e.to, stackRoles[e.kind], e.kind, e.from) {
				frontier = append(frontier, e.to)
			}
		}
	}

	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.kind, a.environment, `+effectiveExposure+`, a.criticality, a.collection_status
		FROM assets a WHERE a.id = ANY($1)`, order)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m StackMember
		if err := rows.Scan(&m.AssetID, &m.Name, &m.Kind, &m.Environment, &m.InternetExposed, &m.Criticality, &m.Status); err != nil {
			rows.Close()
			return nil, err
		}
		cur := members[m.AssetID]
		cur.Name, cur.Kind, cur.Environment, cur.InternetExposed, cur.Criticality, cur.Status =
			m.Name, m.Kind, m.Environment, m.InternetExposed, m.Criticality, m.Status
		if cur.Role == "host" && cur.Kind == "cluster" {
			cur.Role = "cluster" // a workload runs on a cluster, not a host
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	layers := map[string]*StackLayer{}
	for off := 0; off < maxStackFindings; off += 500 {
		page, total, err := s.ListFindings(ctx, FindingFilter{AssetIDs: order, Page: Page{Limit: 500, Offset: off}})
		if err != nil {
			return nil, err
		}
		for _, f := range page {
			layer := findingLayer(f, members[f.AssetID].Kind)
			st.Findings = append(st.Findings, StackFinding{Finding: f, Layer: layer})
			members[f.AssetID].Open++
			l := layers[layer]
			if l == nil {
				l = &StackLayer{Layer: layer, BySeverity: map[string]int{}}
				layers[layer] = l
			}
			l.Open++
			l.BySeverity[f.Severity]++
			if f.KnownExploited {
				l.Exploited++
			}
			if f.Overdue {
				l.Overdue++
			}
		}
		if int64(off+len(page)) >= total {
			break
		}
		if off+500 >= maxStackFindings {
			st.Truncated = true
		}
	}
	for _, id := range order {
		st.Members = append(st.Members, *members[id])
	}
	st.Layers = []StackLayer{}
	for _, name := range stackLayers {
		if l := layers[name]; l != nil {
			st.Layers = append(st.Layers, *l)
		}
	}
	return st, nil
}

// Component names that place a package in a layer other than "os" or
// "runtime". Prefix matches cover versioned and split packages
// (postgresql-16, apache2-bin, mysql-server-8.0).
var (
	webServerNames = []string{"nginx", "apache2", "httpd", "haproxy", "caddy", "traefik", "envoy", "lighttpd", "openresty", "tomcat", "varnish", "squid"}
	dataStoreNames = []string{"mysql", "mariadb", "postgresql", "postgres", "redis", "valkey", "mongodb", "mongod", "memcached",
		"meilisearch", "elasticsearch", "opensearch", "rabbitmq", "kafka", "clickhouse", "cassandra"}
	libraryTypes = map[string]bool{"npm": true, "pypi": true, "composer": true, "golang": true, "cargo": true, "gem": true,
		"nuget": true, "maven": true, "pub": true, "hex": true}
)

func hasNamePrefix(name string, prefixes []string) bool {
	name = strings.ToLower(name[strings.LastIndex(name, "/")+1:])
	for _, p := range prefixes {
		if name == p || strings.HasPrefix(name, p+"-") || strings.HasPrefix(name, p+"_") {
			return true
		}
	}
	return false
}

// findingLayer places a finding in the stack by its component and asset.
func findingLayer(f Finding, assetKind string) string {
	switch {
	case assetKind == "repository":
		return "declared" // what the code asks for, not necessarily what runs
	case assetKind == "managed_service":
		return "managed_service"
	case assetKind == "cluster" && osReleaseNames[f.ComponentName]:
		return "os" // a node operating system
	case assetKind == "cluster":
		return "platform" // Kubernetes, kubelet, container runtime
	case hasNamePrefix(f.ComponentName, webServerNames):
		return "web_server"
	case hasNamePrefix(f.ComponentName, dataStoreNames):
		return "data_store"
	case libraryTypes[f.ComponentType]:
		return "libraries"
	case f.ComponentType == "deb" || f.ComponentType == "rpm" || f.ComponentType == "apk":
		return "os"
	case f.ComponentType == "generic" && runtimeProducts[strings.ToLower(f.ComponentName)]:
		return "runtime"
	case f.ComponentType == "generic" && assetKind == "host":
		return "os" // the operating system release itself
	}
	return "other"
}

// osReleaseNames are the os-release ids reported as pkg:generic/<id>.
var osReleaseNames = map[string]bool{"debian": true, "ubuntu": true, "alpine": true, "rocky": true, "almalinux": true, "rhel": true,
	"centos": true, "amzn": true, "fedora": true, "opensuse-leap": true, "sles": true, "ol": true}

var runtimeProducts = map[string]bool{"nodejs": true, "python": true, "go": true, "ruby": true, "php": true}
