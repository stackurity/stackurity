// Package demo loads a small, clearly labelled estate so a new install has
// something to show before any agent or repository is connected: a server
// with outdated OS packages, an end-of-life runtime and a pending reboot, an
// application deployed on it with its repository, and a second repository.
// Findings appear once the intelligence feeds have synced.
package demo

import (
	"context"
	"fmt"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// Scheme marks every demo asset, so Remove finds exactly these.
const Scheme = "demo"

func obs(purl string, ev map[string]string) model.Observation {
	return model.Observation{Purl: purl, Confidence: model.ConfidenceConfirmed, Evidence: ev}
}

func batch(collector string, asset model.AssetRef, o ...model.Observation) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: collector, Version: "demo", Method: "demo"}, asset)
	b.ObservedAt = time.Now().UTC()
	b.Observations = o
	b.Cover("demo", "checked", "")
	b.Complete = true
	return b
}

// Load ingests the demo assets (again, if already present) and links them.
func Load(ctx context.Context, st *store.Store) ([]int64, error) {
	host := model.AssetRef{Kind: model.AssetHost, Name: "demo-web-1", Environment: "production",
		Identifiers: []model.Identifier{{Scheme: Scheme, Value: "host:web-1"}},
		Attributes: map[string]string{"os": "ubuntu", "os_version": "22.04", "os_name": "Ubuntu 22.04.3 LTS",
			"reboot_required": "true", "reboot_reason": "the package manager requested a reboot (libc6, libssl3)",
			"kernel_running": "5.15.0-88-generic", "kernel_latest_installed": "5.15.0-91-generic"}}
	const distro = "?arch=amd64&distro=ubuntu-22.04"
	osb := batch("linux-agent", host,
		obs("pkg:generic/ubuntu@22.04", map[string]string{"kind": "operating-system"}),
		obs("pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10"+distro+"&upstream=openssl", map[string]string{"source_package": "openssl"}),
		obs("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10"+distro, nil),
		obs("pkg:deb/ubuntu/nginx@1.18.0-6ubuntu14.3"+distro, nil),
		obs("pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.13"+distro, nil),
		obs("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.4"+distro+"&upstream=glibc", map[string]string{"source_package": "glibc"}),
	)
	sw := batch("linux-software", host,
		obs("pkg:generic/nodejs@16.20.2", map[string]string{"kind": "runtime", "install": "unmanaged", "binary": "/usr/local/bin/node"}))

	shopDeps := []model.Observation{
		obs("pkg:npm/express@4.17.1", nil), obs("pkg:npm/lodash@4.17.20", nil), obs("pkg:npm/axios@0.21.1", nil),
		obs("pkg:npm/jsonwebtoken@8.5.1", nil), obs("pkg:npm/next@13.4.0", nil),
	}
	repo := batch("lockfile", model.AssetRef{Kind: model.AssetRepository, Name: "demo-shop",
		Identifiers: []model.Identifier{{Scheme: Scheme, Value: "repo:shop"}, {Scheme: "git-url", Value: "https://example.com/demo/shop"}}},
		shopDeps...)
	billing := batch("lockfile", model.AssetRef{Kind: model.AssetRepository, Name: "demo-billing",
		Identifiers: []model.Identifier{{Scheme: Scheme, Value: "repo:billing"}}},
		obs("pkg:pypi/django@3.2.0", nil), obs("pkg:pypi/requests@2.25.0", nil), obs("pkg:pypi/pyyaml@5.3", nil),
		obs("pkg:pypi/jinja2@2.11.2", nil))

	var ids []int64
	for _, b := range []*model.ObservationBatch{osb, sw, repo, billing} {
		if err := b.Validate(); err != nil {
			return nil, err
		}
		r, err := st.Ingest(ctx, b, 0)
		if err != nil {
			return nil, err
		}
		ids = append(ids, r.AssetID)
	}
	hostID := ids[0]

	app := batch("linux-apps", model.AssetRef{Kind: model.AssetApplication, Name: "demo-shop on demo-web-1", Environment: "production",
		Identifiers: []model.Identifier{{Scheme: Scheme, Value: "app:shop"}},
		Attributes:  map[string]string{"app_dir": "/srv/shop", "host": "demo-web-1", "git_url": "https://example.com/demo/shop"}})
	for _, o := range shopDeps {
		o.Location = "/srv/shop/node_modules/" + o.Purl[len("pkg:npm/"):]
		o.Evidence = map[string]string{"source": "installed", "app_dir": "/srv/shop"}
		app.Observations = append(app.Observations, o)
	}
	app.Relations = []model.RelationRef{
		{Kind: "runs_on", To: []model.Identifier{{Scheme: Scheme, Value: "host:web-1"}}},
		{Kind: "built_from", To: []model.Identifier{{Scheme: Scheme, Value: "repo:shop"}}},
	}
	if err := app.Validate(); err != nil {
		return nil, err
	}
	r, err := st.Ingest(ctx, app, 0)
	if err != nil {
		return nil, err
	}
	ids = append(ids, r.AssetID)
	if _, err := st.Pool.Exec(ctx, `UPDATE assets SET internet_exposed = true, criticality = 'high' WHERE id = ANY($1)`,
		[]int64{hostID, r.AssetID}); err != nil {
		return nil, err
	}
	return ids, nil
}

// Remove deletes every demo asset and its history.
func Remove(ctx context.Context, st *store.Store) (int, error) {
	rows, err := st.Pool.Query(ctx, `SELECT DISTINCT asset_id FROM asset_identifiers WHERE scheme = $1`, Scheme)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := st.DeleteAsset(ctx, id); err != nil {
			return 0, fmt.Errorf("delete demo asset %d: %w", id, err)
		}
	}
	return len(ids), rows.Err()
}
