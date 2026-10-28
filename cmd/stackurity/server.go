package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/packs"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/collect/image"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/demo"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/metrics"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/plugins"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/updates"
	"github.com/stackurity/stackurity/internal/worker"
	"github.com/stackurity/stackurity/web"
)

func newLogger() *slog.Logger {
	var h slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if os.Getenv("STACKURITY_LOG_LEVEL") == "debug" {
		opts.Level = slog.LevelDebug
	}
	if os.Getenv("STACKURITY_LOG_FORMAT") == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func databaseURL() (string, error) {
	if u := os.Getenv("STACKURITY_DATABASE_URL"); u != "" {
		return u, nil
	}
	// Compose secrets: read the URL from a file.
	if f := os.Getenv("STACKURITY_DATABASE_URL_FILE"); f != "" {
		b, err := os.ReadFile(f)
		return strings.TrimSpace(string(b)), err
	}
	return "", errors.New("STACKURITY_DATABASE_URL is not set")
}

func openStore(ctx context.Context) (*store.Store, error) {
	url, err := databaseURL()
	if err != nil {
		return nil, err
	}
	pool, err := db.Open(ctx, url)
	if err != nil {
		return nil, err
	}
	// Every command that uses the database refuses one a newer version has
	// migrated: this version's code may not work with that schema.
	if err := db.CheckSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return store.New(pool), nil
}

func serverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Run the API, dashboard and background workers",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := newLogger()
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			tm, err := parseTimings(os.Getenv("STACKURITY_TEST_TIMINGS"))
			if err != nil {
				return err
			}
			if tm != defaultTimings() {
				log.Warn("STACKURITY_TEST_TIMINGS is set: background timings are shortened for testing", "timings", fmt.Sprintf("%+v", tm))
			}
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			st.JobLockTimeout = tm.JobLock
			applied, err := db.Migrate(ctx, st.Pool)
			if err != nil {
				return err
			}
			if len(applied) > 0 {
				log.Info("applied migrations", "migrations", applied)
			}
			// Reconnect as the application role a migration may have created.
			st.Pool.Reset()
			if err := checkIsolation(ctx, st, log); err != nil {
				return err
			}

			dataDir := env("STACKURITY_DATA_DIR", "/var/lib/stackurity")
			res := secrets.Resolver{AllowedDir: env("STACKURITY_SECRETS_DIR", "/run/secrets")}
			box, err := secrets.BoxFromEnv()
			switch {
			case errors.Is(err, secrets.ErrNoKey):
				log.Warn("stored secrets are disabled; workspaces can only use env: and file: secrets set by an instance admin", "fix", "set STACKURITY_SECRET_KEY")
			case err != nil:
				return err
			default:
				res.Stored = func(ctx context.Context, name string) (string, error) { return st.SecretValue(ctx, box, name) }
			}
			if err := netguard.FromEnv().Validate(); err != nil {
				return err
			}
			updateCfg, err := updates.ConfigFromEnv()
			if err != nil {
				return err
			}
			feedbackURL, err := api.FeedbackURLFromEnv()
			if err != nil {
				return err
			}
			holder, licFromEnv, err := loadLicence(ctx, st, log)
			if err != nil {
				return err
			}
			gate := &license.Gate{Licence: holder, Plan: license.CachedPlan(st.WorkspacePlan, 30*time.Second)}
			keys, err := packs.DefaultKeyring()
			if err != nil {
				return err
			}
			packMgr := &packs.Manager{Store: st, Keys: keys, Log: log, Gate: gate}
			if err := packMgr.Reload(ctx); err != nil {
				return fmt.Errorf("load stack packs: %w", err)
			}

			setupToken := ""
			if n, err := st.CountUsers(ctx); err != nil {
				return err
			} else if n == 0 {
				setupToken = os.Getenv("STACKURITY_SETUP_TOKEN")
				if setupToken == "" {
					b := make([]byte, 16)
					_, _ = rand.Read(b)
					// Every replica must accept the same token, whichever
					// one the browser reaches: the first to start stores it.
					if setupToken, err = st.SharedSetupToken(tenant.System(ctx), hex.EncodeToString(b)); err != nil {
						return err
					}
				}
				// Printed to stderr directly so it is visible with `docker compose logs`.
				fmt.Fprintf(os.Stderr, "\n  No users yet. Open the dashboard and complete setup with this one-time token:\n\n      %s\n\n", setupToken)
			} else if err := st.ClearSetupToken(tenant.System(ctx)); err != nil {
				return err
			}

			cookieSecure := env("STACKURITY_COOKIE_SECURE", "true") != "false"
			listenAddr := env("STACKURITY_LISTEN", ":8080")
			insecureCookies := cookieRisk(cookieSecure, os.Getenv("STACKURITY_BASE_URL"), listenAddr)
			if insecureCookies != "" {
				log.Warn("session cookies are not marked Secure (STACKURITY_COOKIE_SECURE=false); never run like this in production",
					"reason", insecureCookies,
					"fix", "serve Stackurity over HTTPS and remove STACKURITY_COOKIE_SECURE; for a local evaluation only, set STACKURITY_BASE_URL=http://localhost:<port>")
			}
			schema := &db.SchemaGuard{}
			checker := &health.Checker{Store: st, FeedsEnabled: os.Getenv("STACKURITY_FEEDS") != "off",
				PlatformWorkspace: os.Getenv("STACKURITY_PLATFORM_WORKSPACE"), Schema: schema, InsecureCookies: insecureCookies}
			if _, why, err := checker.PlatformTarget(ctx); err != nil {
				return err
			} else if why != "" {
				log.Warn("platform incidents are not raised; critical platform problems are logged instead", "reason", why,
					"fix", "set STACKURITY_PLATFORM_WORKSPACE to an active workspace id or slug")
			}
			allowHTTPHooks := os.Getenv("STACKURITY_ALLOW_HTTP_WEBHOOKS") == "true"
			dispatcher := &notify.Dispatcher{Store: st, Sender: notify.NewSender(allowHTTPHooks), Secrets: res, Log: log,
				BaseURL:  os.Getenv("STACKURITY_BASE_URL"),
				Escalate: func(ctx context.Context) bool { return gate.Has(ctx, license.Teams) },
				Platform: checker.PlatformIncidents, PlatformTarget: checker.PlatformTarget, Lease: tm.DeliveryLease}
			var pluginRunner *plugins.Runner
			if dir := os.Getenv("STACKURITY_PLUGIN_DIR"); dir != "" {
				pluginRunner = &plugins.Runner{Dir: dir, WorkDir: filepath.Join(dataDir, "work"), Timeout: 15 * time.Minute}
			}
			proCfg, err := proConfig(log)
			if err != nil {
				return err
			}
			// The Stackurity Slack app ("Add to Slack"), when configured.
			if dispatcher.SlackApp, err = notify.SlackAppFromEnv(); err != nil {
				return err
			}
			if dispatcher.SlackApp != nil {
				base := strings.TrimRight(os.Getenv("STACKURITY_BASE_URL"), "/")
				log.Info("Slack app enabled (Add to Slack)", "redirect_url", base+"/integrations/slack/oauth/callback",
					"interactivity_url", base+"/api/v1/integrations/slack/actions", "events_url", base+"/api/v1/integrations/slack/events")
				if box == nil {
					log.Warn("Add to Slack needs stored secrets to keep the webhooks and tokens it gets", "fix", "set STACKURITY_SECRET_KEY")
				}
			}
			// An edition may deliver email sent by Stackurity (hosted).
			if editionNotify != nil {
				if err := editionNotify(dispatcher, log); err != nil {
					return err
				}
			}
			challenge, err := envOrFile("STACKURITY_OPENAI_APPS_CHALLENGE")
			if err != nil {
				return err
			}
			srv := &api.Server{
				OpenAIAppsChallenge: challenge,
				Pro:                 proCfg,
				Dispatcher:          dispatcher, AllowHTTPWebhooks: allowHTTPHooks, Plugins: pluginRunner,
				Store: st, Log: log, Secrets: res, Version: version, SetupToken: setupToken,
				BaseURL: os.Getenv("STACKURITY_BASE_URL"), AgentDir: os.Getenv("STACKURITY_AGENT_DIR"),
				CookieSecure: cookieSecure,
				TrustProxy:   os.Getenv("STACKURITY_TRUST_PROXY") == "true",
				Schema:       schema,
				UI:           web.Dist(),
				SecretBox:    box,
				Packs:        packMgr,
				Licence:      holder, Gate: gate, LicenceFromEnv: licFromEnv,
				Health: checker, UpdateCheck: updateCfg.Enabled,
				FeedbackURL: feedbackURL,
			}
			// Metrics have their own listener, off by default, so they are
			// never reachable on the public API port.
			metricsAddr := os.Getenv("STACKURITY_METRICS_ADDR")
			if metricsAddr != "" {
				if metricsAddr == listenAddr {
					return errors.New("STACKURITY_METRICS_ADDR must differ from STACKURITY_LISTEN: metrics are never served on the API port")
				}
				srv.HTTPMetrics = metrics.NewHTTP()
			}
			httpSrv := &http.Server{
				Addr:              listenAddr,
				Handler:           srv.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       5 * time.Minute,
				WriteTimeout:      5 * time.Minute,
				IdleTimeout:       2 * time.Minute,
			}

			w := worker.New(st, log)
			w.Lease, w.Tick, w.Poll = tm.TaskLease, tm.Tick, tm.Poll
			// Periodic tasks running at shutdown may finish within the same
			// deadline as the HTTP server, then they are cancelled.
			w.ShutdownGrace = shutdownTimeout
			if tm.JobLock > 0 {
				w.JobRenew = min(w.JobRenew, tm.JobLock/6)
			}
			// A job or task that makes the heap grow past this is named in a
			// warning, while it runs (docs/operations.md, "Memory").
			if w.HeapWarn, err = heapWarn(os.Getenv("STACKURITY_HEAP_WARN_MIB")); err != nil {
				return err
			}
			registerJobs(w, st, res, dataDir, log, pluginRunner, packMgr)
			// Prioritise, correlate, plan and deliver notifications; none
			// for a read-only workspace.
			w.EveryCollectingWorkspace("alerts", tm.Alerts, dispatcher.Tick)
			w.EveryCollectingWorkspace("alert-digest", time.Hour, dispatcher.Digest)
			w.Every("platform-fallback", 10*time.Minute, dispatcher.PlatformFallback)
			registerPro(w, st, log, gate)
			// The release check sends nothing about this install (see
			// internal/updates); when it is off no request is made at all.
			updates.Register(ctx, w, st, log, updateCfg)
			// The worker stops when a newer version migrates the database
			// under this server (watchSchema); the API keeps answering, but
			// /readyz fails so traffic moves to the new replicas.
			workCtx, stopWork := context.WithCancel(ctx)
			defer stopWork()
			done := make(chan struct{})
			go func() { w.Run(workCtx); close(done) }()
			go followReplicas(ctx, st, holder, licFromEnv, packMgr, log)
			go watchSchema(ctx, st, schema, tm.SchemaCheck, stopWork, log)

			errc := make(chan error, 2)
			go func() {
				log.Info("listening", "addr", httpSrv.Addr, "version", version)
				errc <- httpSrv.ListenAndServe()
			}()
			var metricsSrv *http.Server
			if metricsAddr != "" {
				mux := http.NewServeMux()
				mux.Handle("/metrics", &metrics.Handler{Store: st, Health: checker, HTTP: srv.HTTPMetrics, Log: log,
					Version: version, Edition: edition, Started: time.Now()})
				// Heap and goroutine profiles, on this private port only.
				metrics.Profiles(mux)
				metricsSrv = &http.Server{Addr: metricsAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
					ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
				go func() {
					log.Info("serving metrics", "addr", metricsAddr, "path", "/metrics", "profiles", "/debug/pprof/heap, /debug/pprof/goroutine")
					errc <- metricsSrv.ListenAndServe()
				}()
			}
			select {
			case err := <-errc:
				if !errors.Is(err, http.ErrServerClosed) {
					return err
				}
			case <-ctx.Done():
			}
			log.Info("shutting down")
			sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			_ = httpSrv.Shutdown(sctx)
			if metricsSrv != nil {
				_ = metricsSrv.Shutdown(sctx)
			}
			<-done
			return nil
		},
	}
}

// editionNotify lets an edition built on the core configure notifications
// further (Stackurity Cloud sets the platform mail server for email sent by
// Stackurity, and its limits). Nil in the Community build.
var editionNotify func(d *notify.Dispatcher, log *slog.Logger) error

// shutdownTimeout is how long a stopping server lets requests and running
// periodic tasks finish.
const shutdownTimeout = 30 * time.Second

// loadLicence reads the licence from STACKURITY_LICENSE (or _FILE), which
// wins, or from the database. A licence that does not verify is ignored with
// a warning: Stackurity then runs as Community rather than not at all.
func loadLicence(ctx context.Context, st *store.Store, log *slog.Logger) (*license.Holder, bool, error) {
	h := &license.Holder{}
	key, fromEnv := os.Getenv("STACKURITY_LICENSE"), false
	if f := os.Getenv("STACKURITY_LICENSE_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, false, fmt.Errorf("read licence: %w", err)
		}
		key = string(b)
	}
	if strings.TrimSpace(key) != "" {
		fromEnv = true
	} else {
		var err error
		if key, err = st.LicenseKey(ctx); err != nil {
			return nil, false, err
		}
	}
	if strings.TrimSpace(key) == "" {
		log.Info("no licence: running as Stackurity Community")
		return h, fromEnv, nil
	}
	l, err := license.Parse(key)
	if err != nil {
		log.Warn("licence ignored; running as Community", "err", err)
		return h, fromEnv, nil
	}
	h.Set(l)
	s := h.Status()
	log.Info("licence", "customer", l.Customer, "edition", l.Edition, "state", s.State, "expires", l.ExpiresAt.Format("2006-01-02"))
	return h, fromEnv, nil
}

// followReplicas keeps state that another replica can change in step with
// the database: the licence (uploaded through any replica's dashboard) and
// the installed stack packs. Each replica checks every 30 seconds.
func followReplicas(ctx context.Context, st *store.Store, holder *license.Holder, licFromEnv bool, packMgr *packs.Manager, log *slog.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !licFromEnv {
			if err := refreshLicence(ctx, st, holder); err != nil && ctx.Err() == nil {
				log.Warn("refresh licence", "err", err)
			}
		}
		if err := packMgr.Refresh(ctx); err != nil && ctx.Err() == nil {
			log.Warn("refresh stack packs", "err", err)
		}
	}
}

// watchSchema checks every interval whether a newer version has migrated
// the database, which happens when an upgrade starts new replicas while this
// one still runs. Mixed versions are not supported, so once it has, the
// server stops its background work, fails /readyz and logs an error on every
// check until it is stopped.
func watchSchema(ctx context.Context, st *store.Store, g *db.SchemaGuard, every time.Duration, stopWork func(), log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := g.Check(tenant.System(ctx), st.Pool)
		switch {
		case errors.Is(err, db.ErrNewerSchema):
			stopWork()
			log.Error("database schema is newer than this server: background work stopped and /readyz fails; stop this replica",
				"err", err, "version", version)
		case err != nil && ctx.Err() == nil:
			log.Warn("check database schema version", "err", err)
		}
	}
}

// refreshLicence adopts the licence stored in the database if it differs
// from the one in effect. A key that does not verify means Community, as at
// start.
func refreshLicence(ctx context.Context, st *store.Store, h *license.Holder) error {
	key, err := st.LicenseKey(tenant.System(ctx))
	if err != nil {
		return err
	}
	var l *license.License
	if strings.TrimSpace(key) != "" {
		l, _ = license.Parse(key)
	}
	cur := h.License()
	if (cur == nil) == (l == nil) && (cur == nil || cur.ID == l.ID && cur.IssuedAt.Equal(l.IssuedAt) && cur.ExpiresAt.Equal(l.ExpiresAt)) {
		return nil
	}
	h.Set(l)
	return nil
}

// checkIsolation refuses to serve several workspaces when the database role
// ignores row-level security, and warns when only one exists.
func checkIsolation(ctx context.Context, st *store.Store, log *slog.Logger) error {
	err := db.CheckIsolation(ctx, st.Pool)
	if !errors.Is(err, db.ErrIsolationBypassed) {
		return err
	}
	ids, lerr := st.ActiveWorkspaceIDs(ctx)
	if lerr != nil {
		return lerr
	}
	if len(ids) > 1 {
		return err
	}
	log.Warn("workspace isolation is not enforced by the database", "reason", err)
	return nil
}

// imageScanFresh is how long a successful scan of an image reported by a
// plugin is reused. Running images are pinned to a digest, so their content
// cannot change; a rescan only picks up scanner improvements.
const imageScanFresh = 7 * 24 * time.Hour

func registerJobs(w *worker.Worker, st *store.Store, res secrets.Resolver, dataDir string, log *slog.Logger, pluginRunner *plugins.Runner, packMgr *packs.Manager) {
	scanner := &gitrepo.Scanner{WorkDir: filepath.Join(dataDir, "work"), Version: version, Packs: packMgr.Active}
	imageScanner := &image.Scanner{Syft: env("STACKURITY_SYFT", "syft"), Version: version, WorkDir: filepath.Join(dataDir, "work")}

	w.Handle("integration.run", func(ctx context.Context, payload json.RawMessage) error {
		var p struct {
			IntegrationID int64 `json:"integration_id"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		in, err := st.GetIntegration(ctx, p.IntegrationID)
		if errors.Is(err, store.ErrNotFound) {
			return nil // deleted since it was queued
		}
		if err != nil {
			return err
		}
		runErr := func() error {
			token, err := res.Resolve(ctx, in.SecretRef)
			if err != nil {
				return err
			}
			var b *model.ObservationBatch
			switch in.Kind {
			case api.KindGitRepository:
				var cfg gitrepo.Config
				if err := json.Unmarshal(in.Config, &cfg); err != nil {
					return err
				}
				b, err = scanner.Scan(ctx, cfg, token)
			case api.KindContainerImage:
				var cfg image.Config
				if err := json.Unmarshal(in.Config, &cfg); err != nil {
					return err
				}
				b, err = imageScanner.Scan(ctx, cfg, token)
			case api.KindPlugin:
				if pluginRunner == nil {
					return errors.New("plugins are disabled (STACKURITY_PLUGIN_DIR not set)")
				}
				// Without credentials the plugin would use the server's own.
				if token == "" && !netguard.AllowsPrivate(ctx) {
					return errors.New("plugins in this workspace need credentials (a stored secret)")
				}
				var cfg api.PluginConfig
				if err := json.Unmarshal(in.Config, &cfg); err != nil {
					return err
				}
				// The secret, if any, is a JSON object of the credentials
				// the plugin declares (e.g. {"bearer_token": "..."}).
				creds := map[string]string{}
				if token != "" {
					if err := json.Unmarshal([]byte(token), &creds); err != nil {
						return errors.New("plugin secrets must be a JSON object of credential names to values")
					}
				}
				batches, logs, err := pluginRunner.Collect(ctx, cfg.Plugin, cfg.Config, creds)
				if logs != "" {
					log.Info("plugin output", "plugin", cfg.Plugin, "stderr", truncateLog(logs))
				}
				if err != nil {
					return err
				}
				// At the monitored-asset limit new assets are left out; the
				// ones already monitored are still updated.
				results, refused, err := st.IngestAll(ctx, batches, 0)
				if err != nil {
					return err
				}
				var last int64
				var scans []store.ImageScan
				for i, pb := range batches {
					r := results[i]
					if r == nil {
						continue
					}
					last = r.AssetID
					// Images the plugin found running are read by the image
					// scanner, in the order the plugin gave (most important first).
					if ic, ok := image.ReferenceOnly(pb); ok {
						scans = append(scans, store.ImageScan{AssetID: r.AssetID, Image: ic.Image, Platform: ic.Platform})
					}
				}
				if limit := cfg.ImageScanLimit(); len(scans) > 0 && limit > 0 {
					stats, err := st.QueueImageScans(ctx, scans, limit, imageScanFresh)
					if err != nil {
						return err
					}
					log.Info("image scans", "plugin", cfg.Plugin, "images", len(scans), "queued", stats.Queued,
						"fresh", stats.Fresh, "pending", stats.Pending, "deferred", stats.Limited)
				}
				if len(refused) > 0 {
					return st.IntegrationResult(ctx, in.ID, last, assetLimitNote(len(refused), len(batches)))
				}
				return st.IntegrationResult(ctx, in.ID, last, nil)
			default:
				return fmt.Errorf("unsupported integration kind %q", in.Kind)
			}
			if err != nil {
				return err
			}
			if err := b.Validate(); err != nil {
				return err
			}
			r, err := st.Ingest(ctx, b, 0)
			if err != nil {
				return err
			}
			return st.IntegrationResult(ctx, in.ID, r.AssetID, nil)
		}()
		if runErr != nil {
			_ = st.IntegrationResult(context.WithoutCancel(ctx), in.ID, 0, runErr)
		}
		if errors.Is(runErr, store.ErrAssetLimit) || errors.Is(runErr, store.ErrReadOnly) {
			return nil // recorded on the integration; trying again cannot help
		}
		return runErr
	})

	// Images reported running by a plugin (Kubernetes) are read without
	// credentials. A failure is recorded as coverage on the image, so a
	// registry that needs a pull secret shows as not assessed, never clean.
	w.Handle("image.scan", func(ctx context.Context, payload json.RawMessage) error {
		var p store.ImageScan
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		cfg := image.Config{Image: p.Image, Platform: p.Platform}
		b, err := imageScanner.Scan(ctx, cfg, "")
		if err == nil {
			err = b.Validate()
		}
		if err != nil {
			if ctx.Err() != nil {
				return err // shutting down or timed out: try again
			}
			fb := model.NewBatch(model.Collector{ID: store.ImageScanCollector, Version: version, Method: "scanner"}, model.AssetRef{
				Kind: model.AssetImage, Name: p.Image, Identifiers: []model.Identifier{{Scheme: "image-ref", Value: p.Image}},
			})
			msg := err.Error()
			if len(msg) > 1000 {
				msg = msg[:1000]
			}
			fb.Cover("image:"+p.Image, "failed", msg)
			_, ierr := st.Ingest(ctx, fb, 0)
			if errors.Is(ierr, store.ErrAssetLimit) || errors.Is(ierr, store.ErrReadOnly) {
				return nil
			}
			return ierr
		}
		_, err = st.Ingest(ctx, b, 0)
		if errors.Is(err, store.ErrAssetLimit) || errors.Is(err, store.ErrReadOnly) {
			return nil // no room for the image asset (deleted meanwhile), or nothing is collected now
		}
		return err
	})

	registerIntel(w, st, dataDir, log)

	w.EveryCollectingWorkspace("enqueue-due-integrations", time.Minute, func(ctx context.Context) error {
		due, err := st.DueIntegrations(ctx)
		if err != nil {
			return err
		}
		for _, in := range due {
			key := fmt.Sprintf("integration:%d", in.ID)
			if _, err := st.Enqueue(ctx, "integration.run", map[string]int64{"integration_id": in.ID}, key, time.Time{}); err != nil {
				return err
			}
		}
		return nil
	})
	staleAfter := 48 * time.Hour
	if d, err := time.ParseDuration(os.Getenv("STACKURITY_STALE_AFTER")); err == nil && d > 0 {
		staleAfter = d
	}
	// Check again: complete the checks whose fresh report has been
	// evaluated (all workspaces at once; the query reads open checks only).
	w.Every("complete-checks", 30*time.Second, func(ctx context.Context) error {
		n, err := st.CompleteChecks(ctx)
		if n > 0 {
			log.Info("checks completed", "count", n)
		}
		return err
	})
	w.EveryWorkspace("mark-stale-assets", 10*time.Minute, func(ctx context.Context) error {
		n, err := st.MarkStaleAssets(ctx, staleAfter)
		if n > 0 {
			log.Warn("assets marked stale", "count", n, "after", staleAfter)
		}
		return err
	})
	// The independent second check of high-impact findings runs as a job,
	// never inside the periodic tick: periodic tasks share a few slots, and
	// a long check must not hold one. The tick only asks
	// (bounded to a few seconds) whether anything is waiting and queues one
	// job per workspace; the job checks a batch of 500 findings.
	checker := &secondcheck.Runner{Store: st, Log: log}
	w.Handle("second.check", func(ctx context.Context, _ json.RawMessage) error {
		// Recording second checks writes rows an evaluation deletes and
		// rewrites: not while one runs.
		release, err := st.LockEvaluations(ctx)
		if errors.Is(err, store.ErrEvaluationBusy) {
			return worker.Defer(5*time.Second+mrand.N(10*time.Second), "an evaluation of this workspace is running")
		}
		if err != nil {
			return err
		}
		defer release()
		n, err := checker.Run(ctx)
		if n.Checked > 0 {
			log.Info("second check", "checked", n.Checked, "agreed", n.Agreed, "disagreed", n.Disagreed, "could_not_check", n.CouldNotCheck)
		}
		return err
	})
	w.EveryCollectingWorkspace("second-check", time.Minute, func(ctx context.Context) error {
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		waiting, err := st.SecondCheckWaiting(qctx)
		if err != nil || !waiting {
			return err
		}
		_, err = st.Enqueue(ctx, "second.check", map[string]any{}, "second-check", time.Time{})
		return err
	})
	w.Every("housekeeping", time.Hour, func(ctx context.Context) error {
		if err := st.PurgeExpiredSessions(ctx); err != nil {
			return err
		}
		if _, err := st.PurgeRateLimits(ctx); err != nil {
			return err
		}
		// Unused assistant registrations, old codes and tokens.
		if err := st.PruneOAuth(ctx); err != nil {
			return err
		}
		return st.PurgeJobs(ctx, 14*24*time.Hour)
	})
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply database migrations and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			applied, err := db.Migrate(cmd.Context(), st.Pool)
			if err != nil {
				return err
			}
			fmt.Printf("applied %d migration(s) %v\n", len(applied), applied)
			return nil
		},
	}
}

func adminCmd() *cobra.Command {
	c := &cobra.Command{Use: "admin", Short: "Administrative commands that talk to the database directly"}
	var workspace int64
	c.PersistentFlags().Int64Var(&workspace, "workspace", tenant.DefaultWorkspace, "workspace id the command acts in")
	// wctx scopes a command to the chosen workspace.
	wctx := func(cmd *cobra.Command) context.Context { return tenant.WithWorkspace(cmd.Context(), workspace) }

	var email, name, role string
	createUser := &cobra.Command{
		Use:   "create-user",
		Short: "Create a user (password read from STACKURITY_PASSWORD or stdin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			pw, err := readSecretInput("STACKURITY_PASSWORD", "Password: ")
			if err != nil {
				return err
			}
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			if _, err := db.Migrate(cmd.Context(), st.Pool); err != nil {
				return err
			}
			st.Pool.Reset()
			u, err := st.CreateUser(wctx(cmd), email, name, auth.Role(role), pw)
			if err != nil {
				return err
			}
			_ = st.Audit(wctx(cmd), store.Actor{Type: "system", Name: "cli"}, "user.create", "user", fmt.Sprint(u.ID), map[string]any{"email": u.Email, "role": u.Role})
			fmt.Printf("created user %d (%s, %s)\n", u.ID, u.Email, u.Role)
			return nil
		},
	}
	createUser.Flags().StringVar(&email, "email", "", "email address (required)")
	createUser.Flags().StringVar(&name, "name", "", "display name")
	createUser.Flags().StringVar(&role, "role", "admin", "viewer, engineer, security or admin")
	_ = createUser.MarkFlagRequired("email")

	var tokName, tokRole string
	var ttl time.Duration
	createToken := &cobra.Command{
		Use:   "create-token",
		Short: "Create a collector token for agents and CI (printed once)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if auth.Role(tokRole) != auth.RoleCollector {
				return errors.New("only collector tokens can be created here; create user tokens in the dashboard")
			}
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			t, secret, err := st.CreateToken(wctx(cmd), tokName, auth.RoleCollector, nil, 0, ttl)
			if err != nil {
				return err
			}
			_ = st.Audit(wctx(cmd), store.Actor{Type: "system", Name: "cli"}, "token.create", "token", fmt.Sprint(t.ID), map[string]any{"name": t.Name, "role": t.Role})
			fmt.Println(secret)
			return nil
		},
	}
	createToken.Flags().StringVar(&tokName, "name", "", "token name (required)")
	createToken.Flags().StringVar(&tokRole, "role", "collector", "token role")
	createToken.Flags().DurationVar(&ttl, "ttl", 0, "expiry, e.g. 8760h (0 = never)")
	_ = createToken.MarkFlagRequired("name")

	var removeDemo bool
	loadDemo := &cobra.Command{
		Use:   "load-demo",
		Short: "Load a small labelled demo estate (a server, an application and two repositories) to try Stackurity",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			if removeDemo {
				n, err := demo.Remove(wctx(cmd), st)
				if err == nil {
					fmt.Printf("removed %d demo assets\n", n)
				}
				return err
			}
			ids, err := demo.Load(wctx(cmd), st)
			if err != nil {
				return err
			}
			fmt.Printf("loaded %d demo assets (names start with demo-). Findings appear once the vulnerability feeds have synced,\n"+
				"usually within a few minutes; see Intelligence for feed status. Remove them with: stackurity admin load-demo --remove\n", len(ids))
			return nil
		},
	}
	loadDemo.Flags().BoolVar(&removeDemo, "remove", false, "delete the demo assets instead")

	var wsName, wsSlug, wsAdmin, wsAdminName string
	createWorkspace := &cobra.Command{
		Use:   "create-workspace",
		Short: "Create a workspace for another organisation and its first admin",
		Long: "Creates a workspace. The admin is an existing account with that email, or a new account\n" +
			"whose password is read from STACKURITY_PASSWORD or stdin.",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			pw := ""
			if n, err := st.UserExists(cmd.Context(), wsAdmin); err != nil {
				return err
			} else if !n {
				if pw, err = readSecretInput("STACKURITY_PASSWORD", "Password for the new admin: "); err != nil {
					return err
				}
			}
			ws, u, err := st.CreateWorkspace(cmd.Context(), wsName, wsSlug, wsAdmin, wsAdminName, pw)
			if err != nil {
				return err
			}
			_ = st.Audit(tenant.WithWorkspace(cmd.Context(), ws.ID), store.Actor{Type: "system", Name: "cli"}, "workspace.create",
				"workspace", fmt.Sprint(ws.ID), map[string]any{"name": ws.Name, "admin": u.Email})
			fmt.Printf("created workspace %d (%s, slug %s) with admin %s\n", ws.ID, ws.Name, ws.Slug, u.Email)
			return nil
		},
	}
	createWorkspace.Flags().StringVar(&wsName, "name", "", "workspace name (required)")
	createWorkspace.Flags().StringVar(&wsSlug, "slug", "", "short id for URLs (default: from the name)")
	createWorkspace.Flags().StringVar(&wsAdmin, "admin-email", "", "email of the first admin (required)")
	createWorkspace.Flags().StringVar(&wsAdminName, "admin-name", "", "display name for a new admin account")
	_ = createWorkspace.MarkFlagRequired("name")
	_ = createWorkspace.MarkFlagRequired("admin-email")

	listWorkspaces := &cobra.Command{
		Use:   "list-workspaces",
		Short: "List workspaces with their members and assets",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			wss, err := st.ListWorkspaces(cmd.Context())
			if err != nil {
				return err
			}
			for _, w := range wss {
				state := "active"
				if w.DisabledAt != nil {
					state = "disabled"
				}
				fmt.Printf("%d\t%s\t%s\t%d members\t%d assets\t%s\n", w.ID, w.Slug, w.Name, w.MemberCount, w.AssetCount, state)
			}
			return nil
		},
	}

	var renameTo string
	renameWorkspace := &cobra.Command{
		Use:   "rename-workspace",
		Short: "Rename the workspace given by --workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			if err := st.UpdateWorkspace(cmd.Context(), workspace, store.WorkspaceUpdate{Name: &renameTo}); err != nil {
				return err
			}
			fmt.Printf("workspace %d is now %q\n", workspace, renameTo)
			return nil
		},
	}
	renameWorkspace.Flags().StringVar(&renameTo, "name", "", "new name (required)")
	_ = renameWorkspace.MarkFlagRequired("name")

	setLicence := &cobra.Command{
		Use:   "set-license",
		Short: "Install a licence key (read from STACKURITY_LICENSE_KEY or stdin); restart the server to apply",
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := readSecretInput("STACKURITY_LICENSE_KEY", "Licence key: ")
			if err != nil {
				return err
			}
			l, err := license.Parse(key)
			if err != nil {
				return err
			}
			st, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Pool.Close()
			if err := st.SaveLicenseKey(cmd.Context(), strings.TrimSpace(key), 0); err != nil {
				return err
			}
			_ = st.Audit(tenant.System(cmd.Context()), store.Actor{Type: "system", Name: "cli"}, "license.install", "license", l.ID,
				map[string]any{"customer": l.Customer, "edition": l.Edition, "expires_at": l.ExpiresAt})
			fmt.Printf("installed %s licence for %s until %s; restart the server to apply\n", l.Edition, l.Customer, l.ExpiresAt.Format("2006-01-02"))
			return nil
		},
	}

	c.AddCommand(createUser, createToken, loadDemo, createWorkspace, listWorkspaces, renameWorkspace, setLicence)
	return c
}

// intelConfig reads feed locations from the environment so air-gapped
// installs can use mirrors (STACKURITY_OSV_URL etc.).
func intelConfig(dataDir string) intel.Config {
	cfg := intel.DefaultConfig()
	cfg.OSVBaseURL = env("STACKURITY_OSV_URL", cfg.OSVBaseURL)
	cfg.KEVURL = env("STACKURITY_KEV_URL", cfg.KEVURL)
	cfg.EndOfLifeURL = env("STACKURITY_ENDOFLIFE_URL", cfg.EndOfLifeURL)
	cfg.NpmRegistry = env("STACKURITY_NPM_REGISTRY", cfg.NpmRegistry)
	cfg.AmazonLinuxURL = env("STACKURITY_AMAZON_LINUX_URL", cfg.AmazonLinuxURL)
	cfg.PackagistURL = env("STACKURITY_PACKAGIST_URL", cfg.PackagistURL)
	cfg.PyPIURL = env("STACKURITY_PYPI_URL", cfg.PyPIURL)
	cfg.GoProxyURL = env("STACKURITY_GOPROXY_URL", cfg.GoProxyURL)
	cfg.CratesIndexURL = env("STACKURITY_CRATES_INDEX_URL", cfg.CratesIndexURL)
	cfg.RubyGemsURL = env("STACKURITY_RUBYGEMS_URL", cfg.RubyGemsURL)
	cfg.NuGetURL = env("STACKURITY_NUGET_URL", cfg.NuGetURL)
	cfg.MavenURL = env("STACKURITY_MAVEN_URL", cfg.MavenURL)
	cfg.PubURL = env("STACKURITY_PUB_URL", cfg.PubURL)
	cfg.WorkDir = filepath.Join(dataDir, "work")
	// Registries ask automated clients to identify themselves.
	cfg.UserAgent = "stackurity/" + version + " (+https://github.com/stackurity/stackurity)"
	return cfg
}

func registerIntel(w *worker.Worker, st *store.Store, dataDir string, log *slog.Logger) {
	cfg := intelConfig(dataDir)
	syncer := intel.NewSyncer(st, log, cfg)
	eval := &intel.Evaluator{Store: st}
	feedsOn := os.Getenv("STACKURITY_FEEDS") != "off"
	// Re-evaluation is queued before the feed's cursor moves on, so a crash
	// in between makes the retried sync queue it again rather than lose it.
	syncer.Changed = func(ctx context.Context, feed string, res *intel.SyncResult) error {
		ids, err := intel.ComponentsToEvaluate(ctx, st, feed, res)
		if err != nil || len(ids) == 0 {
			return err
		}
		log.Info("feed changed; re-evaluating", "feed", feed, "records", res.Changed, "components", len(ids))
		// Each workspace evaluates the changed components it has (none
		// that is read-only).
		wss, err := st.CollectingWorkspaceIDs(ctx)
		if err != nil {
			return err
		}
		for _, ws := range wss {
			if _, err := st.Enqueue(tenant.WithWorkspace(ctx, ws), "evaluate", map[string]any{"component_ids": ids}, "", time.Time{}); err != nil {
				return err
			}
		}
		return nil
	}

	// A full archive (Ubuntu is about 750 MB) can take longer than the
	// default job timeout on a small server.
	w.HandleTimeout("feed.sync", 3*time.Hour, func(ctx context.Context, payload json.RawMessage) error {
		var p struct {
			Feed string `json:"feed"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
			return err
		}
		_, err := syncer.Sync(ctx, p.Feed)
		return err
	})

	w.Handle("evaluate", func(ctx context.Context, payload json.RawMessage) error {
		var p struct {
			AssetID      int64   `json:"asset_id"`
			ComponentIDs []int64 `json:"component_ids"`
			All          bool    `json:"all"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		var comps []int64
		if !p.All && p.AssetID == 0 {
			comps = p.ComponentIDs
			if comps == nil {
				comps = []int64{}
			}
		}
		start, err := st.DBNow(ctx)
		if err != nil {
			return err
		}
		// The evaluation, and the priorities of what it found, run under the
		// workspace's evaluation lock: the dispatcher's upkeep of the same
		// findings waits for it rather than lock them in another order.
		release, err := st.LockEvaluations(ctx)
		if errors.Is(err, store.ErrEvaluationBusy) {
			// Another evaluation of this workspace runs: try again shortly,
			// leaving the worker slot to other jobs meanwhile.
			return worker.Defer(5*time.Second+mrand.N(10*time.Second), "another evaluation of this workspace is running")
		}
		if err != nil {
			return err
		}
		defer release()
		stats, err := eval.EvaluateLocked(ctx, comps, p.AssetID)
		if err != nil {
			return err
		}
		log.Info("evaluated", "asset", p.AssetID, "components", len(p.ComponentIDs), "all", p.All,
			"rows", stats.Rows, "opened", stats.Opened, "resolved", stats.Resolved, "gaps", stats.Gaps)
		if comps != nil {
			return nil // a partial run says nothing about whole assets
		}
		// Score the findings before the asset counts as evaluated: a CI
		// gate reading the collection result must see real priorities.
		policy, err := st.RiskPolicy(ctx)
		if err != nil {
			return err
		}
		if _, err := st.PrioritizeAsset(ctx, policy, time.Now(), p.AssetID); err != nil {
			return fmt.Errorf("prioritize: %w", err)
		}
		return st.MarkEvaluated(ctx, p.AssetID, start)
	})

	if !feedsOn {
		log.Warn("STACKURITY_FEEDS=off: intelligence feeds will not be created or refreshed")
		return
	}
	enqueueDueFeeds := func(ctx context.Context) error {
		due, err := st.DueFeeds(ctx)
		if err != nil {
			return err
		}
		for _, f := range due {
			if _, err := st.Enqueue(ctx, "feed.sync", map[string]string{"feed": f.Name}, "feed:"+f.Name, time.Time{}); err != nil {
				return err
			}
		}
		return nil
	}
	// Periodic tasks run side by side, so enqueue-due-feeds may run before a
	// feed exists: ensure-feeds queues the feeds it finds due too, so that a
	// new feed (on first start, or for a new ecosystem) syncs at once rather
	// than a minute later. A feed's sync is queued once (keyed by feed).
	w.Every("ensure-feeds", time.Minute, func(ctx context.Context) error {
		if err := intel.EnsureFeeds(ctx, st); err != nil {
			return err
		}
		return enqueueDueFeeds(ctx)
	})
	w.Every("enqueue-due-feeds", time.Minute, enqueueDueFeeds)
	// Affected entries no advisory refers to any more (advisories changed or
	// withdrawn). It reads every package row once, so daily.
	w.Every("prune-affected-values", 24*time.Hour, func(ctx context.Context) error {
		n, err := st.PruneAffectedValues(ctx)
		if n > 0 {
			log.Info("pruned unreferenced advisory data", "values", n)
		}
		return err
	})
	// Lifecycle dates pass without any feed change, so evaluate everything
	// daily; not a read-only workspace, whose findings stay as they were.
	w.EveryCollectingWorkspace("daily-evaluation", 24*time.Hour, func(ctx context.Context) error {
		_, err := st.Enqueue(ctx, "evaluate", map[string]bool{"all": true}, "evaluate:all", time.Now().Add(10*time.Minute))
		return err
	})
}

func truncateLog(s string) string {
	if len(s) > 2000 {
		return s[:2000] + "…"
	}
	return s
}

// assetLimitNote is the integration result when the organisation's
// monitored-asset limit kept some of a plugin's assets out.
func assetLimitNote(refused, total int) error {
	return fmt.Errorf("%d of %d assets were not added because this organisation is at its monitored-asset limit; "+
		"the assets already monitored were updated. See Settings, Usage: %w", refused, total, store.ErrAssetLimit)
}

// heapWarn parses STACKURITY_HEAP_WARN_MIB: the heap growth, in MiB,
// during one job or periodic task above which a warning names it. Empty is
// the default (worker.DefaultHeapWarn), "off" turns the warning off.
func heapWarn(v string) (int64, error) {
	switch v = strings.TrimSpace(v); v {
	case "":
		return 0, nil
	case "off":
		return -1, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("STACKURITY_HEAP_WARN_MIB must be a positive number of MiB or off, not %q", v)
	}
	return n << 20, nil
}

// envOrFile reads NAME, or the file NAME_FILE names (which wins), trimmed.
func envOrFile(name string) (string, error) {
	v := os.Getenv(name)
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", name, err)
		}
		v = string(b)
	}
	return strings.TrimSpace(v), nil
}
