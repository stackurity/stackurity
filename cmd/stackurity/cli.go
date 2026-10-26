package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stackurity/stackurity/internal/packs"
	"io"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/agentfix"
	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/sbom"
)

// connection flags shared by commands that talk to a server.
type conn struct {
	server    string
	token     string
	tokenFile string
}

func (c *conn) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&c.server, "server", os.Getenv("STACKURITY_SERVER"), "server URL (env STACKURITY_SERVER)")
	cmd.Flags().StringVar(&c.tokenFile, "token-file", os.Getenv("STACKURITY_TOKEN_FILE"), "file containing the API token (env STACKURITY_TOKEN_FILE)")
}

// client builds an API client. Tokens come from a file or STACKURITY_TOKEN,
// never from a flag, so they do not leak into shell history or ps output.
func (c *conn) client() (*client.Client, error) {
	if c.server == "" {
		return nil, errors.New("--server or STACKURITY_SERVER is required")
	}
	tok := os.Getenv("STACKURITY_TOKEN")
	if c.tokenFile != "" {
		b, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read token file: %w", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		return nil, errors.New("no token: set STACKURITY_TOKEN or --token-file")
	}
	return client.New(c.server, tok, version)
}

func readSecretInput(envKey, prompt string) (string, error) {
	if v := os.Getenv(envKey); v != "" {
		return v, nil
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func printResult(r *client.IngestResult) {
	fmt.Printf("asset %d: %d observations stored (collection %d, %d removed)", r.AssetID, r.Observations, r.CollectionID, r.Removed)
	if r.NewAsset {
		fmt.Print(", new asset")
	}
	fmt.Println()
	if len(r.Conflict) > 0 {
		fmt.Printf("warning: identifiers match several assets %v; an admin should resolve the conflict\n", r.Conflict)
	}
}

// hostOptions configures the platform's host collector.
type hostOptions struct {
	root         string
	runtimes     bool
	appDirs      []string
	discoverApps bool
	// packs returns the server's stack packs for one collection and a
	// function that unloads them; nil when there is no server to ask.
	packs func(ctx context.Context) ([]lockfile.Extension, func())
}

// remotePacks offers the server's stack packs to local scans: each is
// downloaded, checked against this build's keyring and loaded only when a file
// it reads is found. Failures only mean fewer file types are read.
func remotePacks(cl *client.Client) func(ctx context.Context) ([]lockfile.Extension, func()) {
	return func(ctx context.Context) ([]lockfile.Extension, func()) {
		keys, err := packs.DefaultKeyring()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: stack packs not used: %v\n", err)
			return nil, func() {}
		}
		r := &packs.Remote{Keys: keys, Get: func(ctx context.Context, path string, w io.Writer) error {
			return cl.Do(ctx, "GET", path, nil, nil, w)
		}}
		exts, err := r.Extensions(ctx)
		if err != nil {
			var ae *client.APIError
			if !(errors.As(err, &ae) && ae.Status == 404) { // 404: an older server, or packs turned off
				fmt.Fprintf(os.Stderr, "warning: stack packs not used: %v\n", err)
			}
			return nil, func() {}
		}
		return exts, func() { r.Close(context.WithoutCancel(ctx)) }
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeBatch(path string, b *model.ObservationBatch) error { return writeJSON(path, b) }

func writeJSON(path string, v any) error {
	var w io.Writer = os.Stdout
	if path != "-" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func agentCmd() *cobra.Command {
	var c conn
	var interval, actionInterval, checkInterval time.Duration
	var once, remediate, noRuntimes, discoverApps, noPacks bool
	var root, envName, output, allowFile string
	var appDirs []string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Collect OS and package inventory from this Linux host and report it",
		Long: `Reads /etc/os-release and the dpkg, rpm or apk package database and sends
the result to the server. Without --remediate it never installs, removes or
changes software, and runs fine as an unprivileged user.

It also looks for runtimes and servers installed outside the package manager
(Node.js, Python, Go, Ruby, PHP, Redis, Valkey, MySQL, MariaDB, PostgreSQL,
MongoDB, nginx, HAProxy, Meilisearch) and reports their versions. To read a
version it runs the binary's --version flag, but only for binaries owned by
root or the agent's own user that no other user can modify, and never under a
--root other than /. Use --no-runtimes to turn this off.

With --remediate (root required) the agent also applies upgrades the server
has approved for this host, but only for packages matching the local
allowlist file. Each change is dry-run first, applied through the package
manager, health-checked, and followed by a fresh inventory collection so the
server can verify it. Remediation needs a token bound to this host.

Between collections the agent asks the server about once a minute whether
someone pressed Check again in the dashboard, and reports at once if so
(--check-interval, 0 turns it off). The question is a small GET with the
agent's own token; it never changes anything on the host.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := &hostOptions{root: root, runtimes: !noRuntimes, appDirs: appDirs, discoverApps: discoverApps}
			hostCollect, err := hostCollector(opts)
			if err != nil {
				return err
			}
			collect := func(ctx context.Context) ([]*model.ObservationBatch, error) {
				bs, err := hostCollect(ctx)
				if err != nil {
					return nil, err
				}
				for _, b := range bs {
					b.Asset.Environment = envName
					if err := b.Validate(); err != nil {
						return nil, fmt.Errorf("%s batch for %s: %w", b.Collector.ID, b.Asset.Name, err)
					}
				}
				return bs, nil
			}
			if output != "" {
				bs, err := collect(cmd.Context())
				if err != nil {
					return err
				}
				return writeJSON(output, bs)
			}
			cl, err := c.client()
			if err != nil {
				return err
			}
			if !noPacks {
				opts.packs = remotePacks(cl)
			}
			var fixer *agentfix.Fixer
			if remediate {
				if runtime.GOOS != "linux" {
					return errors.New("--remediate is only supported on Linux hosts")
				}
				if root != "/" {
					return errors.New("--remediate only works on the live host (--root /)")
				}
				allow, err := agentfix.LoadAllowlist(allowFile)
				if err != nil {
					return fmt.Errorf("%w: %v", agentfix.ErrNoAllowlist, err)
				}
				if len(allow) == 0 {
					return agentfix.ErrNoAllowlist
				}
				fixer = agentfix.New(allow)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// report sends every batch, the host's OS packages first, and
			// returns those for remediation. A failed application batch is
			// reported but does not fail the host's collection.
			// assetIDs are the assets the last report went to, which the
			// agent asks about when it polls for check-again requests.
			var assetIDs []int64
			report := func() (*model.ObservationBatch, error) {
				bs, err := collect(ctx)
				if err != nil {
					return nil, err
				}
				var ids []int64
				for i, b := range bs {
					r, err := cl.Ingest(ctx, b)
					if err != nil {
						if i == 0 {
							return nil, err
						}
						fmt.Fprintf(os.Stderr, "%s batch for %s failed: %v\n", b.Collector.ID, b.Asset.Name, err)
						continue
					}
					printResult(r)
					ids = append(ids, r.AssetID)
				}
				assetIDs = ids
				return bs[0], nil
			}
			remediateOnce := func(current *model.ObservationBatch) {
				if fixer == nil {
					return
				}
				acts, err := cl.AgentActions(ctx)
				if err != nil {
					fmt.Fprintln(os.Stderr, "fetch remediation actions:", err)
					return
				}
				if len(acts) == 0 {
					return
				}
				installed := map[string]string{}
				if current != nil {
					for _, o := range current.Observations {
						if pu, err := packageurl.FromString(o.Purl); err == nil {
							installed[pu.Name] = o.Version
							if o.Evidence["evr"] != "" {
								installed[pu.Name] = o.Evidence["evr"]
							}
						}
					}
				}
				fixer.Installed = func(pkg string) (string, bool) { v, ok := installed[pkg]; return v, ok }
				for _, a := range acts {
					fmt.Printf("remediation %d: %s %s -> %s via %s\n", a.ID, a.Package, a.FromVersion, a.ToVersion, a.Manager)
					rep := fixer.Apply(ctx, agentfix.Action{ID: a.ID, Kind: a.Kind, Package: a.Package, Manager: a.Manager,
						FromVersion: a.FromVersion, ToVersion: a.ToVersion, HealthUnits: a.HealthUnits})
					if rep.Phase == "failed" {
						fmt.Fprintf(os.Stderr, "remediation %d failed: %s\n", a.ID, rep.Error)
					}
					if err := cl.ReportAction(ctx, a.ID, rep); err != nil {
						fmt.Fprintln(os.Stderr, "report remediation result:", err)
					}
				}
				// Re-collect immediately so the server can verify the change.
				if _, err := report(); err != nil {
					fmt.Fprintln(os.Stderr, "post-change collection failed:", err)
				}
			}

			// Between collections the agent asks the server, about once a
			// minute, whether someone pressed Check again; if so it reports
			// at once. Servers older than 0.7 do not know the question, and
			// the agent then stops asking.
			poll := checkInterval > 0
			nextCollect, nextAction := time.Now(), time.Now()
			nextPoll := time.Now().Add(jitter(checkInterval))
			var last *model.ObservationBatch
			for {
				if !time.Now().Before(nextCollect) {
					b, err := report()
					if err != nil {
						fmt.Fprintln(os.Stderr, time.Now().Format(time.RFC3339), "collection failed:", err)
						if once {
							return err
						}
					} else {
						last = b
					}
					nextCollect = time.Now().Add(interval)
				}
				if !time.Now().Before(nextAction) {
					remediateOnce(last)
					nextAction = time.Now().Add(actionInterval)
				}
				if once {
					return nil
				}
				if poll && len(assetIDs) > 0 && !time.Now().Before(nextPoll) {
					due, every, err := cl.CheckDue(ctx, assetIDs)
					switch {
					case errors.Is(err, client.ErrNoCheckPolling):
						poll = false
					case err != nil:
						fmt.Fprintln(os.Stderr, time.Now().Format(time.RFC3339), "check-again poll failed:", err)
					case due:
						fmt.Println(time.Now().Format(time.RFC3339), "check again requested: reporting now")
						nextCollect = time.Now()
					}
					next := checkInterval
					if every >= 15*time.Second && every <= 10*time.Minute {
						next = every
					}
					nextPoll = time.Now().Add(jitter(next))
					if due {
						continue
					}
				}
				wake := nextCollect
				if fixer != nil && nextAction.Before(wake) {
					wake = nextAction
				}
				if poll && nextPoll.Before(wake) {
					wake = nextPoll
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Until(wake)):
				}
			}
		},
	}
	c.flags(cmd)
	cmd.Flags().DurationVar(&interval, "interval", 6*time.Hour, "time between collections")
	cmd.Flags().BoolVar(&once, "once", false, "collect once and exit")
	cmd.Flags().StringVar(&root, "root", "/", "filesystem root to inspect (for containers or mounted images)")
	cmd.Flags().BoolVar(&noRuntimes, "no-runtimes", false, "skip detection of runtimes installed outside the package manager")
	cmd.Flags().BoolVar(&noPacks, "no-packs", false, "do not use the server's stack packs on application directories")
	cmd.Flags().StringSliceVar(&appDirs, "app-dir", splitList(os.Getenv("STACKURITY_APP_DIRS")),
		"directory of a deployed application to inventory (repeatable; env STACKURITY_APP_DIRS, comma-separated)")
	cmd.Flags().BoolVar(&discoverApps, "discover-apps", os.Getenv("STACKURITY_DISCOVER_APPS") == "true",
		"also look for applications under /srv, /var/www, /opt, /app and home directories")
	cmd.Flags().StringVar(&envName, "environment", os.Getenv("STACKURITY_ENVIRONMENT"), "environment label, e.g. production")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the batch to a file (- for stdout) instead of sending it")
	cmd.Flags().BoolVar(&remediate, "remediate", false, "apply server-approved upgrades for allowlisted packages (needs root and a host-bound token)")
	cmd.Flags().StringVar(&allowFile, "allowlist", "/etc/stackurity/remediation-allow", "file of package patterns this host may upgrade")
	cmd.Flags().DurationVar(&actionInterval, "action-interval", 5*time.Minute, "how often to check for approved changes when --remediate is set")
	cmd.Flags().DurationVar(&checkInterval, "check-interval", 45*time.Second,
		"how often to ask the server whether someone pressed Check again (0 turns it off)")
	return cmd
}

// jitter spreads polls from many agents: d plus up to a third of d.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(int64(d)/3+1))
}

func scanCmd() *cobra.Command {
	var c conn
	var g gate
	var name, envName, output, gitURL string
	var noPacks bool
	cmd := &cobra.Command{
		Use:   "scan DIR",
		Short: "Scan a project directory's lockfiles and report them",
		Long: `Parses lockfiles as data: npm (package-lock.json, npm-shrinkwrap.json,
yarn.lock, pnpm-lock.yaml), Composer, Poetry, Pipfile.lock, requirements.txt,
go.mod, Gemfile.lock, NuGet packages.lock.json and pubspec.lock, plus what the
stack packs installed on the server read (for example Java or Cargo); packs
are downloaded, their signatures checked, and run here in a sandbox.
No package manager, script or build is run. Lockfiles the scanner does not
support yet are reported as unsupported coverage.

With --fail-on, --fail-on-priority or --fail-on-kev the command waits for the
server to evaluate the scan and exits with status 3 when an open finding meets
the threshold, so it can gate a CI pipeline. Findings that are suppressed or
risk-accepted on the server do not count.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.validate(); err != nil {
				return err
			}
			if g.enabled() && output != "" {
				return errors.New("--fail-on flags need the server's evaluation; they cannot be combined with --output")
			}
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if name == "" {
				name = filepath.Base(dir)
			}
			asset := model.AssetRef{Kind: model.AssetRepository, Name: name, Environment: envName}
			if gitURL != "" {
				asset.Identifiers = []model.Identifier{{Scheme: "git-url", Value: gitrepo.NormalizeURL(gitURL)}}
			} else {
				asset.Identifiers = []model.Identifier{{Scheme: "name:repository", Value: name}}
			}
			// Packs installed on the server read more file types; they run
			// here, so repository contents never leave this machine.
			var exts []lockfile.Extension
			if output == "" && !noPacks {
				cl, err := c.client()
				if err != nil {
					return err
				}
				var done func()
				exts, done = remotePacks(cl)(cmd.Context())
				defer done()
			}
			b, err := lockfile.ScanDirWith(cmd.Context(), dir, asset, version, exts)
			if err != nil {
				return err
			}
			if err := b.Validate(); err != nil {
				return err
			}
			for _, cv := range b.Coverage {
				if cv.Status != "checked" {
					fmt.Fprintf(os.Stderr, "%s: %s %s\n", cv.Status, cv.Scope, cv.Reason)
				}
			}
			if output != "" {
				return writeBatch(output, b)
			}
			cl, err := c.client()
			if err != nil {
				return err
			}
			r, err := cl.Ingest(cmd.Context(), b)
			if err != nil {
				return err
			}
			printResult(r)
			if !g.enabled() {
				return nil
			}
			res, err := g.await(cmd.Context(), cl, r.CollectionID)
			if err != nil {
				return err
			}
			return g.report(os.Stdout, res)
		},
	}
	c.flags(cmd)
	g.flags(cmd)
	cmd.Flags().BoolVar(&noPacks, "no-packs", false, "do not download and run the stack packs installed on the server")
	cmd.Flags().StringVar(&name, "name", "", "asset name (default: directory name)")
	cmd.Flags().StringVar(&gitURL, "git-url", os.Getenv("STACKURITY_GIT_URL"), "repository URL; used as the asset identity so CI runs and server scans match")
	cmd.Flags().StringVar(&envName, "environment", "", "environment label")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the batch to a file (- for stdout) instead of sending it")
	return cmd
}

func sbomCmd() *cobra.Command {
	c := &cobra.Command{Use: "sbom", Short: "Import or export SBOMs (CycloneDX, SPDX)"}

	var ic conn
	var name, kind, envName string
	imp := &cobra.Command{
		Use:   "import FILE",
		Short: "Import a CycloneDX or SPDX JSON SBOM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			// Validate locally first for a clear error before uploading.
			if _, err := sbom.Import(f, nil, version); err != nil {
				return err
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			cl, err := ic.client()
			if err != nil {
				return err
			}
			r, err := cl.ImportSBOM(cmd.Context(), f, name, kind, envName)
			if err != nil {
				return err
			}
			printResult(r)
			return nil
		},
	}
	ic.flags(imp)
	imp.Flags().StringVar(&name, "asset-name", "", "attach to this asset instead of one derived from the document")
	imp.Flags().StringVar(&kind, "asset-kind", "application", "asset kind when --asset-name is set")
	imp.Flags().StringVar(&envName, "environment", "", "environment label")

	var ec conn
	var assetID int64
	var out string
	exp := &cobra.Command{
		Use:   "export",
		Short: "Export an asset's inventory as CycloneDX 1.6 JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := ec.client()
			if err != nil {
				return err
			}
			var w io.Writer = os.Stdout
			if out != "-" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return cl.Do(cmd.Context(), "GET", fmt.Sprintf("/api/v1/assets/%d/sbom", assetID), nil, nil, w)
		},
	}
	ec.flags(exp)
	exp.Flags().Int64Var(&assetID, "asset", 0, "asset id (required)")
	exp.Flags().StringVarP(&out, "output", "o", "-", "output file")
	_ = exp.MarkFlagRequired("asset")

	c.AddCommand(imp, exp)
	return c
}

func diagnosticsCmd() *cobra.Command {
	var c conn
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Check connectivity, authentication and server version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("client version:", version)
			if c.server == "" {
				return errors.New("--server or STACKURITY_SERVER is required")
			}
			anon, err := client.New(c.server, "", version)
			if err != nil {
				return err
			}
			var meta map[string]any
			if err := anon.Do(cmd.Context(), "GET", "/api/v1/meta", nil, nil, &meta); err != nil {
				return fmt.Errorf("server unreachable: %w", err)
			}
			fmt.Printf("server: %s version %v (setup required: %v)\n", c.server, meta["version"], meta["setup_required"])
			cl, err := c.client()
			if err != nil {
				fmt.Println("auth: skipped -", err)
				return nil
			}
			var me map[string]any
			if err := cl.Do(cmd.Context(), "GET", "/api/v1/auth/me", nil, nil, &me); err != nil {
				return fmt.Errorf("auth failed: %w", err)
			}
			fmt.Printf("auth: ok, role %v\n", me["role"])
			return nil
		},
	}
	c.flags(cmd)
	return cmd
}
