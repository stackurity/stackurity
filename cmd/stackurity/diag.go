package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/diag"
	"github.com/stackurity/stackurity/internal/store"
)

// diagFlags are the options doctor and support-bundle share.
type diagFlags struct {
	offline   bool
	backupDir string
}

func (f *diagFlags) add(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.offline, "offline", false, "skip the outbound checks of feed sources (air-gapped servers)")
	cmd.Flags().StringVar(&f.backupDir, "backup-dir", "", "also check free space where backups are written")
}

// diagConfig reads the configuration `stackurity server` reads, from the
// same environment.
func (f *diagFlags) config() (diag.Config, error) {
	dataDir := env("STACKURITY_DATA_DIR", "/var/lib/stackurity")
	cfg := diag.Config{Version: version, Edition: edition, FeedsEnabled: os.Getenv("STACKURITY_FEEDS") != "off", Offline: f.offline,
		PlatformWorkspace: os.Getenv("STACKURITY_PLATFORM_WORKSPACE"),
		InsecureCookies:   cookieRisk(env("STACKURITY_COOKIE_SECURE", "true") != "false", os.Getenv("STACKURITY_BASE_URL"), env("STACKURITY_LISTEN", ":8080")),
		Disks:             []diag.Disk{{Setting: "STACKURITY_DATA_DIR", Path: dataDir, Explicit: os.Getenv("STACKURITY_DATA_DIR") != ""}},
	}
	cfg.Intel, _ = intelConfig(dataDir)
	if f.backupDir != "" {
		cfg.Disks = append(cfg.Disks, diag.Disk{Setting: "--backup-dir", Path: f.backupDir, Explicit: true})
	}
	var err error
	cfg.LicenceKey, cfg.LicenceFrom, err = licenceKeyFromEnv()
	return cfg, err
}

// openDiagStore connects as the server does, but does not refuse a
// database a newer version migrated: doctor reports that instead.
func openDiagStore(ctx context.Context) (*store.Store, error) {
	url, err := databaseURL()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, url)
	if err != nil {
		return nil, err
	}
	st := store.New(pool)
	st.StaleAfter = staleAfterSetting()
	return st, nil
}

// doctorRun is one run of the checks, with what the bundle reads next.
type doctorRun struct {
	rep   *diag.Report
	cfg   diag.Config
	st    *store.Store // nil when the database could not be opened
	dbErr error
}

func (d *doctorRun) close() {
	if d.st != nil {
		d.st.Pool.Close()
	}
}

func runDoctor(ctx context.Context, f *diagFlags) (*doctorRun, error) {
	cfg, err := f.config()
	if err != nil {
		return nil, err
	}
	d := &doctorRun{cfg: cfg}
	d.st, d.dbErr = openDiagStore(ctx)
	d.rep = diag.Doctor(ctx, d.st, d.dbErr, cfg)
	return d, nil
}

func doctorCmd() *cobra.Command {
	var f diagFlags
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check this installation from the server host: database, migrations, feeds, agents, disk, memory, licence",
		Long: "Run with the server's configuration (the same environment as stackurity server, for example\n" +
			"docker compose exec stackurity stackurity doctor). Each check prints PASS, WARN, FAIL or SKIP and the\n" +
			"next step; the exit code is 1 when any check fails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := runDoctor(cmd.Context(), &f)
			if err != nil {
				return err
			}
			defer d.close()
			rep, out := d.rep, cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(out, "Stackurity %s (%s), %s\n\n", rep.Version, rep.Edition, rep.CheckedAt.Format(time.RFC3339))
				diag.WriteText(out, rep.Results)
				fmt.Fprintf(out, "\n%s\n", rep.Summary())
			}
			if n := rep.Failed(); n > 0 {
				return &exitError{code: 1, msg: fmt.Sprintf("doctor: %d check(s) failed", n)}
			}
			return nil
		},
	}
	f.add(cmd)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the results as JSON")
	return cmd
}

func supportBundleCmd() *cobra.Command {
	var f diagFlags
	var out string
	cmd := &cobra.Command{
		Use:   "support-bundle",
		Short: "Write redacted diagnostics to send to support (no inventory, names, addresses or secrets)",
		Long: "Runs the doctor's checks and collects versions, migrations, feed, task and job states and counts into one\n" +
			"JSON file. Configuration values are redacted unless known to be safe. Read the file before you send it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := runDoctor(cmd.Context(), &f)
			if err != nil {
				return err
			}
			defer d.close()
			environ := os.Environ()
			b := diag.BuildBundle(cmd.Context(), diag.BundleInput{Config: d.cfg, Store: d.st, DBErr: d.dbErr, Report: d.rep, Environ: environ})
			raw, err := b.JSON(environ, d.cfg.Intel)
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, raw, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d bytes; doctor: %s). Read it before you send it.\n", out, len(raw), d.rep.Summary())
			return nil
		},
	}
	f.add(cmd)
	cmd.Flags().StringVar(&out, "out", "", "file to write (required)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}
