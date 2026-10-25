package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/plugins"
	"github.com/stackurity/stackurity/pkg/plugin"
)

func pluginCmd() *cobra.Command {
	c := &cobra.Command{Use: "plugin", Short: "Develop and check collector plugins"}
	var cfgFile, secretsFile string
	var timeout time.Duration
	test := &cobra.Command{
		Use:   "test PLUGIN_EXECUTABLE",
		Short: "Run the conformance checks against a plugin",
		Long: `Runs metadata, validate, health and collect against a plugin executable and
checks every response against the protocol: required metadata, declared
permissions/network access/limitations, schema version, valid batches with
coverage, and behaviour on an invalid config. Exit status is non-zero if any
check fails.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			exe, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			cfg := json.RawMessage("{}")
			if cfgFile != "" {
				b, err := os.ReadFile(cfgFile)
				if err != nil {
					return err
				}
				cfg = b
			}
			secrets := map[string]string{}
			if secretsFile != "" {
				b, err := os.ReadFile(secretsFile)
				if err != nil {
					return err
				}
				if err := json.Unmarshal(b, &secrets); err != nil {
					return fmt.Errorf("secrets file must be a JSON object: %w", err)
				}
			}
			work, err := os.MkdirTemp("", "stk-plugin-test-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(work)
			ctx := cmd.Context()
			failed := 0
			check := func(name string, err error) {
				if err != nil {
					failed++
					fmt.Printf("FAIL  %s: %v\n", name, err)
				} else {
					fmt.Printf("ok    %s\n", name)
				}
			}

			resp, _, err := plugins.Exec(ctx, exe, work, 30*time.Second, "metadata", nil)
			if err == nil && resp.Metadata == nil {
				err = errors.New("no metadata in response")
			}
			check("metadata responds", err)
			if err == nil {
				check("metadata complete", plugins.CheckMetadata(resp.Metadata))
				m := resp.Metadata
				fmt.Printf("      %s %s by %s (%s)\n      network: %s\n      permissions: %s\n",
					m.ID, m.Version, m.Maintainer, m.License, strings.Join(m.NetworkAccess, ", "), strings.Join(m.Permissions, ", "))
			}

			resp, _, err = plugins.Exec(ctx, exe, work, 30*time.Second, "validate", &plugin.Request{Config: cfg})
			if err == nil && (resp.Valid == nil || !resp.Valid.OK) {
				err = fmt.Errorf("config rejected: %+v", resp.Valid)
			}
			check("validate accepts the test config", err)

			resp, _, err = plugins.Exec(ctx, exe, work, 30*time.Second, "validate", &plugin.Request{Config: json.RawMessage(`{"__stackurity_invalid__": true}`)})
			if err == nil && (resp.Valid == nil || resp.Valid.OK) {
				err = errors.New("an unknown config field was accepted; validate should reject configs it does not understand")
			}
			check("validate rejects an unknown config", err)

			resp, _, err = plugins.Exec(ctx, exe, work, time.Minute, "health", &plugin.Request{Config: cfg, Secrets: secrets})
			if err == nil && resp.Health == nil {
				err = errors.New("no health in response")
			}
			check("health responds", err)

			start := time.Now()
			resp, logs, err := plugins.Exec(ctx, exe, work, timeout, "collect", &plugin.Request{Config: cfg, Secrets: secrets})
			check("collect responds", err)
			if err == nil {
				if len(resp.Batches) == 0 {
					check("collect returns batches", errors.New("no batches (report failures as coverage instead of nothing)"))
				}
				obs := 0
				for i, b := range resp.Batches {
					b.Collector.ID, b.Collector.Method = "plugin:test", "plugin"
					var verr error
					if b == nil {
						verr = errors.New("null batch")
					} else if verr = b.Validate(); verr == nil && len(b.Coverage) == 0 {
						verr = errors.New("no coverage items: say what was checked")
					}
					check(fmt.Sprintf("batch %d valid", i), verr)
					if b != nil {
						obs += len(b.Observations)
					}
				}
				fmt.Printf("      %d batch(es), %d observation(s) in %s\n", len(resp.Batches), obs, time.Since(start).Round(time.Millisecond))
			}
			if logs != "" {
				fmt.Printf("      stderr: %s\n", strings.TrimSpace(firstLines(logs, 5)))
			}
			if failed > 0 {
				return fmt.Errorf("%d check(s) failed", failed)
			}
			fmt.Println("all checks passed")
			return nil
		},
	}
	test.Flags().StringVar(&cfgFile, "config", "", "JSON config to test with")
	test.Flags().StringVar(&secretsFile, "secrets", "", "JSON object of credentials to pass")
	test.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "collect timeout")
	c.AddCommand(test)
	return c
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	return strings.Join(lines, "\n      ")
}
