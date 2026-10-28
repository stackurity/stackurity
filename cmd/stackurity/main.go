// Command stackurity is the server, agent and CLI in one binary.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

// newRootCmd builds the whole command tree; docs_test.go walks it.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "stackurity",
		Short:         "Self-hosted software inventory and upgrade intelligence",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.AddCommand(serverCmd(), migrateCmd(), adminCmd(), agentCmd(), scanCmd(), sbomCmd(), diagnosticsCmd(), pluginCmd(), packCmd(), mcpCmd(), enrollCmd())
	return root
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
