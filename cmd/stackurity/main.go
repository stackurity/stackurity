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
	root := &cobra.Command{
		Use:           "stackurity",
		Short:         "Self-hosted software inventory and upgrade intelligence",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.AddCommand(serverCmd(), migrateCmd(), adminCmd(), agentCmd(), scanCmd(), sbomCmd(), diagnosticsCmd(), pluginCmd(), packCmd(), mcpCmd(), enrollCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
