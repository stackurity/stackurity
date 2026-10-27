package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/mcp"
)

func mcpCmd() *cobra.Command {
	var c conn
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve Stackurity to AI assistants over the Model Context Protocol (stdio)",
		Long: `Runs a read-only MCP server on standard input and output, for AI assistants
and coding agents. It answers through the HTTP API with your token, so use a
viewer token: the assistant can see inventory, findings and action plans but
cannot change anything.

Example client configuration:

  {"mcpServers": {"stackurity": {
     "command": "stackurity", "args": ["mcp"],
     "env": {"STACKURITY_SERVER": "https://stackurity.example.com",
             "STACKURITY_TOKEN_FILE": "/home/me/.config/stackurity/token"}}}}

With --project (an id or name; or STACKURITY_PROJECT) every answer is
limited to that project's assets and what hangs off them, as when the
project is chosen in the dashboard's switcher. The project is checked at
start; servers before 0.8, which have no projects, are refused.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := c.connect(cmd.Context(), false)
			if err != nil {
				return err
			}
			s := &mcp.Server{API: cl, Version: version}
			return s.Serve(cmd.Context(), os.Stdin, os.Stdout)
		},
	}
	c.flags(cmd)
	return cmd
}
