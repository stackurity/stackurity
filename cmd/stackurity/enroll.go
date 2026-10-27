package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/client"
)

func enrollCmd() *cobra.Command {
	var server, dir, projectArg string
	var force bool
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Exchange a one-time enrollment code for this host's agent token and settings",
		Long: `Reads the code from STACKURITY_ENROLL_CODE (never from a flag, so it does not
appear in process listings), redeems it with the server, and writes the
agent's token and settings to --dir:

  token       the collector token
  agent.env   STACKURITY_SERVER, STACKURITY_TOKEN_FILE and the settings the
              administrator chose (environment, application directories)

With --project (an id; or STACKURITY_PROJECT) the server first checks that
the code adds hosts to that project, and refuses without using the code up
if it adds them to another project or to none. The code's project is chosen
by the administrator who made it; enrolling cannot change it. A name is not
accepted here, since enrolling has no token to look names up with.

The agent install script runs this for you.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			project, err := enrollProject(projectArg)
			if err != nil {
				return err
			}
			code := strings.TrimSpace(os.Getenv("STACKURITY_ENROLL_CODE"))
			if code == "" {
				return errors.New("set STACKURITY_ENROLL_CODE to the code from Assets > Add server")
			}
			if server == "" || strings.ContainsAny(server, " \t\n\r\"'\\$`") {
				return errors.New("--server must be a URL without spaces or quotes")
			}
			tokenFile := filepath.Join(dir, "token")
			if _, err := os.Stat(tokenFile); err == nil && !force {
				return fmt.Errorf("%s already exists; this host is enrolled (use --force to replace it)", tokenFile)
			}
			cl, err := client.New(server, "", version)
			if err != nil {
				return err
			}
			host, _ := os.Hostname()
			e, err := cl.Enroll(cmd.Context(), code, host, project)
			var ae *client.APIError
			if project > 0 && errors.As(err, &ae) && ae.Status == 400 && strings.Contains(ae.Message, "project_id") {
				return errors.New("the server does not support --project for enrollment (Stackurity 0.10 or later is needed); the code was not used")
			}
			if err != nil {
				return err
			}
			if project > 0 && (e.ProjectID == nil || *e.ProjectID != project) {
				return fmt.Errorf("the server did not confirm that hosts enrolled with this code go to project %d; the token was not saved", project)
			}
			for _, d := range e.AppDirs {
				if strings.ContainsAny(d, ", \t\n\r\"'\\$`") {
					return fmt.Errorf("server sent an unsafe application directory %q", d)
				}
			}
			if strings.ContainsAny(e.Environment, " \t\n\r\"'\\$`") {
				return fmt.Errorf("server sent an unsafe environment %q", e.Environment)
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return err
			}
			if err := writeFileAtomic(tokenFile, []byte(e.Token+"\n"), 0o640); err != nil {
				return err
			}
			env := fmt.Sprintf("STACKURITY_SERVER=%s\nSTACKURITY_TOKEN_FILE=%s\nSTACKURITY_ENVIRONMENT=%s\nSTACKURITY_APP_DIRS=%s\nSTACKURITY_DISCOVER_APPS=%t\n",
				strings.TrimRight(server, "/"), tokenFile, e.Environment, strings.Join(e.AppDirs, ","), e.DiscoverApps)
			if err := writeFileAtomic(filepath.Join(dir, "agent.env"), []byte(env), 0o640); err != nil {
				return err
			}
			fmt.Printf("enrolled %s; settings in %s\n", host, filepath.Join(dir, "agent.env"))
			if e.ProjectID != nil {
				fmt.Printf("the host is added to project %d when it first reports\n", *e.ProjectID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", os.Getenv("STACKURITY_SERVER"), "server URL")
	cmd.Flags().StringVar(&dir, "dir", "/etc/stackurity", "directory for the token and agent.env")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing token")
	projectFlag(cmd, &projectArg, "project id the enrollment code must add hosts to; refused otherwise (env STACKURITY_PROJECT)")
	return cmd
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
