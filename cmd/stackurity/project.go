package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/client"
)

// projectHelp is the --project flag's help on commands that use a token.
const projectHelp = "project id or name: scope reads to it and file new assets in it (env STACKURITY_PROJECT)"

func projectFlag(cmd *cobra.Command, v *string, help string) {
	cmd.Flags().StringVar(v, "project", strings.TrimSpace(env("STACKURITY_PROJECT", "")), help)
}

// connect builds an API client and, with --project, resolves the project
// and scopes the client to it: reads carry X-Stackurity-Project, uploads
// project_id. upload says the command uploads; the server must then say it
// files uploads in projects (0.10), or nothing is sent.
func (c *conn) connect(ctx context.Context, upload bool) (*client.Client, error) {
	cl, err := c.client()
	if err != nil || strings.TrimSpace(c.project) == "" {
		return cl, err
	}
	id, _, err := resolveProject(ctx, cl, c.project)
	if err != nil {
		return nil, fmt.Errorf("--project: %w", err)
	}
	if upload {
		if err := requireUploadProject(ctx, cl); err != nil {
			return nil, err
		}
	}
	cl.Project = id
	return cl, nil
}

// requireUploadProject fails unless the server files uploads in projects.
// Older servers ignore project_id on POST /ingest, which would store the
// asset outside the project without a word.
func requireUploadProject(ctx context.Context, cl *client.Client) error {
	m, err := cl.Meta(ctx)
	if err != nil {
		return fmt.Errorf("--project: could not ask the server what it supports: %w", err)
	}
	if !m.Has(client.FeatureUploadProject) {
		v := m.Version
		if v == "" {
			v = "unknown"
		}
		return fmt.Errorf("--project: the server (version %s) cannot file uploads in a project; Stackurity 0.10 or later is needed. Nothing was uploaded", v)
	}
	return nil
}

// resolveProject turns --project into a project id. A number is an id; it
// is checked when the token may read projects (a collector token may not,
// and the server checks it on upload). Anything else is a name, matched
// exactly, then ignoring case, among the projects the token can see. name
// is "" when the token cannot read the project.
func resolveProject(ctx context.Context, cl *client.Client, v string) (id int64, name string, err error) {
	v = strings.TrimSpace(v)
	if n, perr := strconv.ParseInt(v, 10, 64); perr == nil {
		if n <= 0 {
			return 0, "", fmt.Errorf("%q is not a project id", v)
		}
		p, err := cl.GetProject(ctx, n)
		var ae *client.APIError
		switch {
		case err == nil && p.ArchivedAt != nil:
			return 0, "", fmt.Errorf("project %d (%s) is archived", n, p.Name)
		case err == nil:
			return n, p.Name, nil
		case errors.As(err, &ae) && ae.Status == 403:
			return n, "", nil // a collector token: the server checks the id
		case errors.As(err, &ae) && ae.Status == 404:
			return 0, "", fmt.Errorf("no project %d that this token can see (servers before 0.8 have no projects)", n)
		default:
			return 0, "", err
		}
	}
	ps, err := cl.Projects(ctx)
	var ae *client.APIError
	switch {
	case errors.As(err, &ae) && ae.Status == 403:
		return 0, "", fmt.Errorf("this token cannot list projects, so the name %q cannot be looked up; pass the project's id instead (Settings > Projects and access)", v)
	case errors.As(err, &ae) && ae.Status == 404:
		return 0, "", errors.New("the server has no projects (servers before 0.8)")
	case err != nil:
		return 0, "", err
	}
	match := func(eq func(a, b string) bool) []client.Project {
		var out []client.Project
		for _, p := range ps {
			if p.ArchivedAt == nil && eq(strings.TrimSpace(p.Name), v) {
				out = append(out, p)
			}
		}
		return out
	}
	found := match(func(a, b string) bool { return a == b })
	if len(found) != 1 {
		found = match(strings.EqualFold)
	}
	switch len(found) {
	case 1:
		return found[0].ID, found[0].Name, nil
	case 0:
		var names []string
		for _, p := range ps {
			if p.ArchivedAt == nil {
				names = append(names, p.Name)
			}
		}
		sort.Strings(names)
		if len(names) == 0 {
			return 0, "", fmt.Errorf("no project named %q: this token can see no projects", v)
		}
		if len(names) > 10 {
			names = append(names[:10], "...")
		}
		return 0, "", fmt.Errorf("no project named %q; projects this token can see: %s", v, strings.Join(names, ", "))
	default:
		var ids []string
		for _, p := range found {
			ids = append(ids, fmt.Sprintf("%d (%s)", p.ID, p.Name))
		}
		return 0, "", fmt.Errorf("%d projects are named %q: %s; pass the id instead", len(found), v, strings.Join(ids, ", "))
	}
}

// enrollProject reads enroll's --project: an id only, since enrollment has
// no token to look names up with.
func enrollProject(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("--project: enroll needs the project's id, not a name (%q): it has no token to look names up with. The id is in Settings > Projects and access", v)
	}
	return n, nil
}
