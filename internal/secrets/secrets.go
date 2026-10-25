// Package secrets resolves secret references. Integrations and channels hold
// a reference, never the value:
//
//	env:STACKURITY_SECRET_GITHUB      the server's environment
//	file:/run/secrets/github_token    a file in the server's secrets directory
//	secret:GITHUB_TOKEN               a value stored, encrypted, in the workspace
//
// env and file read the server's own secrets, so on a shared installation only
// instance administrators may use them (see ServerSecret); workspaces keep
// their credentials as stored secrets.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ServerSecret reports whether ref reads the server's own environment or
// files rather than a workspace's stored secrets.
func ServerSecret(ref string) bool {
	return strings.HasPrefix(ref, "env:") || strings.HasPrefix(ref, "file:")
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ValidName reports whether name can be used for a stored secret.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Resolver resolves references. AllowedDir restricts file references; an
// empty AllowedDir disables them.
type Resolver struct {
	AllowedDir string
	// EnvPrefix restricts env references to names with this prefix, so a
	// reference cannot read unrelated server environment such as the
	// database URL. Empty means DefaultEnvPrefix.
	EnvPrefix string
	// Stored returns a secret stored in the workspace of ctx; nil disables
	// secret: references.
	Stored func(ctx context.Context, name string) (string, error)
}

const DefaultEnvPrefix = "STACKURITY_SECRET_"

func (r Resolver) Validate(ref string) error {
	_, err := r.resolve(context.Background(), ref, false)
	return err
}

// Resolve returns the secret ref points at; stored secrets are read from the
// workspace ctx is scoped to.
func (r Resolver) Resolve(ctx context.Context, ref string) (string, error) {
	return r.resolve(ctx, ref, true)
}

func (r Resolver) resolve(ctx context.Context, ref string, read bool) (string, error) {
	if ref == "" {
		return "", nil
	}
	kind, name, ok := strings.Cut(ref, ":")
	if !ok {
		return "", errors.New(`secret reference must look like "secret:NAME", "env:NAME" or "file:/path"`)
	}
	switch kind {
	case "secret":
		if !ValidName(name) {
			return "", errors.New("stored secret names use letters, digits, dot, dash and underscore (max 64)")
		}
		if !read {
			return "", nil
		}
		if r.Stored == nil {
			return "", errors.New("stored secrets are not enabled on this server (STACKURITY_SECRET_KEY)")
		}
		return r.Stored(ctx, name)
	case "env":
		prefix := r.EnvPrefix
		if prefix == "" {
			prefix = DefaultEnvPrefix
		}
		if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
			return "", fmt.Errorf("environment secret names must start with %s", prefix)
		}
		if !read {
			return "", nil
		}
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return strings.TrimSpace(v), nil
	case "file":
		if r.AllowedDir == "" {
			return "", errors.New("file secrets are disabled")
		}
		clean := filepath.Clean(name)
		base := filepath.Clean(r.AllowedDir)
		if !filepath.IsAbs(clean) || (clean != base && !strings.HasPrefix(clean, base+string(filepath.Separator))) {
			return "", fmt.Errorf("file secrets must be under %s", r.AllowedDir)
		}
		if !read {
			return "", nil
		}
		b, err := os.ReadFile(clean)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("unknown secret kind %q", kind)
}
