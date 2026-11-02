package registry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials for a registry: a token or password (with Username when it
// belongs to a named user), or AWS access keys for ECR.
type Credentials struct {
	Username string
	Secret   string
	AWS      *AWSKeys
}

func (c Config) username(cr Credentials) string {
	if cr.Username != "" {
		return cr.Username
	}
	if c.Username != "" {
		return c.Username
	}
	if c.Provider == GHCR {
		// ghcr.io takes any user name with a personal access token.
		return c.Namespace
	}
	return ""
}

func open(ctx context.Context, cfg Config, cr Credentials) (source, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	user := cfg.username(cr)
	switch cfg.Provider {
	case GHCR:
		return newGHCR(strings.ToLower(cfg.Namespace), cr.Secret)
	case DockerHub:
		return newDockerHub(ctx, cfg.Namespace, user, cr.Secret)
	case ECR:
		if cr.AWS == nil {
			return nil, errors.New(`Amazon ECR needs access keys: a secret holding {"aws_access_key_id": "...", "aws_secret_access_key": "..."}, or aws_integration_id naming an aws-managed plugin integration with keys`)
		}
		return newECR(ctx, cfg, *cr.AWS)
	case OCI:
		base, err := ParseRegistryURL(cfg.URL)
		if err != nil {
			return nil, err
		}
		return &ociSource{c: newClient(base, user, cr.Secret, cfg.AuthHost), namespace: cfg.Namespace, platform: cfg.Platform}, nil
	}
	return nil, fmt.Errorf("unknown provider %q", cfg.Provider)
}

// ListRepositories lists a registry's repositories for an admin to pick
// from, at most MaxTags of them, sorted. complete is false when there
// were more.
func ListRepositories(ctx context.Context, cfg Config, cr Credentials) ([]string, bool, error) {
	src, err := open(ctx, cfg, cr)
	if err != nil {
		return nil, false, err
	}
	names, complete, err := src.repositories(ctx)
	if err != nil {
		return nil, false, err
	}
	sort.Strings(names)
	return names, complete, nil
}

// RepoResult is what one repository holds.
type RepoResult struct {
	Name   string
	Images []Image
	// Tags maps every tag read to its digest ("" where the digest was not
	// read: a generic registry's tags beyond MaxInspected). When
	// TagsComplete it is the whole list, so a tag missing from it is gone.
	Tags         map[string]string
	TagsComplete bool
	// Gone: the registry says the repository does not exist.
	Gone bool
	Err  error
}

// StillTagged reports whether the repository may still hold an image: a
// tag points to its digest, or one of the tags it had is there and its
// digest was not read. False only when the tag list is complete and proves
// the image untagged.
func (rr RepoResult) StillTagged(digest string, hadTags []string) bool {
	if !rr.TagsComplete {
		return true
	}
	for _, d := range rr.Tags {
		if d == digest {
			return true
		}
	}
	for _, t := range hadTags {
		if d, ok := rr.Tags[t]; ok && d == "" {
			return true
		}
	}
	return false
}

// Result is one discovery run.
type Result struct {
	// Host is the registry host image references point at, as
	// image.RegistryHost reads them.
	Host string
	// Listed is every repository the registry listed, tracked or not;
	// when ListComplete, a repository missing from it is gone.
	Listed       map[string]bool
	ListComplete bool
	Repositories []RepoResult
	// Skipped counts repositories over MaxRepositories, left out.
	Skipped int
}

// Discover lists the tracked repositories and picks the images in each.
// known maps digests seen before to their push times, so a generic
// registry's images are not read again. A failure to list repositories
// is an error; a failure in one repository is recorded on it.
func Discover(ctx context.Context, cfg Config, cr Credentials, known map[string]time.Time) (*Result, error) {
	src, err := open(ctx, cfg, cr)
	if err != nil {
		return nil, err
	}
	sel := NewSelector(cfg)
	res := &Result{Host: src.host(), Listed: map[string]bool{}}
	var names []string
	if len(cfg.Repositories) > 0 {
		// Named repositories need no catalog (Docker Hub and many
		// registries have none); a deleted one is found by its tag list.
		for _, r := range cfg.Repositories {
			if cfg.Provider == GHCR && !strings.Contains(r, "/") {
				r = strings.ToLower(cfg.Namespace) + "/" + r
			}
			if cfg.Provider == DockerHub && !strings.Contains(r, "/") {
				r = cfg.Namespace + "/" + r
			}
			names = append(names, r)
		}
	} else {
		listed, complete, err := src.repositories(ctx)
		if err != nil {
			return nil, err
		}
		res.ListComplete = complete
		for _, n := range listed {
			res.Listed[n] = true
		}
		names = listed
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] || !sel.Repository(name) {
			continue
		}
		seen[name] = true
		if len(res.Repositories) >= MaxRepositories {
			res.Skipped++
			continue
		}
		rr := RepoResult{Name: name, Tags: map[string]string{}}
		tags, complete, err := src.tags(ctx, name, sel, known)
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case isNotFound(err):
			rr.Gone = true
		case err != nil:
			rr.Err = err
		default:
			rr.TagsComplete = complete
			for _, t := range tags {
				rr.Tags[t.Name] = t.Digest
			}
			for _, im := range sel.Select(tags) {
				im.Repository = name
				base := src.refBase(name)
				im.Ref = base + "@" + im.Digest
				im.Display = base + ":" + im.Tags[0]
				rr.Images = append(rr.Images, im)
			}
		}
		res.Repositories = append(res.Repositories, rr)
	}
	return res, nil
}

// ScanAuth is what an image scan of this registry's images authenticates
// with: the registry host the credentials are for (as image.RegistryHost
// reads a reference), and the user name and password or token. For ECR
// it asks AWS for a registry password. Without credentials it returns
// empty strings.
func ScanAuth(ctx context.Context, cfg Config, cr Credentials) (host, username, secret string, err error) {
	switch cfg.Provider {
	case GHCR:
		return strings.Split(ghcrHost, ":")[0], cfg.username(cr), cr.Secret, nil
	case DockerHub:
		if cr.Secret == "" {
			return "registry-1.docker.io", "", "", nil
		}
		return "registry-1.docker.io", cfg.username(cr), cr.Secret, nil
	case OCI:
		base, err := url.Parse(cfg.URL)
		if err != nil {
			return "", "", "", err
		}
		return base.Hostname(), cfg.username(cr), cr.Secret, nil
	case ECR:
		src, err := open(ctx, cfg, cr)
		if err != nil {
			return "", "", "", err
		}
		e := src.(*ecrSource)
		user, pass, err := e.Login(ctx)
		if err != nil {
			return "", "", "", err
		}
		return e.registry, user, pass, nil
	}
	return "", "", "", fmt.Errorf("unknown provider %q", cfg.Provider)
}
