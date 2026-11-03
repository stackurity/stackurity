// Package registry connects a container registry (GitHub Container
// Registry, Docker Hub, Amazon ECR, or any registry speaking the OCI
// Distribution API) and works out which images in it to scan: the
// repositories an admin picked, and in each the most recently pushed tags
// plus the tags matching a pattern, by digest. It never reads image layers:
// the images it chooses are scanned by the image scanner
// (internal/collect/image) through the existing image.scan job.
//
// Credentials are sent only to the registry being connected and to the
// token service of that registry: a token realm on any other host is
// refused (WWW-Authenticate is chosen by the server, so a hostile registry
// could otherwise name a host of its own to collect them), and a redirect
// to another host never carries them.
package registry

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Providers.
const (
	GHCR      = "ghcr"
	DockerHub = "dockerhub"
	ECR       = "ecr"
	OCI       = "oci"
)

// Limits on what one integration tracks and reads.
const (
	DefaultRecentTags = 1
	MaxRecentTags     = 3
	// MaxPatternTags bounds the tags one repository tracks because they
	// match a pattern (the most recently pushed ones are kept).
	MaxPatternTags = 10
	// MaxRepositories bounds the repositories one integration tracks.
	MaxRepositories = 500
	// MaxTags bounds the tags read for one repository. A repository with
	// more is read in part, and nothing in it is taken as removed.
	MaxTags = 10000
	// MaxInspected bounds the tags of one repository whose manifest is
	// read on a generic OCI registry, which has no API for push times.
	MaxInspected      = 50
	DefaultImageScans = 25
	MaxImageScans     = 500
)

// Config is a container_registry integration's configuration.
type Config struct {
	Provider string `json:"provider"`
	// Namespace: the GitHub organisation or user (ghcr), the Docker Hub
	// namespace (dockerhub), or a repository prefix (oci, optional).
	Namespace string `json:"namespace,omitempty"`
	// URL of a generic registry (oci), https only: https://registry.example.com.
	URL string `json:"url,omitempty"`
	// AuthHost is the one other host:port a generic registry's token
	// service may be on (GitLab: gitlab.com). Credentials go to no other.
	AuthHost string `json:"auth_host,omitempty"`
	// Username goes with the secret when it is a password or token for a
	// named user (Docker Hub, most generic registries).
	Username string `json:"username,omitempty"`

	// Amazon ECR.
	Region     string `json:"region,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	RoleARN    string `json:"role_arn,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	// AWSIntegrationID borrows the access keys (its secret) and role of an
	// aws-managed plugin integration in the same workspace.
	AWSIntegrationID int64 `json:"aws_integration_id,omitempty"`

	// Which repositories: these by name (none: every repository), less
	// those an exclude pattern matches; include patterns, when given,
	// must match too. Patterns are globs: * matches any characters, ?
	// one; they are matched against the name with and without the
	// namespace.
	Repositories []string `json:"repositories,omitempty"`
	Include      []string `json:"include,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`

	// Which tags: the RecentTags most recently pushed tags of each
	// repository (1 to 3; default 1), and tags matching a pattern (a glob,
	// or "semver" for tags such as 1.4.2 and v2.0.0-rc.1).
	RecentTags  int      `json:"recent_tags,omitempty"`
	TagPatterns []string `json:"tag_patterns,omitempty"`

	Platform    string `json:"platform,omitempty"`
	Environment string `json:"environment,omitempty"`
	// ImageScans bounds the image scans one run queues (default 25).
	ImageScans *int `json:"image_scans,omitempty"`
}

var (
	nameRE         = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	hubNamespaceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,254}$`)
	ghNameRE       = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,38})$`)
	regionRE       = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	accountRE      = regexp.MustCompile(`^[0-9]{12}$`)
	roleRE         = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[\w+=,.@/-]{1,512}$`)
	patternRE      = regexp.MustCompile(`^[A-Za-z0-9_.*?/-]{1,128}$`)
	platformRE     = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`)
	hostPortRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)
	usernameRE     = regexp.MustCompile(`^[^\s:]{1,128}$`)
	externalRE     = regexp.MustCompile(`^[\w+=,.@:/-]{2,1000}$`)
	semverTagRE    = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// Validate checks the configuration without contacting the registry.
func (c Config) Validate() error {
	switch c.Provider {
	case GHCR:
		if !ghNameRE.MatchString(c.Namespace) {
			return errors.New("namespace must be the GitHub organisation or user that owns the packages")
		}
	case DockerHub:
		// Docker Hub references carry no host, so a first part that looks
		// like one (a dot, a port) would name another registry.
		if !hubNamespaceRE.MatchString(c.Namespace) {
			return errors.New("namespace must be a Docker Hub user or organisation, such as acme")
		}
		for _, r := range c.Repositories {
			if first, _, _ := strings.Cut(r, "/"); strings.ContainsAny(first, ".:") || first == "localhost" {
				return fmt.Errorf("repository %q names another registry; Docker Hub repositories are namespace/name", r)
			}
		}
	case ECR:
		if !regionRE.MatchString(c.Region) {
			return errors.New("region must be an AWS region such as eu-west-1")
		}
		if c.AccountID != "" && !accountRE.MatchString(c.AccountID) {
			return errors.New("account_id must be a 12-digit AWS account id")
		}
		if c.RoleARN != "" && !roleRE.MatchString(c.RoleARN) {
			return errors.New("role_arn must be an IAM role ARN")
		}
		if c.ExternalID != "" && !externalRE.MatchString(c.ExternalID) {
			return errors.New("external_id is not a valid external id")
		}
		if c.AWSIntegrationID < 0 {
			return errors.New("aws_integration_id must be an integration id")
		}
	case OCI:
		if _, err := ParseRegistryURL(c.URL); err != nil {
			return err
		}
		if c.Namespace != "" && !nameRE.MatchString(c.Namespace) {
			return errors.New("namespace must be a repository prefix such as team/apps")
		}
		if c.AuthHost != "" && !hostPortRE.MatchString(c.AuthHost) {
			return errors.New("auth_host must be a host name, optionally with a port, such as gitlab.com")
		}
	default:
		return fmt.Errorf("provider must be %s, %s, %s or %s", GHCR, DockerHub, ECR, OCI)
	}
	if c.Provider != ECR && (c.RoleARN != "" || c.ExternalID != "" || c.AWSIntegrationID != 0 || c.Region != "" || c.AccountID != "") {
		return errors.New("region, account_id, role_arn, external_id and aws_integration_id are for provider ecr")
	}
	if c.Provider != OCI && (c.URL != "" || c.AuthHost != "") {
		return errors.New("url and auth_host are for provider oci")
	}
	if c.Username != "" && !usernameRE.MatchString(c.Username) {
		return errors.New("username must not contain spaces or a colon")
	}
	if len(c.Repositories) > MaxRepositories {
		return fmt.Errorf("at most %d repositories", MaxRepositories)
	}
	for _, r := range c.Repositories {
		if !nameRE.MatchString(r) || len(r) > 255 {
			return fmt.Errorf("repository %q is not a repository name", r)
		}
	}
	for _, list := range [][]string{c.Include, c.Exclude, c.TagPatterns} {
		if len(list) > 20 {
			return errors.New("at most 20 patterns in each list")
		}
		for _, p := range list {
			if !patternRE.MatchString(p) {
				return fmt.Errorf("pattern %q may only use letters, digits, . _ - / and the wildcards * and ?", p)
			}
		}
	}
	if c.RecentTags < 0 || c.RecentTags > MaxRecentTags {
		return fmt.Errorf("recent_tags must be between 1 and %d", MaxRecentTags)
	}
	if c.Platform != "" && !platformRE.MatchString(c.Platform) {
		return errors.New("platform must look like linux/amd64")
	}
	if len(c.Environment) > 100 {
		return errors.New("environment is too long")
	}
	if c.ImageScans != nil && (*c.ImageScans < 0 || *c.ImageScans > MaxImageScans) {
		return fmt.Errorf("image_scans must be between 0 and %d", MaxImageScans)
	}
	return nil
}

// ImageScanLimit is the number of image scans one run may queue.
func (c Config) ImageScanLimit() int {
	if c.ImageScans == nil {
		return DefaultImageScans
	}
	return *c.ImageScans
}

func (c Config) recent() int {
	if c.RecentTags == 0 {
		return DefaultRecentTags
	}
	return c.RecentTags
}

// ParseRegistryURL checks a generic registry's address: https, a host and
// optional port, no path, query, fragment or user information.
func ParseRegistryURL(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(s, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" || !hostPortRE.MatchString(strings.ToLower(u.Host)) {
		// An IPv6 literal is allowed as well.
		if err == nil && u.Scheme == "https" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" {
			if h := u.Hostname(); net.ParseIP(h) != nil && strings.HasPrefix(u.Host, "[") {
				return &url.URL{Scheme: "https", Host: u.Host}, nil
			}
		}
		return nil, errors.New("url must be the registry's https address, such as https://registry.example.com")
	}
	return &url.URL{Scheme: "https", Host: strings.ToLower(u.Host)}, nil
}

// DisplayName names the registry for an integration without a name of its own.
func (c Config) DisplayName() string {
	switch c.Provider {
	case GHCR:
		return "ghcr.io/" + strings.ToLower(c.Namespace)
	case DockerHub:
		return "docker.io/" + c.Namespace
	case ECR:
		if c.AccountID != "" {
			return c.AccountID + ".dkr.ecr." + c.Region + ".amazonaws.com"
		}
		return "Amazon ECR " + c.Region
	}
	u, err := ParseRegistryURL(c.URL)
	if err != nil {
		return c.URL
	}
	if c.Namespace != "" {
		return u.Host + "/" + c.Namespace
	}
	return u.Host
}

// glob compiles a pattern: * matches any characters (slashes too), ? one.
func glob(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range p {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// Selector decides which repositories and tags an integration tracks.
type Selector struct {
	namespace string
	names     map[string]bool
	include   []*regexp.Regexp
	exclude   []*regexp.Regexp
	semver    bool
	tags      []*regexp.Regexp
	recent    int
}

// NewSelector compiles a validated configuration's choices.
func NewSelector(c Config) *Selector {
	s := &Selector{namespace: strings.ToLower(c.Namespace), recent: c.recent()}
	if len(c.Repositories) > 0 {
		s.names = map[string]bool{}
		for _, r := range c.Repositories {
			s.names[r] = true
		}
	}
	for _, p := range c.Include {
		s.include = append(s.include, glob(p))
	}
	for _, p := range c.Exclude {
		s.exclude = append(s.exclude, glob(p))
	}
	for _, p := range c.TagPatterns {
		if strings.EqualFold(p, "semver") {
			s.semver = true
			continue
		}
		s.tags = append(s.tags, glob(p))
	}
	return s
}

// Repository reports whether a repository is tracked.
func (s *Selector) Repository(name string) bool {
	short := name
	if s.namespace != "" {
		short = strings.TrimPrefix(name, s.namespace+"/")
	}
	match := func(res []*regexp.Regexp) bool {
		for _, re := range res {
			if re.MatchString(name) || re.MatchString(short) {
				return true
			}
		}
		return false
	}
	if s.names != nil && !s.names[name] && !s.names[short] {
		return false
	}
	if len(s.include) > 0 && !match(s.include) {
		return false
	}
	return !match(s.exclude)
}

// PatternTag reports whether a tag matches one of the tag patterns.
func (s *Selector) PatternTag(tag string) bool {
	if s.semver && semverTagRE.MatchString(tag) {
		return true
	}
	for _, re := range s.tags {
		if re.MatchString(tag) {
			return true
		}
	}
	return false
}
