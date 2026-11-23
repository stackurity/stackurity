package confcheck

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/stackurity/stackurity/internal/model"
)

// GitHub Actions supply chain. A workflow that runs a third-party action by
// a tag or a branch runs whatever the action's repository points that name
// at on the day it runs: whoever takes over that repository, or one of its
// maintainers' accounts, changes the code without any change here (the
// tj-actions/changed-files compromise of March 2025 rewrote every tag).
// That matters most where the job hands the action a credential: an SSH
// key, cloud credentials or a deploy token, or a login as root.

// Actions rules.
const (
	RuleActionUnpinned        = "gha-action-unpinned"
	RuleActionUnpinnedSecrets = "gha-action-unpinned-secrets"
	RuleActionFirstPartyTag   = "gha-action-first-party-tag"
	RulePRTargetCheckout      = "gha-pull-request-target-checkout"
)

// maxWorkflows bounds the workflow files read in one repository.
const maxWorkflows = 200

var (
	fullSHA    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	secretRef  = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)|secrets\[\s*['"]([^'"]+)['"]\s*\]`)
	sshSecret  = regexp.MustCompile(`(?i)(ssh|private_?key|id_rsa|id_ed25519|\bpem\b|_pem|deploy_?key|server_?key)`)
	cloudCreds = regexp.MustCompile(`(?i)(aws_(secret|access|session)|azure_(credentials|client_secret)|arm_client_secret|gcp_|gcloud|` +
		`google_(application_)?credentials|service_account|digitalocean|^do_(api_)?(access_)?token|hcloud|linode|vultr|cloudflare_api|` +
		`^cf_api_token|kube_?config|^oci_)`)
	deployToken = regexp.MustCompile(`(?i)(deploy|heroku_api_key|fly_api_token|vercel_token|netlify_auth_token|railway_token|render_api_key)`)
	// Inputs that take a key or cloud credentials whatever the secret is called.
	keyInput = regexp.MustCompile(`(?i)^(key|ssh[-_]?key|ssh[-_]?private[-_]?key|private[-_]?key|aws-secret-access-key|credentials_json|creds|kubeconfig|kube-config)$`)
	// A checkout of a pull request's own code.
	prHead     = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref|repo)|github\.head_ref|refs/pull/`)
	prHeadRun  = regexp.MustCompile(`gh\s+pr\s+checkout|git\s+(fetch|checkout|switch)\b[^\n]*(pull/|github\.event\.pull_request\.head|github\.head_ref)`)
	branchName = regexp.MustCompile(`^(main|master|develop|dev|trunk|stable|release|latest|nightly|canary|edge)$|/`)
)

// pinDoc is the how-to linked from findings about unpinned actions.
const pinDoc = "https://stackurity.ai/blog/how-to-harden-github-actions-pin-actions-to-a-commit-sha/"

// RuleDoc is the page that explains a rule and how to fix it, or "".
func RuleDoc(rule string) string {
	switch rule {
	case RuleActionUnpinned, RuleActionUnpinnedSecrets, RuleActionFirstPartyTag:
		return pinDoc
	case RulePRTargetCheckout:
		return "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
	case RuleAttackToolArtex, RuleAttackToolArtexBackdoor:
		return AttackToolsDoc
	case RuleKernelSCTP:
		return KernelModulesDoc
	}
	return ""
}

// Workflows checks the GitHub Actions workflows of the repository at dir
// (.github/workflows/*.yml and *.yaml). Paths are relative to dir.
// problems names the files that could not be read.
func Workflows(dir string) (found []model.ConfigFinding, problems []string) {
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, ".github", "workflows", pat))
		files = append(files, m...)
	}
	sort.Strings(files)
	if len(files) > maxWorkflows {
		problems = append(problems, fmt.Sprintf("more than %d workflow files; the first were checked", maxWorkflows))
		files = files[:maxWorkflows]
	}
	for _, f := range files {
		rel, err := filepath.Rel(dir, f)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		real, ok := insideDir(dir, f)
		if !ok {
			continue // a link may point out of the repository
		}
		data, truncated, err := ReadBounded(real)
		if err != nil || truncated {
			problems = append(problems, rel+" could not be read")
			continue
		}
		fs, err := WorkflowFindings(rel, data)
		if err != nil {
			problems = append(problems, rel+" is not valid YAML")
			continue
		}
		found = append(found, fs...)
	}
	return found, problems
}

// WorkflowFindings checks one workflow file; rel is how it is named.
func WorkflowFindings(rel string, data []byte) ([]model.ConfigFinding, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	root := doc.Content[0]
	prt := hasTrigger(get(root, "on"), "pull_request_target")
	wfSecrets := secretsIn(get(root, "env"))
	var out []model.ConfigFinding
	seen := map[string]bool{}
	jobs := get(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		jobSecrets := append(append([]credential{}, wfSecrets...), secretsIn(get(job, "env"))...)
		// A reusable workflow called by the job.
		if u := get(job, "uses"); u != nil && u.Kind == yaml.ScalarNode {
			creds := append(append([]credential{}, jobSecrets...), secretsIn(get(job, "with"))...)
			s := get(job, "secrets")
			if s != nil && s.Kind == yaml.ScalarNode && s.Value == "inherit" {
				creds = append(creds, credential{name: "every secret (secrets: inherit)", kind: "secrets"})
			} else {
				creds = append(creds, secretsIn(s)...)
			}
			if f, ok := actionFinding(rel, jobName, u, creds, false); ok && !seen[f.Fingerprint] {
				seen[f.Fingerprint] = true
				out = append(out, f)
			}
		}
		steps := get(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		prtDone := false
		for _, st := range steps.Content {
			if st.Kind != yaml.MappingNode {
				continue
			}
			u := get(st, "uses")
			with := get(st, "with")
			if prt && !prtDone {
				if line, what := headCheckout(st, u, with); line > 0 {
					prtDone = true
					out = append(out, finding(RulePRTargetCheckout, model.ConfigCI, "pull_request_target runs the pull request's code", "high",
						rel, line, "job "+jobName,
						"Job "+jobName+" runs on pull_request_target, which has this repository's secrets and a token that can write to it, and "+
							what+": anyone who opens a pull request can run code with them.",
						"Build pull request code under the pull_request trigger instead; if this job needs secrets, have it check out only "+
							"the base branch, or split it into a pull_request job and a workflow_run job that reads only its results."))
				}
			}
			if u == nil || u.Kind != yaml.ScalarNode {
				continue
			}
			creds := append(append([]credential{}, jobSecrets...), secretsIn(get(st, "env"))...)
			creds = append(creds, secretsIn(with)...)
			asRoot := false
			if with != nil {
				if v := get(with, "username"); v != nil && strings.EqualFold(strings.TrimSpace(v.Value), "root") {
					asRoot = true
				}
				if v := get(with, "user"); v != nil && strings.EqualFold(strings.TrimSpace(v.Value), "root") {
					asRoot = true
				}
			}
			if f, ok := actionFinding(rel, jobName, u, creds, asRoot); ok && !seen[f.Fingerprint] {
				seen[f.Fingerprint] = true
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// credential is a secret a step or job is given that matters if the action
// is replaced: what it is called and what kind it looks like.
type credential struct{ name, kind string }

// secretsIn finds the secrets passed in a mapping (env, with, secrets) that
// look like an SSH key, cloud credentials or a deploy token.
func secretsIn(n *yaml.Node) []credential {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var out []credential
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		if val.Kind != yaml.ScalarNode {
			continue
		}
		for _, m := range secretRef.FindAllStringSubmatch(val.Value, -1) {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			if strings.EqualFold(name, "GITHUB_TOKEN") {
				continue
			}
			switch {
			case sshSecret.MatchString(name):
				out = append(out, credential{name, "an SSH key"})
			case cloudCreds.MatchString(name):
				out = append(out, credential{name, "cloud credentials"})
			case deployToken.MatchString(name):
				out = append(out, credential{name, "a deploy token"})
			case keyInput.MatchString(key) && strings.Contains(strings.ToLower(key), "key") && !strings.HasPrefix(strings.ToLower(key), "aws"):
				out = append(out, credential{name, "an SSH key"})
			case keyInput.MatchString(key):
				out = append(out, credential{name, "cloud credentials"})
			}
		}
	}
	return out
}

// actionFinding grades one "uses:" of an action or a reusable workflow.
func actionFinding(rel, job string, u *yaml.Node, creds []credential, asRoot bool) (model.ConfigFinding, bool) {
	ref := strings.TrimSpace(u.Value)
	if ref == "" || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") || strings.Contains(ref, "${{") {
		return model.ConfigFinding{}, false
	}
	name, ver, ok := strings.Cut(ref, "@")
	if !ok || ver == "" || fullSHA.MatchString(ver) {
		return model.ConfigFinding{}, false
	}
	owner, _, _ := strings.Cut(name, "/")
	byWhat := "tag " + ver
	if branchName.MatchString(ver) {
		byWhat = "branch " + ver
	}
	fix := "Pin it to a commit: uses: " + name + "@<40-character commit SHA> # " + ver +
		" (Dependabot or Renovate keep pinned SHAs up to date). How-to: " + pinDoc
	switch o := strings.ToLower(owner); {
	case o == "actions" || o == "github":
		return finding(RuleActionFirstPartyTag, model.ConfigCI, "GitHub's own action used by "+strings.SplitN(byWhat, " ", 2)[0], "info",
			rel, u.Line, ref,
			name+" runs by "+byWhat+". It is GitHub's own action, so the risk is small; pin it if your policy is to pin every action.",
			fix), true
	case len(creds) > 0 || asRoot:
		var gave []string
		for _, c := range creds {
			if c.kind == "secrets" {
				gave = append(gave, c.name)
				continue
			}
			gave = append(gave, c.kind+" ("+c.name+")")
		}
		if asRoot {
			gave = append(gave, "a login as root")
		}
		gave = uniq(gave)
		return finding(RuleActionUnpinnedSecrets, model.ConfigCI, "Unpinned third-party action is given credentials", "medium",
			rel, u.Line, ref+" in job "+job,
			name+" runs by "+byWhat+", which its owner, or anyone who takes over its repository, can point at other code; job "+job+
				" gives it "+strings.Join(gave, ", ")+", so that code would get them too.",
			fix), true
	default:
		return finding(RuleActionUnpinned, model.ConfigCI, "Third-party action used by "+strings.SplitN(byWhat, " ", 2)[0], "low",
			rel, u.Line, ref,
			name+" runs by "+byWhat+", which can be moved to different code without any change to this workflow.",
			fix), true
	}
}

// headCheckout reports the line of a step that checks out a pull
// request's own code, and how it does.
func headCheckout(st, u, with *yaml.Node) (int, string) {
	if u != nil && strings.HasPrefix(strings.ToLower(u.Value), "actions/checkout@") && with != nil {
		for _, k := range []string{"ref", "repository"} {
			if v := get(with, k); v != nil && prHead.MatchString(v.Value) {
				return v.Line, "checks out the pull request's head (" + k + ": " + clip(strings.TrimSpace(v.Value), 120) + ")"
			}
		}
	}
	if r := get(st, "run"); r != nil && prHeadRun.MatchString(r.Value) {
		return r.Line, "its run step checks out the pull request's code"
	}
	return 0, ""
}

// hasTrigger reports whether a workflow's "on" names event.
func hasTrigger(on *yaml.Node, event string) bool {
	if on == nil {
		return false
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == event
	case yaml.SequenceNode:
		for _, c := range on.Content {
			if c.Value == event {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(on.Content); i += 2 {
			if on.Content[i].Value == event {
				return true
			}
		}
	}
	return false
}

// get returns the value of key in a mapping node, or nil.
func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
