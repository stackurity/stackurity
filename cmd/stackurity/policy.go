package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/client"
)

// Policy gates in the CLI (docs/policy-gates.md, "In CI" and "At deploy"):
// stackurity scan asks the server whether the scanned repository passes
// the organisation's policies once its upload is evaluated (--policy), and
// stackurity policy check asks it for any asset, for deploy pipelines.
// Violations of policies in warn mode are printed and pass; a violation of
// an enforced policy exits gateExitCode, as --fail-on does.

const (
	policyAuto = "auto"
	policyOff  = "off"
)

// policyGate is scan's --policy.
type policyGate struct {
	mode string
}

func (p *policyGate) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.mode, "policy", policyAuto,
		"check the organisation's policy gates once the server has evaluated the scan: auto (when the server has policy gates) or off")
}

func (p *policyGate) validate() error {
	p.mode = strings.ToLower(strings.TrimSpace(p.mode))
	if p.mode == "" {
		p.mode = policyAuto
	}
	if p.mode != policyAuto && p.mode != policyOff {
		return fmt.Errorf("--policy must be auto or off")
	}
	return nil
}

func (p *policyGate) enabled() bool { return p.mode == policyAuto }

// scanPolicy is the policy check of one scan: prepare asks the server
// (when it has policy gates) which policies apply, before waiting for the
// evaluation; check asks for the answer once the result is ready.
type scanPolicy struct {
	cl  *client.Client
	req client.PolicyCheckRequest
	// active: the server checks policy gates and at least one applies.
	active bool
	// enforced counts the policies that can fail this check.
	enforced int
	warn     io.Writer
}

// prepare finds out whether the policy check applies to this upload.
// Servers without policy gates, or where no policy applies to the asset,
// are skipped without a word; any other failure is a warning (nothing is
// known to be enforced yet).
func (sp *scanPolicy) prepare(ctx context.Context) {
	m, err := sp.cl.Meta(ctx)
	if err != nil || !m.Has(client.FeatureGatePolicies) {
		return
	}
	dry := sp.req
	dry.DryRun = true
	pc, err := sp.cl.CheckPolicies(ctx, dry)
	switch {
	case errors.Is(err, client.ErrPolicyCheckUnsupported):
		return
	case err != nil:
		fmt.Fprintf(sp.warn, "warning: policy gates not checked: %v\n", err)
		return
	}
	sp.active = pc.PoliciesEvaluated > 0
	sp.enforced = pc.PoliciesEnforced
}

// check asks for the answer and prints it to w. It returns an exitError
// when an enforced policy fails. A check that cannot be made fails the
// build only when an enforced policy applies; otherwise it is a warning.
func (sp *scanPolicy) check(ctx context.Context, w io.Writer) error {
	pc, err := sp.cl.CheckPolicies(ctx, sp.req)
	if err != nil {
		if errors.Is(err, client.ErrPolicyCheckUnsupported) {
			return nil
		}
		if sp.enforced > 0 {
			return fmt.Errorf("policy gates could not be checked, and %s enforced: %w", count(sp.enforced, "policy is", "policies are"), err)
		}
		fmt.Fprintf(sp.warn, "warning: policy gates not checked: %v\n", err)
		return nil
	}
	printPolicyCheck(w, pc)
	return policyExit(pc)
}

// notReady handles --wait running out before the server evaluated the
// upload when only the policy check needed the result: with an enforced
// policy the gate could not be applied (notReadyExitCode, never a pass);
// otherwise a warning.
func (sp *scanPolicy) notReady(err error) error {
	if sp.enforced > 0 {
		return err
	}
	fmt.Fprintf(sp.warn, "warning: policy gates not checked: %v\n", err)
	return nil
}

// policyExit is the exit a check's answer calls for: gateExitCode when it
// failed (a violation of an enforced policy), nil otherwise.
func policyExit(pc *client.PolicyCheck) error {
	if pc.Result != "fail" {
		return nil
	}
	n := 0
	for _, v := range pc.Violations {
		if v.Mode == "enforce" && !v.EnforceRequiresPlan {
			n++
		}
	}
	if n == 0 {
		n = len(pc.Violations)
	}
	return &exitError{code: gateExitCode, msg: count(n, "violation", "violations") + " of enforced policy gates"}
}

// printPolicyCheck prints the "Policy gates" block: the result, then each
// violation with its policy, mode, reason and link.
func printPolicyCheck(w io.Writer, pc *client.PolicyCheck) {
	policies := count(pc.PoliciesEvaluated, "policy", "policies")
	switch pc.Result {
	case "pass", "":
		fmt.Fprintf(w, "Policy gates: pass (%s checked)\n", policies)
		return
	case "warn":
		fmt.Fprintf(w, "Policy gates: %s, none enforced (%s checked)\n", count(len(pc.Violations), "violation", "violations"), policies)
	default:
		fmt.Fprintf(w, "Policy gates: fail, %s (%s checked)\n", count(len(pc.Violations), "violation", "violations"), policies)
	}
	for _, v := range pc.Violations {
		mode := v.Mode
		if v.EnforceRequiresPlan {
			mode = "enforce, not enforced on this plan"
		}
		fmt.Fprintf(w, "  %s [%s]\n", v.PolicyName, mode)
		fmt.Fprintf(w, "    %s\n", v.Reason)
		if v.Component != "" && !strings.Contains(v.Reason, v.Component) {
			fmt.Fprintf(w, "    component: %s\n", v.Component)
		}
		if v.Link != "" {
			fmt.Fprintf(w, "    %s\n", v.Link)
		}
	}
	for _, v := range pc.Violations {
		if v.EnforceRequiresPlan {
			fmt.Fprintln(w, "  Enforce mode needs a paid plan; until then those policies only warn.")
			break
		}
	}
}

// ciRef is the branch or tag a CI job runs for, from the provider's
// variables, for the check's record.
func ciRef(getenv func(string) string) string {
	for _, k := range []string{"GITHUB_REF", "CI_COMMIT_REF_NAME", "BITBUCKET_BRANCH", "BUILDKITE_BRANCH", "CIRCLE_BRANCH"} {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// policyCheckOptions are the flags of stackurity policy check.
type policyCheckOptions struct {
	asset        int64
	image, repo  string
	commit, ref  string
	json         bool
	stdout, warn io.Writer
}

// request validates the flags and builds the request.
func (o *policyCheckOptions) request() (client.PolicyCheckRequest, error) {
	n := 0
	if o.asset != 0 {
		n++
	}
	if strings.TrimSpace(o.image) != "" {
		n++
	}
	if strings.TrimSpace(o.repo) != "" {
		n++
	}
	if n != 1 {
		return client.PolicyCheckRequest{}, errors.New("name the asset with one of --asset, --image and --repo")
	}
	if o.asset < 0 {
		return client.PolicyCheckRequest{}, errors.New("--asset must be an asset id")
	}
	img := strings.TrimSpace(o.image)
	if img != "" {
		// image@sha256:… is accepted; only the digest is sent.
		if _, d, ok := strings.Cut(img, "@"); ok {
			img = d
		}
		if !strings.HasPrefix(img, "sha256:") || len(img) != len("sha256:")+64 {
			return client.PolicyCheckRequest{}, errors.New("--image takes an image digest: sha256:<64 hex digits> (or name@sha256:…)")
		}
	}
	return client.PolicyCheckRequest{AssetID: o.asset, ImageDigest: img, RepositoryURL: strings.TrimSpace(o.repo),
		Source: "deploy", Commit: strings.TrimSpace(o.commit), Ref: strings.TrimSpace(o.ref)}, nil
}

// deployPlanNotice is printed when the server answers a deploy check
// without the deploy gate (a paid feature): the deploy goes ahead whatever
// the violations, rather than breaking a pipeline when a plan changes.
const deployPlanNotice = "notice: the deploy gate needs a paid plan; this check reports violations but never fails a deploy"

// run asks the server and reports, as text or JSON.
func (o *policyCheckOptions) run(ctx context.Context, cl *client.Client) error {
	req, err := o.request()
	if err != nil {
		return err
	}
	pc, err := cl.CheckPolicies(ctx, req)
	if err != nil {
		return err
	}
	if pc.DeployRequiresPlan {
		// On stderr, so --json output stays JSON.
		fmt.Fprintln(o.warn, deployPlanNotice)
	}
	if o.json {
		enc := json.NewEncoder(o.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(pc); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(o.stdout, "asset %d: %s\n", pc.AssetID, pc.AssetName)
		printPolicyCheck(o.stdout, pc)
	}
	return policyExit(pc)
}

func policyCmd() *cobra.Command {
	root := &cobra.Command{Use: "policy", Short: "Check assets against the organisation's policy gates"}
	var c conn
	o := policyCheckOptions{stdout: os.Stdout, warn: os.Stderr}
	check := &cobra.Command{
		Use:   "check",
		Short: "Check one asset against its policy gates, for deploy pipelines",
		Long: `Asks the server whether an asset passes the policy gates that apply to it
now, and prints each violation with its policy, mode, reason and link. Name
the asset with one of --asset (its id), --image (a container image digest,
sha256:…, or name@sha256:…) or --repo (a repository URL).

Violations of policies in warn mode are printed and the command exits 0; a
violation of an enforced policy exits with status 3, as stackurity scan
--fail-on does. Failing a deploy needs a paid plan (the deploy gate):
without it the check reports violations, prints a notice and exits 0. --json prints the server's answer as JSON instead. The
check is recorded on the server as a deploy check.

The token needs the viewer role (an API token), or is a collector token
bound to the asset. A server older than policy gates is an error here.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := o.request(); err != nil {
				return err
			}
			cl, err := c.connect(cmd.Context(), false)
			if err != nil {
				return err
			}
			return o.run(cmd.Context(), cl)
		},
	}
	c.flags(check)
	check.Flags().Int64Var(&o.asset, "asset", 0, "the asset's id")
	check.Flags().StringVar(&o.image, "image", "", "a container image digest (sha256:…, or name@sha256:…)")
	check.Flags().StringVar(&o.repo, "repo", "", "a repository URL (https://github.com/acme/app)")
	check.Flags().StringVar(&o.commit, "commit", "", "the commit being deployed, recorded with the check")
	check.Flags().StringVar(&o.ref, "ref", "", "the branch, tag or release being deployed, recorded with the check")
	check.Flags().BoolVar(&o.json, "json", false, "print the server's answer as JSON")
	root.AddCommand(check)
	return root
}
