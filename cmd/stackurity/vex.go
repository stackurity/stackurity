package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/vex"
)

// vexImportResult is the part of POST /vex/import's answer the command
// prints.
type vexImportResult struct {
	Document struct {
		ID          int64  `json:"id"`
		Format      string `json:"format"`
		Source      string `json:"source"`
		Signature   string `json:"signature"`
		AutoApplied bool   `json:"auto_applied"`
	} `json:"document"`
	Statements   int `json:"statements"`
	Matched      int `json:"matched"`
	Unmatched    int `json:"unmatched"`
	Pending      int `json:"pending"`
	AutoApproved int `json:"auto_approved"`
	Ignored      int `json:"ignored"`
	Ended        int `json:"ended"`
	Skipped      int `json:"skipped"`
	// AutoApplyRefused and OutsideSubject: why a trusted source's
	// statements still wait for approval.
	AutoApplyRefused string `json:"auto_apply_refused"`
	OutsideSubject   int    `json:"outside_subject"`
	Problems         []struct {
		Product string `json:"product"`
		Kind    string `json:"kind"`
		Reason  string `json:"reason"`
	} `json:"problems"`
}

func vexCmd() *cobra.Command {
	c := &cobra.Command{Use: "vex", Short: "Import VEX statements, or export decisions as OpenVEX or CycloneDX VEX"}

	var ic conn
	var source, asset int64
	imp := &cobra.Command{
		Use:   "import FILE",
		Short: "Import an OpenVEX or CycloneDX VEX document (or a signed attestation of one)",
		Long: `Uploads a VEX document: OpenVEX (v0.2, and v0.0.1), CycloneDX VEX or a
CycloneDX BOM with VEX embedded, plain or as a signed in-toto attestation (a
DSSE envelope or Sigstore bundle, as cosign attest writes it). It is read here
first, for a clear error before anything is uploaded.

A not_affected statement does not hide anything by itself: it waits in
Approvals until a security or admin user approves it, unless --source names a
source an admin trusts to apply on its own. Statements whose products match
nothing here, or match ambiguously, are listed and not applied.

--asset or --project (an id or name; or STACKURITY_PROJECT) limits matching to
that asset or project's assets.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			doc, err := vex.Read(data)
			if err != nil {
				return err
			}
			if len(doc.Statements) == 0 {
				return errors.New("the document has no VEX statements")
			}
			cl, err := ic.connect(cmd.Context(), false)
			if err != nil {
				return err
			}
			q := url.Values{"filename": {filepath.Base(args[0])}}
			if source > 0 {
				q.Set("source_id", strconv.FormatInt(source, 10))
			}
			if asset > 0 {
				q.Set("asset_id", strconv.FormatInt(asset, 10))
			} else if cl.Project > 0 {
				q.Set("project_id", strconv.FormatInt(cl.Project, 10))
			}
			var r vexImportResult
			if err := cl.Do(cmd.Context(), "POST", "/api/v1/vex/import?"+q.Encode(), bytes.NewReader(data),
				map[string]string{"Content-Type": "application/json"}, &r); err != nil {
				return err
			}
			fmt.Printf("VEX document %d (%s, from %s, signature %s): %d statements, %d matched, %d not matched\n",
				r.Document.ID, r.Document.Format, r.Document.Source, r.Document.Signature, r.Statements, r.Matched, r.Unmatched)
			if r.AutoApproved > 0 {
				fmt.Printf("%d not_affected statements applied on import (trusted source): %d issues ignored\n", r.AutoApproved, r.Ignored)
			}
			if r.AutoApplyRefused != "" {
				fmt.Println("not applied on its own: " + r.AutoApplyRefused)
			}
			if r.OutsideSubject > 0 {
				fmt.Printf("%d not_affected statements matched assets the attestation is not about (or a bare package anywhere): that part waits for approval\n", r.OutsideSubject)
			}
			if r.Pending > 0 {
				fmt.Printf("%d not_affected statements wait for approval under Approvals\n", r.Pending)
			}
			if r.Ended > 0 {
				fmt.Printf("%d earlier VEX ignore rules ended: newer statements say affected or under investigation\n", r.Ended)
			}
			if r.Skipped > 0 {
				fmt.Printf("%d CycloneDX vulnerabilities have no analysis and were skipped\n", r.Skipped)
			}
			for i, p := range r.Problems {
				if i == 20 {
					fmt.Printf("... and %d more (see the document under Settings > VEX)\n", len(r.Problems)-20)
					break
				}
				fmt.Printf("  %s: %s: %s\n", p.Kind, p.Product, p.Reason)
			}
			return nil
		},
	}
	ic.flags(imp)
	imp.Flags().Int64Var(&source, "source", 0, "VEX source id (Settings > VEX); its key or token decides whether statements apply on their own")
	imp.Flags().Int64Var(&asset, "asset", 0, "match only on this asset (needed for a document about a product with no identifier of its own)")

	var ec conn
	var exportAsset int64
	var format, out string
	var notes bool
	exp := &cobra.Command{
		Use:   "export",
		Short: "Export decisions (false positives, mitigations, imported VEX) as OpenVEX or CycloneDX VEX",
		Long: `Writes the decisions about open issues as a VEX document: issues ignored as a
false positive or mitigated (with the justification of the VEX statement that
made the rule, when one did), and the latest imported affected, fixed or
under_investigation statements. Each statement names the component version,
inside its image (by digest) or application when the asset has one.

--asset limits it to one asset; --project (an id or name; or
STACKURITY_PROJECT) to one project; neither, every asset you can see.

People's ignore notes and mitigations stay out unless --notes is given
(security or admin role): read the document before you share it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != vex.FormatOpenVEX && format != vex.FormatCycloneDX {
				return errors.New("--format must be openvex or cyclonedx")
			}
			cl, err := ec.connect(cmd.Context(), false)
			if err != nil {
				return err
			}
			q := url.Values{"format": {format}}
			if exportAsset > 0 {
				q.Set("asset_id", strconv.FormatInt(exportAsset, 10))
			}
			if notes {
				q.Set("notes", "true")
			}
			var w io.Writer = os.Stdout
			if out != "-" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			return cl.Do(cmd.Context(), "GET", "/api/v1/vex/export?"+q.Encode(), nil, nil, w)
		},
	}
	ec.flags(exp)
	exp.Flags().Int64Var(&exportAsset, "asset", 0, "export only this asset's decisions")
	exp.Flags().StringVar(&format, "format", vex.FormatOpenVEX, "openvex or cyclonedx")
	exp.Flags().StringVarP(&out, "output", "o", "-", "output file")
	exp.Flags().BoolVar(&notes, "notes", false, "include people's ignore notes and mitigations as impact statements (security or admin role)")

	c.AddCommand(imp, exp)
	return c
}
