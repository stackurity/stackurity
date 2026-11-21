package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/codefindings"
)

// codeImportResult is POST /code-findings/import's answer.
type codeImportResult struct {
	AssetID  int64 `json:"asset_id"`
	Complete bool  `json:"complete"`
	Sources  []struct {
		Source  string `json:"source"`
		Found   int    `json:"found"`
		Open    int    `json:"open"`
		Closed  int    `json:"closed"`
		New     int    `json:"new"`
		Gone    int    `json:"gone"`
		Skipped int    `json:"skipped"`
	} `json:"sources"`
}

func importCmd() *cobra.Command {
	c := &cobra.Command{Use: "import", Short: "Import other tools' reports"}

	var ic conn
	var format, asset, model string
	var partial bool
	code := &cobra.Command{
		Use:   "code-findings FILE",
		Short: "Import a code scanner's findings (deepsec JSON export, SARIF 2.1.0) for a repository",
		Long: `Uploads a code-review scanner's report as code findings of a repository,
shown next to its dependency, host and image findings. --format deepsec reads
the JSON that "deepsec export --format json" writes; --format sarif reads SARIF
2.1.0. The file is read here first, for a clear error before anything is
uploaded (at most 16 MB and 5,000 findings).

--asset is the repository: its asset id, or its URL as stackurity scan reports
it (default STACKURITY_GIT_URL, or in a CI job with keyless sign-in, the job's
own repository). The repository must have reported already.

Importing again updates the same findings; with a complete report, findings it
no longer has are resolved as gone. Use --partial for a filtered export (for
example deepsec's --only-true-positive or --since), so nothing else is
resolved. --model records the AI model that produced the report.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			data, err := io.ReadAll(io.LimitReader(f, codefindings.MaxDocumentSize+1))
			if err != nil {
				return err
			}
			rep, err := codefindings.Parse(format, data)
			if err != nil {
				return err
			}
			cl, err := ic.connect(cmd.Context(), false)
			if err != nil {
				return err
			}
			m, err := cl.Meta(cmd.Context())
			if err != nil {
				return fmt.Errorf("could not ask the server what it supports: %w", err)
			}
			if !m.Has(client.FeatureCodeFindings) {
				return fmt.Errorf("the server (version %s) does not take code findings; upgrade it first", m.Version)
			}
			target := strings.TrimSpace(asset)
			if target == "" {
				target = ic.ciRepo
			}
			if target == "" {
				return errors.New("--asset is required: the repository's asset id or URL (or set STACKURITY_GIT_URL)")
			}
			q := url.Values{"format": {format}}
			if id, err := strconv.ParseInt(target, 10, 64); err == nil {
				q.Set("asset_id", strconv.FormatInt(id, 10))
			} else {
				q.Set("git_url", target)
			}
			if partial {
				q.Set("complete", "false")
			}
			if model != "" {
				q.Set("model", model)
			}
			var res codeImportResult
			if err := cl.Do(cmd.Context(), "POST", "/api/v1/code-findings/import?"+q.Encode(), bytes.NewReader(data),
				map[string]string{"Content-Type": "application/json"}, &res); err != nil {
				return err
			}
			printCodeImport(cmd.OutOrStdout(), rep, &res)
			return nil
		},
	}
	ic.ci = true
	ic.flags(code)
	code.Flags().StringVar(&format, "format", "", "report format: deepsec or sarif (required)")
	code.Flags().StringVar(&asset, "asset", os.Getenv("STACKURITY_GIT_URL"), "the repository: asset id or URL (env STACKURITY_GIT_URL)")
	code.Flags().StringVar(&model, "model", "", "the AI model that produced the report, recorded with each finding")
	code.Flags().BoolVar(&partial, "partial", false, "the report is filtered: resolve nothing it does not hold")
	_ = code.MarkFlagRequired("format")

	c.AddCommand(code)
	return c
}

func printCodeImport(w io.Writer, rep *codefindings.Report, res *codeImportResult) {
	for _, s := range res.Sources {
		fmt.Fprintf(w, "asset %d, %s: %d findings (%d open, %d closed by the source's verdict, %d new)", res.AssetID, s.Source,
			s.Found, s.Open, s.Closed, s.New)
		if res.Complete {
			fmt.Fprintf(w, ", %d resolved as gone", s.Gone)
		}
		if s.Skipped > 0 {
			fmt.Fprintf(w, ", %d results skipped (not failures)", s.Skipped)
		}
		fmt.Fprintln(w)
	}
	if len(res.Sources) == 0 && rep.Count() == 0 {
		fmt.Fprintln(w, "the report holds no findings")
	}
}
