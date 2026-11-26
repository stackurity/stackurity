package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/evidencesig"
)

func evidenceCmd() *cobra.Command {
	c := &cobra.Command{Use: "evidence", Short: "Verify a compliance evidence pack, or print a signing key's key set entry"}

	var keys string
	verify := &cobra.Command{
		Use:   "verify PACK.zip",
		Short: "Check an evidence pack's files and its signed manifest",
		Long: `Checks every file in an evidence pack ZIP against manifest.json's SHA-256
list, then manifest.json's Ed25519 signature (manifest.json.sig) against the
published key set. Runs offline with --keys FILE.

--keys is a key set file or https URL (default: Stackurity Cloud's, ` + evidencesig.KeySetURL + `).
A self-hosted server that signs with its own key publishes its own key set.

Exit status 0: the pack is signed by a key in the set and no file changed.
Any other status: it is unsigned, changed or signed by an unknown or
revoked key; the message says which.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := loadKeySet(cmd.Context(), keys)
			if err != nil {
				return err
			}
			return verifyPack(cmd.OutOrStdout(), args[0], ks)
		},
	}
	verify.Flags().StringVar(&keys, "keys", evidencesig.KeySetURL, "key set: a file or an https URL")

	var notBefore string
	pub := &cobra.Command{
		Use:   "pubkey KEYFILE",
		Short: "Print the key set entry for an Ed25519 signing key (PKCS#8 PEM)",
		Long: `Prints the JSON entry to add to the published key set for the private key
in KEYFILE (made with: openssl genpkey -algorithm ed25519 -out KEYFILE).
Only the public key is printed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := evidencesig.LoadSigner(args[0])
			if err != nil {
				return err
			}
			nb := time.Now()
			if notBefore != "" {
				if nb, err = time.Parse(time.RFC3339, notBefore); err != nil {
					return fmt.Errorf("--not-before: %w", err)
				}
			}
			b, _ := json.MarshalIndent(evidencesig.Entry(s.PublicKey(), nb.Truncate(time.Second)), "", "  ")
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return err
		},
	}
	pub.Flags().StringVar(&notBefore, "not-before", "", "first moment the key signs, RFC 3339 (default: now)")
	c.AddCommand(verify, pub)
	return c
}

func loadKeySet(ctx context.Context, src string) (*evidencesig.KeySet, error) {
	var b []byte
	var err error
	switch {
	case strings.HasPrefix(src, "https://"):
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if rerr != nil {
			return nil, rerr
		}
		resp, rerr := http.DefaultClient.Do(req)
		if rerr != nil {
			return nil, fmt.Errorf("key set: %w (use --keys FILE offline)", rerr)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("key set: %s answered %s", src, resp.Status)
		}
		b, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	case strings.HasPrefix(src, "http://"):
		return nil, errors.New("key set: use an https URL or a file")
	default:
		b, err = os.ReadFile(src)
	}
	if err != nil {
		return nil, err
	}
	return evidencesig.ParseKeySet(b)
}

func verifyPack(w io.Writer, path string, ks *evidencesig.KeySet) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	res, err := evidencesig.VerifyZIP(f, st.Size(), ks)
	if errors.Is(err, evidencesig.ErrUnsigned) {
		fmt.Fprintf(w, "%d files match manifest.json, but the pack is NOT SIGNED: nothing proves who made it.\n", res.Files)
		return err
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "ok: %d files match manifest.json, signed by %s (%s) on %s\n", res.Files, res.Key.KeyID, res.Key.Status,
		res.Manifest.GeneratedAt.UTC().Format(time.RFC3339))
	return nil
}
