package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/packs"
)

func packCmd() *cobra.Command {
	c := &cobra.Command{Use: "pack", Short: "Build, sign, inspect and try stack packs"}

	var out, keyFile string
	build := &cobra.Command{
		Use:   "build DIR",
		Short: "Build a pack file from a directory with pack.json and Go sources (or pack.wasm)",
		Long: `Builds DIR into a .stkpack file. DIR holds pack.json and either Go sources,
compiled here with GOOS=wasip1 GOARCH=wasm, or a ready pack.wasm from any
language that targets WASI preview 1. With --key the pack is signed with the
publisher's Ed25519 key (a file holding the base64 seed).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			manifest, err := os.ReadFile(filepath.Join(dir, "pack.json"))
			if err != nil {
				return err
			}
			wasm, err := os.ReadFile(filepath.Join(dir, "pack.wasm"))
			if errors.Is(err, os.ErrNotExist) {
				tmp, err := os.MkdirTemp("", "pack-build")
				if err != nil {
					return err
				}
				defer os.RemoveAll(tmp)
				target := filepath.Join(tmp, "pack.wasm")
				build := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", target, "./"+filepath.Clean(dir))
				build.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
				build.Stdout, build.Stderr = os.Stdout, os.Stderr
				if err := build.Run(); err != nil {
					return fmt.Errorf("compile pack: %w", err)
				}
				if wasm, err = os.ReadFile(target); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			data, err := (&packs.Archive{ManifestRaw: manifest, Wasm: wasm}).Bytes()
			if err != nil {
				return err
			}
			a, err := packs.ReadArchive(data) // validates the manifest
			if err != nil {
				return err
			}
			if keyFile != "" {
				raw, err := os.ReadFile(keyFile)
				if err != nil {
					return err
				}
				seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
				if err != nil || len(seed) != ed25519.SeedSize {
					return errors.New("the key file must hold a base64 Ed25519 seed")
				}
				packs.Sign(a, ed25519.NewKeyFromSeed(seed))
			}
			if out == "" {
				out = a.Manifest.ID + "-" + a.Manifest.Version + ".stkpack"
			}
			data, err = a.Bytes()
			if err != nil {
				return err
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
			signed := "unsigned"
			if a.Signature != nil {
				signed = "signed with key " + a.Signature.KeyID
			}
			fmt.Printf("built %s (%s %s, %d KiB, module sha256 %s, %s)\n", out, a.Manifest.ID, a.Manifest.Version,
				len(data)>>10, a.SHA256()[:16], signed)
			return nil
		},
	}
	build.Flags().StringVarP(&out, "output", "o", "", "pack file to write (default ID-VERSION.stkpack)")
	build.Flags().StringVar(&keyFile, "key", "", "publisher signing key (base64 Ed25519 seed)")

	inspect := &cobra.Command{
		Use:   "inspect FILE",
		Short: "Show a pack's manifest and whether this build trusts its signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := readPackFile(args[0])
			if err != nil {
				return err
			}
			kr, err := packs.DefaultKeyring()
			if err != nil {
				return err
			}
			trust, verr := kr.Verify(a)
			m, _ := json.MarshalIndent(a.Manifest, "", "  ")
			fmt.Printf("%s\nmodule sha256: %s\n", m, a.SHA256())
			if verr != nil {
				fmt.Printf("signature: NOT TRUSTED (%v)\n", verr)
			} else {
				fmt.Printf("signature: %s\n", trust)
			}
			return nil
		},
	}

	run := &cobra.Command{
		Use:   "run FILE DIR",
		Short: "Run a pack over a directory and print what it finds (for pack authors)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := readPackFile(args[0])
			if err != nil {
				return err
			}
			kr, err := packs.DefaultKeyring()
			if err != nil {
				return err
			}
			trust, err := kr.Verify(a)
			if err != nil {
				trust = packs.TrustUnsigned // local trial of your own pack
				fmt.Fprintf(os.Stderr, "note: %v; running it anyway because this is a local trial\n", err)
			}
			l, err := packs.Load(cmd.Context(), a, trust)
			if err != nil {
				return err
			}
			defer l.Close(cmd.Context())
			obs, cov, err := lockfile.ScanWith(cmd.Context(), os.DirFS(args[1]), []lockfile.Extension{l})
			if err != nil {
				return err
			}
			for _, o := range obs {
				fmt.Printf("%s\t%s\t%s\n", o.Purl, o.Location, o.Scope)
			}
			for _, c := range cov {
				if strings.HasPrefix(c.Scope, "pack:") {
					fmt.Printf("coverage\t%s\t%s\t%s\n", c.Scope, c.Status, c.Reason)
				}
			}
			return nil
		},
	}
	c.AddCommand(build, inspect, run)
	return c
}

func readPackFile(p string) (*packs.Archive, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return packs.ReadArchive(data)
}
