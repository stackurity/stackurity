// Command feedback-agent works on the Stackurity feedback queue as feedback
// arrives (docs/feedback-queue.md#the-feedback-agent). It runs on the
// owner's Mac, from launchd every ten minutes, never in GitHub Actions.
//
// Each run, for each new item and each item the owner approved (approved
// first, at most -max a run):
//
//  1. reads the item, its thread and its attachments with the triage token
//     (frames from videos with ffmpeg when it is installed);
//  2. makes a fresh worktree of origin/main and runs `claude -p` headless in
//     it, with the item as untrusted data, the allowed paths and the rules
//     for what needs the owner. Claude writes result.json: done,
//     needs_more_info, needs_approval or cannot;
//  3. checks what changed. Anything outside web/, internal/, docs/ and
//     changelog.d/, or in a path that needs approval (migrations, billing,
//     sign-in and roles, emails, legal text, Ask prompts, dependencies),
//     goes to the owner instead, unless they approved it;
//  4. done: runs the checks (gofmt, go build/vet, go test of the changed
//     packages, and the web's typecheck, lint and tests), pushes a branch,
//     opens a pull request and links it on the item (in_progress). Never
//     merges, never deploys;
//     needs_more_info: asks the sender in the thread (needs_info);
//     needs_approval: needs_owner with the reason (the server emails
//     STACKURITY_FEEDBACK_APPROVERS);
//     cannot: needs_owner as a won't-fix candidate, for the owner to decline
//     with a reason or approve;
//  5. posts each outcome to Slack when a webhook file is configured.
//
// Runs never overlap (a lock file), each claude run stops after 45 minutes,
// and an item that fails twice goes to the owner.
//
//	go run ./tools/feedback-agent            one run
//	go run ./tools/feedback-agent -item FB-12
//	go run ./tools/feedback-agent -dry-run   decide, but write nothing to the queue, push nothing
//
// Settings (environment):
//
//	STACKURITY_FEEDBACK_API          default https://app.stackurity.dev/api/v1/admin/feedback
//	STACKURITY_FEEDBACK_TOKEN_FILE   the triage token (mode 0600), default ~/.config/stackurity/feedback-agent-token
//	FEEDBACK_AGENT_REPO              a clone of github.com/stackurity/stackurity, default ~/code/stackurity-feedback
//	FEEDBACK_AGENT_WORK              runs and worktrees, default ~/code/feedback-agent-runs
//	FEEDBACK_AGENT_SLACK_WEBHOOK_FILE  a Slack incoming webhook URL (mode 0600); unset posts nothing
//	FEEDBACK_AGENT_CLAUDE_TOKEN_FILE   CLAUDE_CODE_OAUTH_TOKEN (`claude setup-token`); unset uses claude's own sign-in
//	FEEDBACK_AGENT_TEST_DATABASE_URL   a throwaway PostgreSQL for Go tests that need one; unset, those tests skip
//	FEEDBACK_AGENT_TEST_SLOT           ~/.config/stackurity/test-slot.sh by default when it exists: heavy checks wait for a slot
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type config struct {
	API, TokenFile, Repo, Work string
	SlackFile, ClaudeTokenFile string
	TestDB, TestSlot           string
	Claude, GH, Git            string
	Max                        int
	Item                       string
	DryRun                     bool
	Timeout                    time.Duration
	Base                       string // origin branch, main
	Remote                     string // origin
	GitHubRepo                 string // stackurity/stackurity, for gh
	AdminURL                   string // where the owner opens an item
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func home(p string) string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, p)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	slot := env("FEEDBACK_AGENT_TEST_SLOT", "")
	if slot == "" {
		if _, err := os.Stat(home(".config/stackurity/test-slot.sh")); err == nil {
			slot = home(".config/stackurity/test-slot.sh")
		}
	}
	cfg := config{
		API:             env("STACKURITY_FEEDBACK_API", "https://app.stackurity.dev/api/v1/admin/feedback"),
		TokenFile:       env("STACKURITY_FEEDBACK_TOKEN_FILE", home(".config/stackurity/feedback-agent-token")),
		Repo:            env("FEEDBACK_AGENT_REPO", home("code/stackurity-feedback")),
		Work:            env("FEEDBACK_AGENT_WORK", home("code/feedback-agent-runs")),
		SlackFile:       env("FEEDBACK_AGENT_SLACK_WEBHOOK_FILE", ""),
		ClaudeTokenFile: env("FEEDBACK_AGENT_CLAUDE_TOKEN_FILE", ""),
		TestDB:          env("FEEDBACK_AGENT_TEST_DATABASE_URL", ""),
		TestSlot:        slot,
		Base:            "main",
		Remote:          "origin",
		GitHubRepo:      "stackurity/stackurity",
		AdminURL:        "https://app.stackurity.dev/admin/feedback?item=",
		Timeout:         45 * time.Minute,
	}
	flag.StringVar(&cfg.Item, "item", "", "work on this item only (FB-123), whatever its status")
	flag.IntVar(&cfg.Max, "max", 3, "items per run")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "run claude and the checks, but write nothing to the queue and push nothing")
	flag.StringVar(&cfg.Claude, "claude", "claude", "the claude command")
	flag.StringVar(&cfg.GH, "gh", "gh", "the gh command")
	flag.StringVar(&cfg.Git, "git", "git", "the git command")
	flag.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "how long one claude run may take")
	flag.Parse()
	if err := run(context.Background(), cfg); err != nil {
		log.Fatalf("feedback-agent: %v", err)
	}
}

// errLocked: another run is still going.
var errLocked = errors.New("another run is still going")

// lock takes the run lock; the OS releases it if the process dies.
func lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errLocked
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// readSecret reads a token file that only its owner may read.
func readSecret(path, what string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s %s must be mode 0600 (chmod 600 %s)", what, path, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s %s is empty", what, path)
	}
	return v, nil
}

func run(ctx context.Context, cfg config) error {
	unlock, err := lock(cfg.Work)
	if errors.Is(err, errLocked) {
		log.Print("another run is still going; nothing to do")
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock()
	token, err := readSecret(cfg.TokenFile, "triage token")
	if err != nil {
		return err
	}
	a := &agent{cfg: cfg, q: &queue{base: strings.TrimRight(cfg.API, "/"), token: token}}
	if cfg.SlackFile != "" {
		if _, serr := os.Stat(cfg.SlackFile); errors.Is(serr, os.ErrNotExist) {
			log.Printf("no Slack webhook at %s; outcomes are only logged", cfg.SlackFile)
		} else if a.slack, err = readSecret(cfg.SlackFile, "Slack webhook"); err != nil {
			return err
		}
	}
	if cfg.ClaudeTokenFile != "" {
		if a.claudeToken, err = readSecret(cfg.ClaudeTokenFile, "Claude token"); err != nil {
			return err
		}
	}
	a.pruneRuns(30 * 24 * time.Hour)
	return a.runOnce(ctx)
}
