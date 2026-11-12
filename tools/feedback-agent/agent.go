package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

type agent struct {
	cfg         config
	q           *queue
	slack       string
	claudeToken string
}

// result is what claude writes to result.json.
type result struct {
	Decision      string `json:"decision"`
	Title         string `json:"title"`
	Summary       string `json:"summary"`
	SenderMessage string `json:"sender_message"`
	Questions     string `json:"questions"`
	Reason        string `json:"reason"`
	Tests         string `json:"tests"`
}

// maxAttempts: an item that fails this often goes to the owner.
const maxAttempts = 2

// state remembers failed attempts per item and round (a new round starts
// when the sender answers or the owner approves).
type state struct {
	Attempts map[string]int `json:"attempts"`
}

func (a *agent) statePath() string { return filepath.Join(a.cfg.Work, "state.json") }

func (a *agent) loadState() *state {
	st := &state{Attempts: map[string]int{}}
	if b, err := os.ReadFile(a.statePath()); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.Attempts == nil {
		st.Attempts = map[string]int{}
	}
	return st
}

func (a *agent) saveState(st *state) {
	b, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(a.statePath(), b, 0o600)
}

// roundKey changes when the sender answers (a new comment) or the owner
// approves.
func roundKey(it item) string {
	k := fmt.Sprintf("%s|%d", it.Ref, it.Comments)
	if it.ApprovedAt != nil {
		k += "|" + it.ApprovedAt.UTC().Format(time.RFC3339)
	}
	return k
}

// pick chooses this run's items: approved first, then new, oldest first.
func pick(items []item, max int) []item {
	var out []item
	for _, it := range items {
		if it.Status == "new" || it.approved() {
			out = append(out, it)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].approved() != out[j].approved() {
			return out[i].approved()
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func (a *agent) runOnce(ctx context.Context) error {
	var todo []item
	if a.cfg.Item != "" {
		d, err := a.q.get(ctx, a.cfg.Item)
		if err != nil {
			return err
		}
		todo = []item{d.Item}
	} else {
		items, err := a.q.list(ctx)
		if err != nil {
			return err
		}
		todo = pick(items, a.cfg.Max)
	}
	log.Printf("%d item(s) to work on", len(todo))
	st := a.loadState()
	for _, it := range todo {
		key := roundKey(it)
		if err := a.process(ctx, it); err != nil {
			st.Attempts[key]++
			a.saveState(st)
			log.Printf("%s: %v (attempt %d)", it.Ref, err, st.Attempts[key])
			if st.Attempts[key] >= maxAttempts {
				if err := a.toOwner(ctx, it.Ref, fmt.Sprintf("The feedback agent failed %d times: %s", maxAttempts, oneLine(err.Error(), 300)), ""); err != nil {
					log.Printf("%s: could not hand it to the owner: %v", it.Ref, err)
				}
			}
			continue
		}
		delete(st.Attempts, key)
		a.saveState(st)
	}
	return nil
}

// process works on one item from start to finish.
func (a *agent) process(ctx context.Context, it item) error {
	d, err := a.q.get(ctx, it.Ref)
	if err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102-150405.000")
	runDir := filepath.Join(a.cfg.Work, "runs", it.Ref+"-"+strings.Replace(stamp, ".", "-", 1))
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	log.Printf("%s (%s): working in %s", it.Ref, it.Status, runDir)
	files := a.attachments(ctx, d, runDir)
	branch := "feedback/" + strings.ToLower(it.Ref) + "-" + strings.Replace(stamp, ".", "-", 1)
	wt := filepath.Join(a.cfg.Work, "worktrees", filepath.Base(runDir))
	if err := a.git(ctx, a.cfg.Repo, "fetch", "-q", a.cfg.Remote, a.cfg.Base); err != nil {
		return err
	}
	if err := a.git(ctx, a.cfg.Repo, "worktree", "add", "-q", "-b", branch, wt, a.cfg.Remote+"/"+a.cfg.Base); err != nil {
		return err
	}
	defer func() {
		_ = a.git(context.Background(), a.cfg.Repo, "worktree", "remove", "--force", wt)
		_ = a.git(context.Background(), a.cfg.Repo, "branch", "-D", branch)
	}()
	text := prompt(d, runDir, files)
	if err := os.WriteFile(filepath.Join(runDir, "prompt.txt"), []byte(text), 0o600); err != nil {
		return err
	}
	if err := a.runClaude(ctx, wt, runDir, text); err != nil {
		return err
	}
	var r result
	raw, err := os.ReadFile(filepath.Join(runDir, "result.json"))
	if err != nil {
		return fmt.Errorf("claude did not write result.json")
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("result.json: %w", err)
	}
	changed, err := a.changedPaths(ctx, wt)
	if err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(runDir, "changes.txt"), []byte(strings.Join(changed, "\n")), 0o600)
	if len(changed) > 0 {
		if patch, err := a.output(ctx, wt, a.cfg.Git, "diff", "HEAD"); err == nil {
			_ = os.WriteFile(filepath.Join(runDir, "changes.patch"), patch, 0o600)
		}
	}
	return a.outcome(ctx, d.Item, r, wt, branch, changed, runDir)
}

// outcome acts on claude's decision and the paths it changed.
func (a *agent) outcome(ctx context.Context, it item, r result, wt, branch string, changed []string, runDir string) error {
	switch r.Decision {
	case "needs_more_info":
		q := clip(r.Questions, 3000)
		if q == "" {
			q = clip(r.Summary, 3000)
		}
		if q == "" {
			return errors.New("needs_more_info without questions")
		}
		if err := a.write(ctx, func() error { return a.q.comment(ctx, it.Ref, q, true) }); err != nil {
			return err
		}
		a.post(fmt.Sprintf(":speech_balloon: %s: the feedback agent asked the sender for details.", it.Ref), it.Ref)
		return nil
	case "needs_approval":
		reason := clip(r.Reason, 1800)
		if reason == "" {
			reason = "The agent wants your decision."
		}
		return a.toOwner(ctx, it.Ref, reason, r.Summary)
	case "cannot":
		why := clip(r.Summary, 1500)
		if why == "" {
			why = "no reason given"
		}
		return a.toOwner(ctx, it.Ref, "Won't-fix candidate: the agent could not do this: "+why+
			" Decline it with a reason the sender will read, or approve it to try again.", "")
	case "done":
	default:
		return fmt.Errorf("result.json has no valid decision (%q)", oneLine(r.Decision, 40))
	}

	if len(changed) == 0 {
		return a.toOwner(ctx, it.Ref, "The agent finished without changing anything: "+clip(r.Summary, 1500), "")
	}
	outside, sensitive, secret := classify(changed)
	if len(secret) > 0 {
		return a.toOwner(ctx, it.Ref, "The agent's change touched files that look like secrets ("+strings.Join(secret, ", ")+"); nothing was committed.", r.Summary)
	}
	if len(outside) > 0 {
		return a.toOwner(ctx, it.Ref, "It needs changes outside web/, internal/, docs/ and changelog.d/ ("+strings.Join(outside, ", ")+
			"). The proposed diff is in the run folder "+filepath.Base(runDir)+".", r.Summary)
	}
	if len(sensitive) > 0 && !it.approved() {
		return a.toOwner(ctx, it.Ref, "It changes files that need your approval ("+strings.Join(sensitive, ", ")+
			"): billing, sign-in and roles, customer emails or wording, legal text, data deletion or migrations, AI prompts or dependencies. "+
			clip(r.Summary, 800), "")
	}
	if problem := a.check(ctx, wt, changed); problem != "" {
		_ = os.WriteFile(filepath.Join(runDir, "checks.txt"), []byte(problem), 0o600)
		return fmt.Errorf("the change failed the checks: %s", oneLine(problem, 400))
	}
	if a.cfg.DryRun {
		log.Printf("%s: done (dry run): %s; %s", it.Ref, oneLine(r.Title, 70), strings.Join(changed, ", "))
		return nil
	}
	pr, err := a.publish(ctx, it, r, wt, branch, changed)
	if err != nil {
		return err
	}
	if err := a.q.patch(ctx, it.Ref, map[string]any{"status": "in_progress", "link": pr,
		"note": "Feedback agent: pull request opened (" + oneLine(r.Title, 70) + "). Checks passed on the Mac. Merging and release are the release owner's job."}); err != nil {
		return err
	}
	if msg := clip(r.SenderMessage, 1500); msg != "" {
		if err := a.q.comment(ctx, it.Ref, msg+"\n\nIt will reach you with a coming release; we will let you know.", false); err != nil {
			log.Printf("%s: sender comment not added: %v", it.Ref, err)
		}
	}
	a.post(fmt.Sprintf(":white_check_mark: %s: the feedback agent opened %s (%s). Not merged.", it.Ref, pr, oneLine(r.Title, 70)), it.Ref)
	return nil
}

// toOwner holds an item for the owner's decision.
func (a *agent) toOwner(ctx context.Context, ref, reason, note string) error {
	p := map[string]any{"status": "needs_owner", "owner_reason": clip(reason, 2000)}
	if n := clip(note, 4000); n != "" {
		p["note"] = "Feedback agent: " + n
	}
	if err := a.write(ctx, func() error { return a.q.patch(ctx, ref, p) }); err != nil {
		return err
	}
	a.post(fmt.Sprintf(":raised_hand: %s needs approval: %s", ref, oneLine(reason, 300)), ref)
	return nil
}

// write runs a change to the queue, unless this is a dry run.
func (a *agent) write(ctx context.Context, f func() error) error {
	if a.cfg.DryRun {
		log.Print("dry run: not writing to the queue")
		return nil
	}
	return f()
}

// publish commits, pushes and opens the pull request; it returns its URL.
func (a *agent) publish(ctx context.Context, it item, r result, wt, branch string, changed []string) (string, error) {
	title := oneLine(r.Title, 70)
	if title == "" {
		title = "Fix from feedback"
	}
	msg := fmt.Sprintf("%s (%s)\n\n%s\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n", title, it.Ref, clip(r.Summary, 3000))
	if err := a.git(ctx, wt, append([]string{"add", "-A", "--"}, changed...)...); err != nil {
		return "", err
	}
	if err := a.git(ctx, wt, "commit", "-q", "-m", msg); err != nil {
		return "", err
	}
	if err := a.git(ctx, wt, "push", "-q", "-u", a.cfg.Remote, branch); err != nil {
		return "", err
	}
	approval := ""
	if it.approved() {
		approval = fmt.Sprintf("\n\nThe owner approved this item (%s).", it.ApprovedAt.UTC().Format("2 Jan 2006"))
	}
	body := fmt.Sprintf(`Built by the feedback agent (tools/feedback-agent) for feedback %s. The item's text stays in the queue: open it under Admin, Feedback.%s

## What changed

%s

## Files

%s

## Checks run on the Mac

%s

Not merged by the agent: release freeze rules apply; the release owner merges, and moves %s to fixed when it is merged.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
`, it.Ref, approval, clip(r.Summary, 4000), "- "+strings.Join(changed, "\n- "), clip(r.Tests, 2000)+"\n\nRunner: gofmt, go build, go vet and go test of the changed packages; web typecheck, lint and tests when web/ changed.", it.Ref)
	out, err := a.output(ctx, wt, a.cfg.GH, "pr", "create", "--repo", a.cfg.GitHubRepo, "--base", a.cfg.Base, "--head", branch,
		"--title", title+" ("+it.Ref+")", "--body", body)
	if err != nil {
		return "", err
	}
	url := prURL.FindString(string(out))
	if url == "" {
		return "", fmt.Errorf("gh pr create gave no pull request URL: %s", oneLine(string(out), 200))
	}
	return url, nil
}

var prURL = regexp.MustCompile(`https://github\.com/stackurity/[A-Za-z0-9._-]+/pull/[0-9]+`)

// changedPaths lists what the worktree changed, untracked files included.
func (a *agent) changedPaths(ctx context.Context, wt string) ([]string, error) {
	out, err := a.output(ctx, wt, a.cfg.Git, "status", "--porcelain=v1", "-uall", "-z")
	if err != nil {
		return nil, err
	}
	var paths []string
	parts := strings.Split(string(out), "\x00")
	for i := 0; i < len(parts); i++ {
		e := parts[i]
		if len(e) < 4 {
			continue
		}
		paths = append(paths, e[3:])
		if e[0] == 'R' || e[0] == 'C' { // the original path follows
			i++
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// check runs the checks a pull request needs before it is opened. It
// returns what failed, or "".
func (a *agent) check(ctx context.Context, wt string, changed []string) string {
	var goFiles, pkgs []string
	seen := map[string]bool{}
	web := false
	for _, p := range changed {
		if strings.HasPrefix(p, "web/") {
			web = true
		}
		if strings.HasSuffix(p, ".go") {
			if _, err := os.Stat(filepath.Join(wt, p)); err == nil {
				goFiles = append(goFiles, p)
			}
			if d := "./" + filepath.Dir(p); !seen[d] {
				if _, err := os.Stat(filepath.Join(wt, filepath.Dir(p))); err == nil {
					seen[d] = true
					pkgs = append(pkgs, d)
				}
			}
		}
	}
	if len(goFiles) > 0 {
		out, err := a.output(ctx, wt, "gofmt", append([]string{"-l"}, goFiles...)...)
		if err != nil || len(bytes.TrimSpace(out)) > 0 {
			return "gofmt: " + string(out)
		}
		for _, args := range [][]string{{"build", "./..."}, append([]string{"vet"}, pkgs...)} {
			if out, err := a.output(ctx, wt, "go", args...); err != nil {
				return "go " + args[0] + ": " + tail(out)
			}
		}
		if out, err := a.slot(ctx, wt, "feedback-agent go test", append([]string{"go", "test", "-count=1", "-timeout", "40m"}, pkgs...)...); err != nil {
			return "go test: " + tail(out)
		}
	}
	if web {
		for _, c := range [][]string{{"npm", "ci", "--no-audit", "--no-fund"}, {"npm", "run", "typecheck"}, {"npm", "run", "lint"}, {"npm", "test"}} {
			out, err := a.output(ctx, filepath.Join(wt, "web"), c[0], c[1:]...)
			if err != nil {
				return strings.Join(c, " ") + ": " + tail(out)
			}
		}
	}
	return ""
}

func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 1500 {
		s = "…" + s[len(s)-1500:]
	}
	return s
}

// slot runs a heavy command through the Mac's shared test queue when it
// is configured, so parallel sessions don't overload the machine.
func (a *agent) slot(ctx context.Context, dir, label string, cmd ...string) ([]byte, error) {
	if a.cfg.TestSlot != "" {
		cmd = append([]string{a.cfg.TestSlot, "run", label, "--"}, cmd...)
	}
	return a.output(ctx, dir, cmd[0], cmd[1:]...)
}

// baseEnv is the environment of everything the agent starts: no queue or
// Slack secrets, ever.
func (a *agent) baseEnv() []string {
	keep := []string{"PATH", "HOME", "USER", "LANG", "TMPDIR", "GOPATH", "GOCACHE", "GOMODCACHE", "SSH_AUTH_SOCK"}
	var env []string
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if a.cfg.TestDB != "" {
		env = append(env, "STACKURITY_TEST_DATABASE_URL="+a.cfg.TestDB)
	}
	return env
}

func (a *agent) output(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Env = a.baseEnv()
	return c.CombinedOutput()
}

func (a *agent) git(ctx context.Context, dir string, args ...string) error {
	out, err := a.output(ctx, dir, a.cfg.Git, args...)
	if err != nil {
		return fmt.Errorf("git %s: %v: %s", args[0], err, oneLine(string(out), 300))
	}
	return nil
}

// runClaude runs claude -p in the worktree with the run's permissions,
// and stops it after the timeout.
func (a *agent) runClaude(ctx context.Context, wt, runDir, text string) error {
	settings := map[string]any{"permissions": map[string]any{
		"allow": []string{"Read", "Edit", "Write", "Glob", "Grep",
			"Bash(go build:*)", "Bash(go vet:*)", "Bash(go test:*)", "Bash(gofmt:*)", "Bash(go run ./tools/changelog:*)",
			"Bash(npm ci:*)", "Bash(npm run:*)", "Bash(npm test:*)",
			"Bash(git diff:*)", "Bash(git status:*)", "Bash(git log:*)", "Bash(git show:*)", "Bash(ls:*)", "Bash(wc:*)"},
		"deny": []string{"WebFetch", "WebSearch",
			"Bash(git push:*)", "Bash(git commit:*)", "Bash(gh:*)", "Bash(curl:*)", "Bash(wget:*)", "Bash(ssh:*)", "Bash(scp:*)",
			"Read(~/.config/**)", "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(**/.env*)", "Read(**/*token*)", "Read(**/*secret*)",
			"Read(**/*.pem)", "Read(**/*.key)", "Edit(**/.env*)"},
	}}
	sb, _ := json.Marshal(settings)
	sp := filepath.Join(runDir, "settings.json")
	if err := os.WriteFile(sp, sb, 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	c := exec.CommandContext(ctx, a.cfg.Claude, "-p", "--output-format", "json", "--permission-mode", "acceptEdits",
		"--settings", sp, "--add-dir", runDir)
	c.Dir = wt
	c.Env = append(a.baseEnv(), "DISABLE_AUTOUPDATER=1")
	if a.claudeToken != "" {
		c.Env = append(c.Env, "CLAUDE_CODE_OAUTH_TOKEN="+a.claudeToken)
	}
	c.Stdin = strings.NewReader(text)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGTERM) }
	c.WaitDelay = 30 * time.Second
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	_ = os.WriteFile(filepath.Join(runDir, "claude-output.json"), out.Bytes(), 0o600)
	if errb.Len() > 0 {
		_ = os.WriteFile(filepath.Join(runDir, "claude-stderr.txt"), errb.Bytes(), 0o600)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("claude did not finish within %s", a.cfg.Timeout)
	}
	if err != nil {
		return fmt.Errorf("claude: %v: %s", err, oneLine(errb.String(), 300))
	}
	return nil
}

// attachments saves the item's files in the run folder, with up to six
// frames of each video.
func (a *agent) attachments(ctx context.Context, d *detail, runDir string) []file {
	var files []file
	dir := filepath.Join(runDir, "attachments")
	for _, at := range d.Attachments {
		if at.PurgedAt != nil {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			break
		}
		ext := map[string]string{"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp",
			"video/mp4": "mp4", "video/webm": "webm", "application/pdf": "pdf"}[at.ContentType]
		if ext == "" {
			continue
		}
		p := filepath.Join(dir, fmt.Sprintf("%d.%s", at.ID, ext))
		if err := a.q.download(ctx, d.Item.Ref, at.ID, p, 60<<20); err != nil {
			log.Printf("%s: attachment %d not downloaded: %v", d.Item.Ref, at.ID, err)
			continue
		}
		f := file{Name: oneLine(at.Name, 100), Type: at.ContentType, Path: p}
		if strings.HasPrefix(at.ContentType, "video/") {
			f.Frames = a.frames(ctx, p, filepath.Join(dir, fmt.Sprintf("%d-frames", at.ID)))
		}
		files = append(files, f)
	}
	return files
}

func (a *agent) frames(ctx context.Context, video, outDir string) []string {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return nil
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := a.output(ctx, outDir, "ffmpeg", "-v", "error", "-y", "-i", video, "-vf", "fps=1/3,scale='min(1280,iw)':-2",
		"-frames:v", "6", filepath.Join(outDir, "frame-%02d.jpg")); err != nil {
		return nil
	}
	m, _ := filepath.Glob(filepath.Join(outDir, "frame-*.jpg"))
	return m
}

// post sends one line to Slack, never the feedback's text or the sender's
// address.
func (a *agent) post(text, ref string) {
	log.Print(text)
	if a.slack == "" || a.cfg.DryRun {
		return
	}
	b, _ := json.Marshal(map[string]string{"text": text + " <" + a.cfg.AdminURL + ref + "|Open " + ref + ">"})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", a.slack, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	} else {
		log.Printf("slack: %v", err)
	}
}

// pruneRuns deletes run folders older than keep.
func (a *agent) pruneRuns(keep time.Duration) {
	dir := filepath.Join(a.cfg.Work, "runs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > keep {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}
