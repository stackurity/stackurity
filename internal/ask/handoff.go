package ask

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/mcp"
	"github.com/stackurity/stackurity/internal/store"
)

// Hand-offs ("tier 2", owner decision 2026-11-12). When the person asks Ask
// to connect something (GitHub, Jira, a Slack channel, a new server), the
// connection needs them on the other service's consent page, or a secret,
// so Ask never makes it. The model calls propose_connect, which stores a
// proposal with tool "connect" (the same store, event and card as the
// propose tools, propose.go). The card under the answer then:
//
//   - for an OAuth connect or an app install (HowStart), has one button
//     that starts the same flow as the Integrations page, with the same
//     request and redirect (web/src/integrationStart.ts);
//   - for a flow that needs a secret typed in (HowPage), links to the exact
//     setup page, with non-secret fields only in the address;
//   - for a server (HowApply), says what will be created; the person's
//     Apply creates the install code as them (the API's ask_proposals.go)
//     and the card shows the install command built from it, copy-only. The
//     code exists only in that response: the model never sees it, and it
//     is not stored with the proposal.
//
// The model gets a short description only. It never handles secrets: the
// tool takes no field that could carry one and refuses text shaped like
// one, and secrets pasted into a question are removed before the model
// sees it (RedactUserText). Disconnecting, deleting, tokens, SSO, users,
// roles and billing are never offered: they are not kinds.

// ConnectTool is the hand-off tool's name, as the model sees it.
const ConnectTool = "propose_connect"

// ConnectProposal is the tool name a hand-off is stored with.
const ConnectProposal = "connect"

// How a hand-off is finished.
const (
	// HowStart: a button starts the service's own consent or install flow.
	HowStart = "start"
	// HowPage: a link to the setup page, where the person enters what is
	// secret themselves.
	HowPage = "page"
	// HowApply: Apply creates it as the person (a write, like a proposal).
	HowApply = "apply"
)

// ConnectKind is one thing Ask can hand off.
type ConnectKind struct {
	Kind    string
	Service string
	How     string
	// Summary is what the card and the model are told, one sentence.
	Summary string
	// Fields are the optional non-secret fields this kind takes.
	Fields []string
}

// connectKinds are what exists in the codebase to connect, in this order.
// Slack, Jira and PagerDuty start their app's flow when the server has the
// app set up, and otherwise link to their page (the card decides, as the
// Integrations page does). Keep in step with migration 0106's CHECK and
// web/src/askHandoff.ts.
var connectKinds = []ConnectKind{
	{Kind: "github", Service: "GitHub", How: HowStart, Summary: "Install the Stackurity app on GitHub and pick the repositories to scan. GitHub asks you to approve it."},
	{Kind: "gitlab", Service: "GitLab", How: HowStart, Summary: "Connect a GitLab group. GitLab asks you to allow Stackurity, then you pick the group."},
	{Kind: "jira", Service: "Jira", How: HowStart, Summary: "Connect Jira. Atlassian asks you to allow Stackurity, then you pick the Jira project.", Fields: []string{"name"}},
	{Kind: "pagerduty", Service: "PagerDuty", How: HowStart, Summary: "Connect PagerDuty. PagerDuty asks you to allow Stackurity, then you pick the service.", Fields: []string{"name"}},
	{Kind: "slack", Service: "Slack", How: HowStart, Summary: "Add Stackurity to Slack. Slack asks you to pick a channel, then you choose what to send.", Fields: []string{"name"}},
	{Kind: "teams", Service: "Microsoft Teams", How: HowPage, Summary: "Add Microsoft Teams on its setup page.", Fields: []string{"name"}},
	{Kind: "email", Service: "Email", How: HowPage, Summary: "Add email alerts on the setup page.", Fields: []string{"name"}},
	{Kind: "webhook", Service: "Webhook", How: HowPage, Summary: "Add a webhook on its setup page. You enter the address there, not in Ask.", Fields: []string{"name"}},
	{Kind: "server", Service: "Server agent", How: HowApply, Summary: "Create an install command for one new server.", Fields: []string{"name", "environment", "project_id"}},
	{Kind: "digitalocean", Service: "DigitalOcean", How: HowPage, Summary: "Connect DigitalOcean on its setup page. You paste the API token there, never in Ask."},
}

// ConnectKinds lists the kinds, in their fixed order.
func ConnectKinds() []ConnectKind { return append([]ConnectKind(nil), connectKinds...) }

// ConnectKindOf returns kind's definition.
func ConnectKindOf(kind string) (ConnectKind, bool) {
	for _, k := range connectKinds {
		if k.Kind == kind {
			return k, true
		}
	}
	return ConnectKind{}, false
}

func connectKindNames() []any {
	out := make([]any, 0, len(connectKinds))
	for _, k := range connectKinds {
		out = append(out, k.Kind)
	}
	return out
}

const connectDescription = "Hands a connection over to the person: shows them a card with one button that starts connecting it, " +
	"or a link to its setup page. Calling this connects nothing and changes nothing. Use it only when the person asked, in their own words, " +
	"to connect, add or set up one of these: github (the GitHub app), gitlab (a GitLab group), jira, pagerduty, slack, teams (Microsoft Teams), " +
	"email or webhook (alerts), server (a new server: install the agent) or digitalocean. Never ask for, accept or repeat a token, password, " +
	"key or webhook address: the person enters those on the page. Fields other than kind are optional and never secret."

// connectSchema is the tool's input schema.
func connectSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"kind": map[string]any{"type": "string", "enum": connectKindNames(), "description": "What to connect."},
			"name": map[string]any{"type": "string", "maxLength": maxConnectName,
				"description": "Optional. A plain name: the alert channel's name, or the new server's label. Never a token, key, password or web address."},
			"environment": map[string]any{"type": "string", "maxLength": 40, "description": "Optional, server only: its environment, such as production."},
			"project_id":  map[string]any{"type": "integer", "minimum": 1, "description": "Optional, server only: the project the new server joins."},
		},
		"required": []string{"kind"},
	}
}

const maxConnectName = 80

var envRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,40}$`)

// Connect is a hand-off's checked input.
type Connect struct {
	Kind        string `json:"kind"`
	Name        string `json:"name,omitempty"`
	Environment string `json:"environment,omitempty"`
	ProjectID   int64  `json:"project_id,omitempty"`
}

// ParseConnect checks the model's input: a known kind, only the fields
// that kind takes, and no text that could be a secret or an address.
func ParseConnect(raw json.RawMessage) (Connect, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil || in == nil {
		return Connect{}, fmt.Errorf("the input must be a JSON object with kind")
	}
	var c Connect
	if err := json.Unmarshal(in["kind"], &c.Kind); err != nil || c.Kind == "" {
		return Connect{}, fmt.Errorf("kind is required")
	}
	k, ok := ConnectKindOf(c.Kind)
	if !ok {
		return Connect{}, fmt.Errorf("kind %q is not something Ask can hand off; use one of %s", c.Kind, kindList())
	}
	allowed := map[string]bool{"kind": true}
	for _, f := range k.Fields {
		allowed[f] = true
	}
	for f := range in {
		if !allowed[f] {
			return Connect{}, fmt.Errorf("%s does not take %s", c.Kind, f)
		}
	}
	text := func(field string, max int) (string, error) {
		raw, ok := in[field]
		if !ok {
			return "", nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("%s must be text", field)
		}
		s = strings.TrimSpace(CleanText(s))
		switch {
		case utf8.RuneCountInString(s) > max:
			return "", fmt.Errorf("%s is longer than %d characters", field, max)
		case strings.ContainsFunc(s, unicode.IsControl):
			return "", fmt.Errorf("%s has control characters", field)
		case LooksLikeSecret(s) || strings.Contains(s, "://") || strings.Contains(strings.ToLower(s), "www."):
			return "", fmt.Errorf("%s must be a plain name, never a token, password, key or web address; leave it out", field)
		}
		return s, nil
	}
	var err error
	if c.Name, err = text("name", maxConnectName); err != nil {
		return Connect{}, err
	}
	if c.Environment, err = text("environment", 40); err != nil {
		return Connect{}, err
	}
	if c.Environment != "" && !envRE.MatchString(c.Environment) {
		return Connect{}, fmt.Errorf("environment may have letters, digits, dot, dash and underscore only")
	}
	if raw, ok := in["project_id"]; ok {
		if err := json.Unmarshal(raw, &c.ProjectID); err != nil || c.ProjectID <= 0 {
			return Connect{}, fmt.Errorf("project_id must be a project's id")
		}
	}
	return c, nil
}

func kindList() string {
	var names []string
	for _, k := range connectKinds {
		names = append(names, k.Kind)
	}
	return strings.Join(names, ", ")
}

// code is the hand-off's check value: the store requires one, and Apply
// of a server compares it with the arguments it creates the code from.
func (c Connect) code() string {
	b, _ := json.Marshal(c)
	h := sha256.Sum256(append([]byte("ask-connect|"), b...))
	return hex.EncodeToString(h[:6])
}

// CheckCode reports whether code is the one stored for c.
func (c Connect) CheckCode(code string) bool { return code != "" && c.code() == code }

// runConnect stores a hand-off for one answer. The person must be an
// organisation admin, as every connect flow requires; otherwise nothing is
// stored and the model is told who can.
func (p *proposer) runConnect(ctx context.Context, api mcp.API, u ToolUse, emit func(Event)) map[string]any {
	c, err := ParseConnect(u.Input)
	if err != nil {
		return toolResult(u.ID, "Not handed off: "+err.Error()+".", true)
	}
	k, _ := ConnectKindOf(c.Kind)
	var me struct {
		Role string `json:"role"`
	}
	if err := api.Do(ctx, "GET", "/api/v1/auth/me", nil, nil, &me); err != nil {
		return toolResult(u.ID, ErrorText(err), true)
	}
	if me.Role != "admin" {
		return toolResult(u.ID, fmt.Sprintf("Not handed off: only an organisation admin can connect %s. Tell the person to ask an admin.", k.Service), true)
	}
	summary := k.Summary
	details := map[string]any{"kind": c.Kind, "service": k.Service, "how": k.How}
	var notes []string
	if c.Kind == "server" {
		var parts []string
		if c.Name != "" {
			parts = append(parts, fmt.Sprintf("label %q", c.Name))
		}
		if c.Environment != "" {
			parts = append(parts, fmt.Sprintf("environment %q", c.Environment))
		}
		if c.ProjectID > 0 {
			var pr struct {
				Project struct {
					Name string `json:"name"`
				} `json:"project"`
			}
			if err := api.Do(ctx, "GET", fmt.Sprintf("/api/v1/projects/%d", c.ProjectID), nil, nil, &pr); err != nil {
				return toolResult(u.ID, ErrorText(err), true)
			}
			name := pr.Project.Name
			parts = append(parts, fmt.Sprintf("project %q", name))
			details["project_id"], details["project"] = c.ProjectID, name
		}
		if len(parts) > 0 {
			summary = strings.TrimSuffix(summary, ".") + " (" + strings.Join(parts, ", ") + ")."
		}
		notes = append(notes, "The install code in the command works for one server, for 24 hours. It is shown once, on this card.")
	}
	if c.Name != "" && c.Kind != "server" {
		details["name"] = c.Name
	}
	pr, err := p.e.Store.CreateAskProposal(context.WithoutCancel(ctx), p.q.UserID, p.q.Conversation.ID, store.NewAskProposal{
		QuestionSeq: p.seq, Tool: ConnectProposal, Args: c, Summary: summary, Details: details, Notes: notes, Code: c.code(),
		Unrequested: !AskedForChange(p.q.Text)})
	if err != nil {
		p.e.log().Error("assistant: storing a hand-off", "err", err)
		return toolResult(u.ID, "The connection could not be handed off. Tell the person to start it under Integrations instead.", true)
	}
	p.done = true
	emit(Event{Kind: "proposal", Proposal: pr})
	next := fmt.Sprintf("The person now sees a card under your answer with a button that opens %s's own page, where they approve it. "+
		"Nothing is connected until they finish there. Say that in one short sentence.", k.Service)
	switch k.How {
	case HowPage:
		next = "The person now sees a card under your answer with a link to the setup page, where they enter what is needed themselves. " +
			"Say that in one short sentence."
	case HowApply:
		next = "The person now sees a card under your answer with Apply. Apply creates an install code as them and shows the install command on the card. " +
			"You never see the code or the command: never write an install command yourself. Say in one short sentence that the card has it."
	}
	out := map[string]any{"status": "handed_off", "connected": "nothing", "kind": c.Kind, "card": summary,
		"next": next + " Never ask for, accept or repeat a token, password, key or webhook address."}
	return toolResult(u.ID, ToolResultText(u.Name, out), false)
}
