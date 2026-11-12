package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/stackurity/stackurity/internal/client"
)

// The account tools answer questions about the person's own account and
// organisation: the plan and its limits against use, their role, how many
// members have each role, Ask Stackurity's questions left, which
// integrations and notification channels are connected and the notification
// rules in effect. Like every tool they call the API as the person, so each
// part needs the role its endpoint needs; a part the person may not read is
// listed under not_available with the reason instead of being shown as
// empty.
//
// They never return what could be used to send or sign in: channel and
// integration configuration (webhook URLs, addresses, tokens, SMTP
// settings) and secret references are not read into the output at all, and
// error text that may quote a URL has its addresses removed. Members are
// counted by role, never named.

// unavailable is a part of an answer the person cannot read, and why.
type unavailable struct {
	Section string `json:"section"`
	Reason  string `json:"reason"`
}

// parts runs a tool's API calls. A refusal (or any error) is recorded
// for the answer instead of failing the whole tool, so a viewer still gets
// what they may read.
type parts struct{ missing []unavailable }

func (p *parts) get(ctx context.Context, api API, section, path string, out any) bool {
	if err := api.Do(ctx, "GET", path, nil, nil, out); err != nil {
		p.missing = append(p.missing, unavailable{section, refusal(err)})
		return false
	}
	return true
}

// refusal says why a part could not be read, without anything the error
// may quote.
func refusal(err error) string {
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case 401, 403:
			msg := "your role or this connection may not read it"
			if ae.Message != "" {
				msg += " (" + withoutURLs(ae.Message) + ")"
			}
			return msg
		case 404:
			return "not set up on this server"
		case 402:
			return "not included in this organisation's plan"
		}
		return withoutURLs(ae.Error())
	}
	return withoutURLs(err.Error())
}

// urlRE matches a web address. Webhook URLs (Slack, Teams, generic) carry
// their secret in the path, so any address in text from a channel or an
// integration is removed, not just its user:password.
var urlRE = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>]+`)

func withoutURLs(s string) string { return urlRE.ReplaceAllString(s, "(address removed)") }

func init() {
	tools["account_overview"] = tool{
		description: "The person's own account and organisation, read-only: their role (role; access organisation or projects; " +
			"project_role) and how many projects they see; the organisation's name, whether it is read-only and why, and report_mode " +
			"(trial reports are shortened); the edition and its features, and on a self-hosted server the licence key state; the plan " +
			"(plan.name, next_plan, members used and limit, allowed notification channel kinds, history_days, SBOM imports this month, " +
			"API requests per hour); monitored assets against the limit (assets.monitored, limit null means no limit, at_limit, by_kind, " +
			"stale, refused_recently) and projects against the project limit; members by role (admins only: members.by_role counts, never " +
			"names; organisation-wide roles admin, security, engineer, viewer, and project_access_only for people with project access " +
			"only); and Ask Stackurity's questions used, limit and left this period (in Ask Stackurity only). Billing amounts and payment " +
			"details are not here. not_available lists each part the person's role cannot read, with the reason: say so rather than " +
			"guessing.",
		schema: obj(map[string]any{}),
		run:    accountOverview,
	}
	tools["integrations_status"] = tool{
		description: "Which integrations and notification channels the organisation has connected and whether each is on, read-only. " +
			"channels (security role and above): each notification channel's kind (slack, slack_app, teams, teams_app, email, " +
			"stackurity_email, webhook, jira, pagerduty, servicenow), name, enabled, where it belongs (organisation, or a project or asset id), " +
			"when it last worked and last delivered a message, whether its stored credential is missing, and its last error. " +
			"sources (engineer and above): scanning integrations (repositories, images, registries, cloud accounts) with kind, name, " +
			"enabled, schedule and last run. github, gitlab, jira and digitalocean: app installations and connections and their status. " +
			"Never returns webhook URLs, addresses, tokens, passwords or other configuration. not_available lists what the person's role " +
			"cannot read.",
		schema: obj(map[string]any{}),
		run:    integrationsStatus,
	}
	tools["notification_settings"] = tool{
		description: "The notification rules in effect, read-only (security role and above): for each rule its name, enabled, the " +
			"channel it sends to (name, kind, on or off), where it belongs (organisation, project or asset), what it sends (events: urgent, " +
			"new_issues, regressed, overdue, connected, problems, daily_summary, weekly_summary; mode), the lowest priority it sends " +
			"(min_priority, P1 the most urgent; new_issues_min_priority for new issues), sos_only, the asset kinds, environments, projects " +
			"and teams it is limited to (empty: all), resolved notices, summary time and day, quiet hours, timezone and the hourly cap. " +
			"A rule sends only when it and its channel are both enabled. project_chat_apps says whether project admins may connect their " +
			"own Slack or Teams. Use it for 'are we notified about critical issues' (critical findings are usually P1 or P2).",
		schema: obj(map[string]any{}),
		run:    notificationSettings,
	}
	readTitles["account_overview"] = "Your account and plan"
	readTitles["integrations_status"] = "Integrations status"
	readTitles["notification_settings"] = "Notification rules"
}

func accountOverview(ctx context.Context, api API, _ map[string]any) (any, error) {
	var p parts
	out := map[string]any{}

	var me struct {
		Role        string          `json:"role"`
		Access      string          `json:"access"`
		ProjectRole json.RawMessage `json:"project_role"`
		Edition     string          `json:"edition"`
		Features    []string        `json:"features"`
		Projects    []struct{}      `json:"projects"`
		Workspace   *struct {
			Name       string          `json:"name"`
			ReadOnly   json.RawMessage `json:"read_only"`
			ReportMode string          `json:"report_mode"`
		} `json:"workspace"`
		LicenseKey *struct {
			State     string     `json:"state"`
			GraceEnds *time.Time `json:"grace_ends"`
		} `json:"license_key"`
	}
	if !p.get(ctx, api, "you", "/api/v1/auth/me", &me) {
		// Without the person's own account nothing else is meaningful.
		return nil, errors.New("could not read your account: " + p.missing[0].Reason)
	}
	you := map[string]any{"role": me.Role, "access": me.Access, "projects_you_can_see": len(me.Projects)}
	if me.Role == "" {
		you["role"] = "none (project access only)"
	}
	if len(me.ProjectRole) > 0 && string(me.ProjectRole) != "null" && string(me.ProjectRole) != `""` {
		you["project_role"] = me.ProjectRole
	}
	out["you"] = you
	if me.Workspace != nil {
		org := map[string]any{"name": me.Workspace.Name, "report_mode": me.Workspace.ReportMode, "read_only": nil}
		if len(me.Workspace.ReadOnly) > 0 && string(me.Workspace.ReadOnly) != "null" {
			org["read_only"] = me.Workspace.ReadOnly
		}
		out["organisation"] = org
	}
	if me.Features == nil {
		me.Features = []string{}
	}
	out["edition"] = map[string]any{"name": me.Edition, "features": me.Features}
	if me.LicenseKey != nil {
		out["licence_key"] = me.LicenseKey
	}

	var u struct {
		Monitored       int64            `json:"monitored"`
		Limit           *int64           `json:"limit"`
		AtLimit         bool             `json:"at_limit"`
		ByKind          map[string]int64 `json:"by_kind"`
		Stale           int64            `json:"stale"`
		Workloads       int64            `json:"workloads"`
		RefusedRecently int64            `json:"refused_recently"`
		Projects        int64            `json:"projects"`
		ProjectLimit    *int64           `json:"project_limit"`
		ProjectsAtLimit bool             `json:"projects_at_limit"`
		Plan            *struct {
			Plan                 string          `json:"plan"`
			NextPlan             string          `json:"next_plan"`
			Members              json.RawMessage `json:"members"`
			AllowedChannelKinds  []string        `json:"allowed_channel_kinds"`
			SBOMImports          json.RawMessage `json:"sbom_imports"`
			CheckCooldownSeconds int64           `json:"check_again_cooldown_seconds"`
			APIRequestsPerHour   int64           `json:"api_requests_per_hour"`
			HistoryDays          int64           `json:"history_days"`
			InactivePauseDays    int64           `json:"inactive_pause_days"`
			ReadOnlyProjects     []int64         `json:"read_only_projects"`
		} `json:"plan"`
	}
	if p.get(ctx, api, "usage", "/api/v1/usage", &u) {
		out["assets"] = map[string]any{"monitored": u.Monitored, "limit": u.Limit, "at_limit": u.AtLimit, "by_kind": u.ByKind,
			"stale": u.Stale, "kubernetes_workloads_not_counted": u.Workloads, "refused_recently": u.RefusedRecently}
		out["projects"] = map[string]any{"active": u.Projects, "limit": u.ProjectLimit, "at_limit": u.ProjectsAtLimit}
		if pl := u.Plan; pl != nil {
			plan := map[string]any{"name": pl.Plan, "members": pl.Members, "history_days": pl.HistoryDays,
				"api_requests_per_hour": pl.APIRequestsPerHour, "check_again_cooldown_seconds": pl.CheckCooldownSeconds}
			if pl.NextPlan != "" {
				plan["next_plan"] = pl.NextPlan
			}
			if len(pl.AllowedChannelKinds) > 0 {
				plan["allowed_channel_kinds"] = pl.AllowedChannelKinds
			}
			if len(pl.SBOMImports) > 0 && string(pl.SBOMImports) != "null" {
				plan["sbom_imports_this_month"] = pl.SBOMImports
			}
			if pl.InactivePauseDays > 0 {
				plan["inactive_pause_days"] = pl.InactivePauseDays
			}
			if len(pl.ReadOnlyProjects) > 0 {
				plan["read_only_projects"] = pl.ReadOnlyProjects
			}
			out["plan"] = plan
		} else {
			out["plan"] = map[string]any{"name": nil, "note": "no plan limits apply to this organisation"}
		}
	}

	// Members by role: the list of people is for admins, and only the
	// counts leave this function.
	var users struct {
		Items []struct {
			Role     string `json:"role"`
			Access   string `json:"access"`
			Disabled bool   `json:"disabled"`
		} `json:"items"`
	}
	if p.get(ctx, api, "members", "/api/v1/users", &users) {
		byRole := map[string]int{}
		active, disabled := 0, 0
		for _, x := range users.Items {
			if x.Disabled {
				disabled++
				continue
			}
			active++
			switch {
			case x.Role != "":
				byRole[x.Role]++
			default:
				byRole["project_access_only"]++
			}
		}
		out["members"] = map[string]any{"active": active, "disabled": disabled, "by_role": byRole,
			"note": "counts only; names and email addresses are on People → Users"}
	}

	var ask struct {
		Available      bool       `json:"available"`
		Reason         string     `json:"reason"`
		QuestionsUsed  int64      `json:"questions_used"`
		QuestionsLimit *int64     `json:"questions_limit"`
		QuestionPeriod string     `json:"question_period"`
		ResetsAt       *time.Time `json:"resets_at"`
	}
	if p.get(ctx, api, "ask", "/api/v1/ask/status", &ask) {
		a := map[string]any{"available": ask.Available, "questions_used": ask.QuestionsUsed, "questions_limit": ask.QuestionsLimit,
			"question_period": ask.QuestionPeriod}
		if ask.Reason != "" {
			a["reason"] = ask.Reason
		}
		if ask.QuestionsLimit != nil {
			a["questions_left"] = max(*ask.QuestionsLimit-ask.QuestionsUsed, 0)
		}
		if ask.QuestionPeriod != "total" && ask.ResetsAt != nil {
			a["resets_at"] = ask.ResetsAt
		}
		a["note"] = "the limit is the organisation's, shared by everyone in it; questions_limit null means no question limit"
		out["ask_stackurity"] = a
	}

	out["not_available"] = nonNil(p.missing)
	return out, nil
}

func integrationsStatus(ctx context.Context, api API, _ map[string]any) (any, error) {
	var p parts
	out := map[string]any{}

	var chans struct {
		Items []channel `json:"items"`
	}
	if p.get(ctx, api, "channels", "/api/v1/channels", &chans) {
		list := make([]map[string]any, 0, len(chans.Items))
		for _, c := range chans.Items {
			list = append(list, c.public())
		}
		out["channels"] = list
	}

	var srcs struct {
		Items []struct {
			ID          int64      `json:"id"`
			Kind        string     `json:"kind"`
			Name        string     `json:"name"`
			ScheduleMin int64      `json:"schedule_minutes"`
			Enabled     bool       `json:"enabled"`
			AssetID     *int64     `json:"asset_id"`
			LastAttempt *time.Time `json:"last_attempt"`
			LastSuccess *time.Time `json:"last_success"`
			LastError   string     `json:"last_error"`
		} `json:"items"`
	}
	if p.get(ctx, api, "sources", "/api/v1/integrations", &srcs) {
		list := make([]map[string]any, 0, len(srcs.Items))
		for _, x := range srcs.Items {
			m := map[string]any{"id": x.ID, "kind": x.Kind, "name": withoutURLs(x.Name), "enabled": x.Enabled,
				"schedule_minutes": x.ScheduleMin, "last_attempt": x.LastAttempt, "last_success": x.LastSuccess}
			if x.AssetID != nil {
				m["asset_id"] = *x.AssetID
			}
			if x.LastError != "" {
				m["last_error"] = withoutURLs(x.LastError)
			}
			list = append(list, m)
		}
		out["sources"] = list
	}

	var gh struct {
		Configured    bool `json:"configured"`
		Installations []struct {
			Account      string     `json:"account_login,omitempty"`
			AccountType  string     `json:"account_type"`
			Selection    string     `json:"repository_selection"`
			Status       string     `json:"status"`
			Note         string     `json:"note"`
			LastSync     *time.Time `json:"last_sync"`
			Repositories int64      `json:"repositories"`
		} `json:"installations"`
	}
	if p.get(ctx, api, "github", "/api/v1/integrations/github", &gh) {
		for i := range gh.Installations {
			in := &gh.Installations[i]
			in.Note = withoutURLs(in.Note)
			if in.AccountType != "Organization" {
				// A personal GitHub account's login names a person.
				in.Account = ""
			}
		}
		out["github"] = map[string]any{"app_set_up_on_server": gh.Configured, "installations": nonNil(gh.Installations)}
	}

	var gl struct {
		Configured  bool `json:"configured"`
		Connections []struct {
			GroupPath         string     `json:"group_path"`
			GroupName         string     `json:"group_name"`
			CredentialKind    string     `json:"credential_kind"`
			CredentialExpires *time.Time `json:"credential_expires"`
			Status            string     `json:"status"`
			Note              string     `json:"note"`
			LastSync          *time.Time `json:"last_sync"`
			Projects          int64      `json:"projects"`
		} `json:"connections"`
	}
	if p.get(ctx, api, "gitlab", "/api/v1/integrations/gitlab", &gl) {
		for i := range gl.Connections {
			gl.Connections[i].Note = withoutURLs(gl.Connections[i].Note)
		}
		out["gitlab"] = map[string]any{"set_up_on_server": gl.Configured, "connections": nonNil(gl.Connections)}
	}

	var jira struct {
		Items []struct {
			Sites []struct {
				Name string `json:"name"`
			} `json:"sites"`
			Status       string     `json:"status"`
			StatusReason string     `json:"status_reason"`
			ConnectedAt  time.Time  `json:"connected_at"`
			RefreshedAt  *time.Time `json:"refreshed_at"`
		} `json:"items"`
	}
	if p.get(ctx, api, "jira", "/api/v1/integrations/jira/connections", &jira) {
		for i := range jira.Items {
			jira.Items[i].StatusReason = withoutURLs(jira.Items[i].StatusReason)
		}
		out["jira"] = map[string]any{"connections": nonNil(jira.Items)}
	}

	var do struct {
		Connected   bool       `json:"connected"`
		ConnectedAt *time.Time `json:"connected_at"`
	}
	if p.get(ctx, api, "digitalocean", "/api/v1/integrations/digitalocean", &do) {
		out["digitalocean"] = do
	}

	out["not_available"] = nonNil(p.missing)
	out["note"] = "A channel sends only while enabled and while a notification rule uses it (notification_settings). " +
		"Configuration, addresses and credentials are never shown."
	return out, nil
}

func notificationSettings(ctx context.Context, api API, _ map[string]any) (any, error) {
	var p parts
	out := map[string]any{}

	var chans struct {
		Items []channel `json:"items"`
	}
	byID := map[int64]channel{}
	if p.get(ctx, api, "channels", "/api/v1/channels", &chans) {
		for _, c := range chans.Items {
			byID[c.ID] = c
		}
	}
	chanRef := func(id int64) map[string]any {
		c, ok := byID[id]
		if !ok {
			return map[string]any{"id": id}
		}
		return map[string]any{"id": c.ID, "name": withoutURLs(c.Name), "kind": c.Kind, "enabled": c.Enabled}
	}

	var routes struct {
		Items []struct {
			ID             int64            `json:"id"`
			Name           string           `json:"name"`
			ChannelID      int64            `json:"channel_id"`
			Enabled        bool             `json:"enabled"`
			MinPriority    string           `json:"min_priority"`
			NewMinPriority string           `json:"new_min_priority"`
			SOSOnly        bool             `json:"sos_only"`
			Kinds          []string         `json:"kinds"`
			Environments   []string         `json:"environments"`
			TeamIDs        []int64          `json:"team_ids"`
			ProjectIDs     []int64          `json:"project_ids"`
			Escalation     bool             `json:"escalation"`
			SendResolved   bool             `json:"send_resolved"`
			QuietStart     string           `json:"quiet_start"`
			QuietEnd       string           `json:"quiet_end"`
			Timezone       string           `json:"timezone"`
			MaxPerHour     int              `json:"max_per_hour"`
			Mode           string           `json:"mode"`
			SummaryTime    string           `json:"summary_time"`
			SummaryDay     string           `json:"summary_day"`
			Events         []string         `json:"events"`
			EventChannels  map[string]int64 `json:"event_channels"`
			SummaryUpdates bool             `json:"summary_updates"`
			OwnerProjectID *int64           `json:"owner_project_id"`
			OwnerAssetID   *int64           `json:"owner_asset_id"`
		} `json:"items"`
	}
	if p.get(ctx, api, "rules", "/api/v1/routes", &routes) {
		list := make([]map[string]any, 0, len(routes.Items))
		for _, r := range routes.Items {
			m := map[string]any{"id": r.ID, "name": r.Name, "enabled": r.Enabled, "channel": chanRef(r.ChannelID),
				"belongs_to": owner(r.OwnerProjectID, r.OwnerAssetID), "events": nonNil(r.Events), "mode": r.Mode,
				"min_priority": r.MinPriority, "sos_only": r.SOSOnly, "kinds": nonNil(r.Kinds), "environments": nonNil(r.Environments),
				"project_ids": nonNil(r.ProjectIDs), "team_ids": nonNil(r.TeamIDs), "send_resolved": r.SendResolved,
				"escalation": r.Escalation, "timezone": r.Timezone, "max_per_hour": r.MaxPerHour}
			if r.NewMinPriority != "" {
				m["new_issues_min_priority"] = r.NewMinPriority
			}
			if r.SummaryTime != "" {
				m["summary_time"] = r.SummaryTime
			}
			if r.SummaryDay != "" {
				m["summary_day"] = r.SummaryDay
			}
			if r.QuietStart != "" || r.QuietEnd != "" {
				m["quiet_hours"] = map[string]string{"start": r.QuietStart, "end": r.QuietEnd}
			}
			if r.SummaryUpdates {
				m["weekly_summary_lists_updates"] = true
			}
			if len(r.EventChannels) > 0 {
				ev := map[string]any{}
				keys := make([]string, 0, len(r.EventChannels))
				for k := range r.EventChannels {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					ev[k] = chanRef(r.EventChannels[k])
				}
				m["event_channels"] = ev
			}
			m["sends"] = r.Enabled && byID[r.ChannelID].Enabled
			list = append(list, m)
		}
		out["rules"] = list
	}

	var ns struct {
		ProjectChatApps *bool `json:"project_chat_apps"`
	}
	if p.get(ctx, api, "settings", "/api/v1/settings/notifications", &ns) && ns.ProjectChatApps != nil {
		out["project_chat_apps"] = *ns.ProjectChatApps
	}
	out["not_available"] = nonNil(p.missing)
	out["note"] = "sends: the rule and its channel are both enabled. min_priority P1 is the most urgent; a rule with " +
		"min_priority P2 sends P1 and P2. Empty kinds, environments, project_ids and team_ids mean every one."
	return out, nil
}

// channel is what the account tools read of a notification channel. Its
// config and secret_ref are not even decoded.
type channel struct {
	ID             int64      `json:"id"`
	Kind           string     `json:"kind"`
	Name           string     `json:"name"`
	Enabled        bool       `json:"enabled"`
	LastOKAt       *time.Time `json:"last_ok_at"`
	LastDeliveryAt *time.Time `json:"last_delivery_at"`
	LastError      string     `json:"last_error"`
	OwnerProjectID *int64     `json:"owner_project_id"`
	OwnerAssetID   *int64     `json:"owner_asset_id"`
	SecretSource   string     `json:"secret_source"`
}

func (c channel) public() map[string]any {
	m := map[string]any{"id": c.ID, "kind": c.Kind, "name": withoutURLs(c.Name), "enabled": c.Enabled,
		"belongs_to": owner(c.OwnerProjectID, c.OwnerAssetID), "last_worked_at": c.LastOKAt, "last_delivered_at": c.LastDeliveryAt}
	if c.SecretSource == "missing" {
		m["credential_missing"] = true
	}
	if c.LastError != "" {
		m["last_error"] = withoutURLs(c.LastError)
	}
	return m
}

func owner(project, asset *int64) string {
	switch {
	case asset != nil:
		return "asset " + strconv.FormatInt(*asset, 10)
	case project != nil:
		return "project " + strconv.FormatInt(*project, 10)
	}
	return "organisation"
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
