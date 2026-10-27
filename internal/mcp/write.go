package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tools that change something work in two steps. Called without confirm,
// a tool only reads (to name what it would touch and check that the caller
// can see it) and answers with a preview and a confirm code; nothing is
// changed. Called again with the same arguments and that code, it makes
// the change through the API, which checks the caller's role on everything
// it touches and writes the audit log.
//
// The code is a digest of the tool, its arguments and what the preview
// found (the issues a fix covers now, whether an ignore is applied or
// asked for), so it only works for the exact change that was shown. It is
// not a secret and not a consent: it guards against a model acting on a
// guess, not against the model itself, which can always send it. What may
// change is decided by the person: "Allow changes" on the connection (or
// --allow-writes) offers these tools at all, and the API checks their role
// on everything a call touches. MCP clients that ask the user before a tool
// that is not read-only see the second call with its arguments, and the
// annotations mark which tools are destructive.

type writeTool struct {
	title string
	// destructive: it overwrites or hides something (a name, an
	// assignment, an issue from lists). openWorld: it reaches outside
	// Stackurity (an email to any address).
	destructive bool
	idempotent  bool
	openWorld   bool
	// plan reads what the change needs and describes it. It must not
	// change anything.
	plan func(ctx context.Context, s *Server, a map[string]any) (*change, error)
}

// change is what a write tool will do.
type change struct {
	summary string // one sentence: what will change
	details any    // what it touches, by id and name
	key     string // what will be done exactly, beyond the arguments
	apply   func(ctx context.Context) (any, error)
	notes   []string
}

// Install codes made by an assistant: at most this many servers and hours.
const (
	maxEnrollUses  = 50
	maxEnrollHours = 24
)

// writeTools are listed after the read-only tools, in this order.
var writeTools = []string{"create_project", "rename_project", "add_assets_to_project", "remove_assets_from_project",
	"create_enrollment", "assign", "snooze", "ignore", "check_again", "invite_to_project"}

func confirmCode(name string, a map[string]any, key string) string {
	args := map[string]any{}
	for k, v := range a {
		if k != "confirm" {
			args[k] = v
		}
	}
	raw, _ := json.Marshal(args) // map keys are sorted
	h := sha256.Sum256([]byte("stackurity-mcp-confirm-v1\x00" + name + "\x00" + string(raw) + "\x00" + key))
	return hex.EncodeToString(h[:])[:12]
}

func (s *Server) runWrite(ctx context.Context, name string, w *writeTool, a map[string]any) (any, error) {
	c, err := w.plan(ctx, s, a)
	if err != nil {
		return nil, err
	}
	code := confirmCode(name, a, c.key)
	given, _ := a["confirm"].(string)
	if strings.TrimSpace(given) == code {
		res, err := c.apply(ctx)
		if err != nil {
			return nil, fmt.Errorf("not done: %w", err)
		}
		return map[string]any{"status": "done", "done": c.summary, "result": res}, nil
	}
	out := map[string]any{
		"status":  "preview",
		"changed": "nothing yet",
		"will":    c.summary,
		"details": c.details,
		"confirm": code,
		"next": "Show this to the user. Only if they agree, call " + name + " again with exactly the same arguments and " +
			`"confirm": "` + code + `".`,
	}
	if given != "" {
		out["note"] = "The confirm code did not match this exact change (the arguments, or what they cover, changed since the preview). " +
			"Nothing was changed; review this preview instead."
	}
	if len(c.notes) > 0 {
		out["notes"] = c.notes
	}
	return out, nil
}

func confirmProp() map[string]any {
	return str("Leave out to get a preview (nothing changes). To apply, the confirm code from the preview, after the user agreed")
}

// --- argument helpers

func idList(v any, max int, what string) ([]int64, error) {
	raw, ok := v.([]any)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("%s must list at least one id", what)
	}
	if len(raw) > max {
		return nil, fmt.Errorf("%s: at most %d at a time", what, max)
	}
	seen := map[int64]bool{}
	var out []int64
	for _, x := range raw {
		n, ok := intArg(x)
		if !ok || n <= 0 {
			return nil, fmt.Errorf("%s must be positive integer ids", what)
		}
		if !seen[int64(n)] {
			seen[int64(n)] = true
			out = append(out, int64(n))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func positive(a map[string]any, k string) (int64, error) {
	n, ok := intArg(a[k])
	if !ok || n <= 0 {
		return 0, fmt.Errorf("%s is required", k)
	}
	return int64(n), nil
}

func text(a map[string]any, k string) string {
	v, _ := a[k].(string)
	return strings.TrimSpace(v)
}

func send(ctx context.Context, api API, method, path string, body any, out any) error {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	return api.Do(ctx, method, path, bytes.NewReader(raw), map[string]string{"Content-Type": "application/json"}, out)
}

type named struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func getProject(ctx context.Context, api API, id int64) (named, error) {
	var res struct {
		Project named `json:"project"`
	}
	if err := api.Do(ctx, "GET", fmt.Sprintf("/api/v1/projects/%d", id), nil, nil, &res); err != nil {
		return named{}, fmt.Errorf("project %d: %w", id, err)
	}
	return res.Project, nil
}

func getAssets(ctx context.Context, api API, ids []int64) ([]named, error) {
	out := make([]named, 0, len(ids))
	for _, id := range ids {
		var x struct {
			Asset named `json:"asset"`
		}
		if err := api.Do(ctx, "GET", fmt.Sprintf("/api/v1/assets/%d", id), nil, nil, &x); err != nil {
			return nil, fmt.Errorf("asset %d: %w", id, err)
		}
		out = append(out, x.Asset)
	}
	return out, nil
}

func idsKey(ids []int64) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(s, ",")
}

// issueSet is the open issues a change applies to: listed ids, or a fix's
// active issues as the caller sees them now.
type issueSet struct {
	ids      []int64
	fixGroup string
	shown    []map[string]any
}

const maxIssues = 500

func resolveIssues(ctx context.Context, api API, a map[string]any) (*issueSet, error) {
	fix := text(a, "fix_group")
	_, listed := a["finding_ids"]
	if (fix == "") == !listed {
		return nil, fmt.Errorf("give finding_ids or fix_group (a fix's group_id from action_plan or remediation_plan), not both")
	}
	set := &issueSet{fixGroup: fix}
	if listed {
		ids, err := idList(a["finding_ids"], maxIssues, "finding_ids")
		if err != nil {
			return nil, err
		}
		set.ids = ids
		for i, id := range ids {
			if i == 10 {
				break
			}
			var res struct {
				Finding finding `json:"finding"`
			}
			if err := api.Do(ctx, "GET", fmt.Sprintf("/api/v1/findings/%d", id), nil, nil, &res); err != nil {
				return nil, fmt.Errorf("finding %d: %w", id, err)
			}
			set.shown = append(set.shown, issueLine(res.Finding))
		}
		return set, nil
	}
	var res struct {
		Group struct {
			Title     string `json:"title"`
			AssetName string `json:"asset_name"`
		} `json:"group"`
		Findings struct {
			Items []finding `json:"items"`
			Total int64     `json:"total"`
		} `json:"findings"`
	}
	if err := api.Do(ctx, "GET", "/api/v1/fix-groups/"+url.PathEscape(fix)+"?limit="+strconv.Itoa(maxIssues), nil, nil, &res); err != nil {
		return nil, fmt.Errorf("fix %s: %w", fix, err)
	}
	if res.Findings.Total > maxIssues {
		return nil, fmt.Errorf("the fix %q has %d open issues; at most %d can be changed at once, so give finding_ids in batches", res.Group.Title, res.Findings.Total, maxIssues)
	}
	if len(res.Findings.Items) == 0 {
		return nil, fmt.Errorf("the fix %q has no open issues left", res.Group.Title)
	}
	for i, f := range res.Findings.Items {
		set.ids = append(set.ids, f.ID)
		if i < 10 {
			set.shown = append(set.shown, issueLine(f))
		}
	}
	sort.Slice(set.ids, func(i, j int) bool { return set.ids[i] < set.ids[j] })
	return set, nil
}

func issueLine(f finding) map[string]any {
	return map[string]any{"finding_id": f.ID, "key": f.Key, "component": f.ComponentName, "version": f.Version,
		"asset": f.AssetName, "priority": f.Priority, "state": f.State}
}

func (set *issueSet) details() map[string]any {
	d := map[string]any{"issues": len(set.ids), "first_issues": set.shown}
	if set.fixGroup != "" {
		d["fix_group"] = set.fixGroup
	}
	return d
}

func issues(n int) string {
	if n == 1 {
		return "1 issue"
	}
	return strconv.Itoa(n) + " issues"
}

// actionResult is the answer of POST /findings/actions.
type actionResult struct {
	Applied int      `json:"applied"`
	Failed  []string `json:"failed"`
}

func bulkAction(ctx context.Context, api API, ids []int64, body map[string]any) (any, error) {
	body["ids"] = ids
	var res actionResult
	if err := send(ctx, api, "POST", "/api/v1/findings/actions", body, &res); err != nil {
		return nil, err
	}
	out := map[string]any{"applied": res.Applied}
	if len(res.Failed) > 0 {
		out["failed"] = res.Failed[:min(len(res.Failed), 20)]
	}
	return out, nil
}

// me is the caller as GET /auth/me describes them.
type me struct {
	User struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Role        string `json:"role"`
	ProjectRole string `json:"project_role"`
}

var rank = map[string]int{"viewer": 1, "engineer": 2, "security": 3, "admin": 4}

func whoAmI(ctx context.Context, api API) (*me, error) {
	var m me
	if err := api.Do(ctx, "GET", "/api/v1/auth/me", nil, nil, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// highest is the caller's highest role anywhere: organisation-wide or from
// a project. The API still checks the role on each asset.
func (m *me) highest() string {
	if rank[m.ProjectRole] > rank[m.Role] {
		return m.ProjectRole
	}
	return m.Role
}

func dateArg(a map[string]any, k string) (*time.Time, error) {
	v := text(a, k)
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		d, derr := time.Parse("2006-01-02", v)
		if derr != nil {
			return nil, fmt.Errorf("%s must be a date (2026-12-31) or an RFC 3339 time", k)
		}
		t = d.Add(24*time.Hour - time.Second)
	}
	if !t.After(time.Now()) {
		return nil, fmt.Errorf("%s must be in the future", k)
	}
	return &t, nil
}

var issueTarget = map[string]any{
	"finding_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "maxItems": maxIssues,
		"description": "Findings (issues) by id, up to 500. Give this or fix_group"},
	"fix_group": str("A fix's group_id (from action_plan or remediation_plan): its open issues. Give this or finding_ids"),
}

func with(base map[string]any, more map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range more {
		out[k] = v
	}
	return out
}

func init() {
	tools["create_project"] = tool{
		description: "Create a project (a site, client or product) and optionally put assets in it. Needs the admin role. " +
			"Without confirm it only previews.",
		schema: obj(map[string]any{
			"name":        str("Project name, 1 to 100 characters, unique in the organisation"),
			"description": str("Optional description"),
			"asset_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "maxItems": 100, "description": "Assets to add (from list_assets)"},
			"confirm":     confirmProp(),
		}, "name"),
		write: &writeTool{title: "Create a project", plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			name, desc := text(a, "name"), text(a, "description")
			if name == "" || len(name) > 100 {
				return nil, fmt.Errorf("name must be 1 to 100 characters")
			}
			var ids []int64
			var assets []named
			if _, ok := a["asset_ids"]; ok {
				var err error
				if ids, err = idList(a["asset_ids"], 100, "asset_ids"); err != nil {
					return nil, err
				}
				if assets, err = getAssets(ctx, s.API, ids); err != nil {
					return nil, err
				}
			}
			sum := fmt.Sprintf("Create the project %q", name)
			if len(ids) > 0 {
				sum += fmt.Sprintf(" with %d assets", len(ids))
			}
			return &change{summary: sum, details: map[string]any{"name": name, "description": desc, "assets": assets},
				apply: func(ctx context.Context) (any, error) {
					body := map[string]any{"name": name, "description": desc}
					if len(ids) > 0 {
						body["asset_ids"] = ids
					}
					var p map[string]any
					err := send(ctx, s.API, "POST", "/api/v1/projects", body, &p)
					return map[string]any{"project_id": p["id"], "name": p["name"], "asset_count": p["asset_count"]}, err
				}}, nil
		}},
	}
	tools["rename_project"] = tool{
		description: "Rename a project. Needs the admin role. Without confirm it only previews.",
		schema: obj(map[string]any{
			"project_id": num("The project"),
			"name":       str("The new name, 1 to 100 characters"),
			"confirm":    confirmProp(),
		}, "project_id", "name"),
		write: &writeTool{title: "Rename a project", idempotent: true, destructive: true, plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			id, err := positive(a, "project_id")
			if err != nil {
				return nil, err
			}
			name := text(a, "name")
			if name == "" || len(name) > 100 {
				return nil, fmt.Errorf("name must be 1 to 100 characters")
			}
			p, err := getProject(ctx, s.API, id)
			if err != nil {
				return nil, err
			}
			return &change{summary: fmt.Sprintf("Rename the project %q (%d) to %q", p.Name, id, name),
				details: map[string]any{"project_id": id, "from": p.Name, "to": name},
				apply: func(ctx context.Context) (any, error) {
					var out map[string]any
					err := send(ctx, s.API, "PATCH", fmt.Sprintf("/api/v1/projects/%d", id), map[string]any{"name": name}, &out)
					return map[string]any{"project_id": id, "name": out["name"]}, err
				}}, nil
		}},
	}
	projectAssets := func(add bool) *writeTool {
		verb, title := "Add", "Add assets to a project"
		if !add {
			verb, title = "Remove", "Remove assets from a project"
		}
		return &writeTool{title: title, idempotent: true, destructive: !add, plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			id, err := positive(a, "project_id")
			if err != nil {
				return nil, err
			}
			ids, err := idList(a["asset_ids"], 100, "asset_ids")
			if err != nil {
				return nil, err
			}
			p, err := getProject(ctx, s.API, id)
			if err != nil {
				return nil, err
			}
			assets, err := getAssets(ctx, s.API, ids)
			if err != nil {
				return nil, err
			}
			prep := "to"
			if !add {
				prep = "from"
			}
			c := &change{summary: fmt.Sprintf("%s %d assets %s the project %q (%d)", verb, len(ids), prep, p.Name, id),
				details: map[string]any{"project_id": id, "project": p.Name, "assets": assets},
				apply: func(ctx context.Context) (any, error) {
					method := "POST"
					if !add {
						method = "DELETE"
					}
					var out map[string]any
					err := send(ctx, s.API, method, fmt.Sprintf("/api/v1/projects/%d/assets", id), map[string]any{"asset_ids": ids}, &out)
					return map[string]any{"changed": out["changed"]}, err
				}}
			if !add {
				c.notes = []string{"People and teams with access through this project stop seeing these assets, unless another project or grant gives it."}
			}
			return c, nil
		}}
	}
	assetsSchema := obj(map[string]any{
		"project_id": num("The project"),
		"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "minItems": 1, "maxItems": 100, "description": "Assets (from list_assets)"},
		"confirm":    confirmProp(),
	}, "project_id", "asset_ids")
	tools["add_assets_to_project"] = tool{
		description: "Put assets in a project (an asset can be in several). Needs the admin role. Without confirm it only previews.",
		schema:      assetsSchema, write: projectAssets(true),
	}
	tools["remove_assets_from_project"] = tool{
		description: "Take assets out of a project; the assets themselves stay. Needs the admin role. Without confirm it only previews.",
		schema:      assetsSchema, write: projectAssets(false),
	}
	tools["create_enrollment"] = tool{
		description: "Create an install code for new Linux servers and return the one-line install command to run on each " +
			"(as root). Use it for \"set up 3 servers\": servers is how many may use the code. The code is shown once. " +
			"Needs the admin role. Without confirm it only previews.",
		schema: obj(map[string]any{
			"servers":     num("How many servers may use the code (1 to 50, default 1): exactly the number to set up"),
			"valid_hours": num("Hours the code works (1 to 24, default 24)"),
			"label":       str("A label for the code, such as what the servers are for"),
			"environment": str("Environment label for the servers, e.g. production (letters, digits, . _ -)"),
			"project_id":  num("Add the servers to this project"),
			"check_apps": map[string]any{"type": "boolean",
				"description": "Also look for websites and applications deployed on the servers (default true); false reads only the operating system's packages"},
			"confirm": confirmProp(),
		}),
		write: &writeTool{title: "Create a server install code", plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			uses, ttl := 1, 24
			if n, ok := intArg(a["servers"]); ok {
				uses = n
			}
			if n, ok := intArg(a["valid_hours"]); ok {
				ttl = n
			}
			// Small on purpose: the code ends up in a chat. More servers, or
			// a longer life, are for Settings, Add servers.
			if uses < 1 || uses > maxEnrollUses || ttl < 1 || ttl > maxEnrollHours {
				return nil, fmt.Errorf("servers must be 1 to %d and valid_hours 1 to %d; create larger codes in Stackurity under Add servers", maxEnrollUses, maxEnrollHours)
			}
			apps := true
			if b, ok := a["check_apps"].(bool); ok {
				apps = b
			}
			body := map[string]any{"uses": uses, "ttl_hours": ttl, "label": text(a, "label"), "environment": text(a, "environment"),
				"discover_apps": apps}
			details := map[string]any{"servers": uses, "valid_hours": ttl, "label": body["label"], "environment": body["environment"],
				"check_apps": apps}
			where := ""
			if _, ok := a["project_id"]; ok {
				id, err := positive(a, "project_id")
				if err != nil {
					return nil, err
				}
				p, err := getProject(ctx, s.API, id)
				if err != nil {
					return nil, err
				}
				body["project_id"] = id
				details["project"] = p.Name
				where = fmt.Sprintf(" into the project %q", p.Name)
			}
			return &change{summary: fmt.Sprintf("Create an install code for %d server(s)%s, valid for %d hours", uses, where, ttl), details: details,
				apply: func(ctx context.Context) (any, error) {
					var res struct {
						Enrollment map[string]any `json:"enrollment"`
						Code       string         `json:"code"`
					}
					if err := send(ctx, s.API, "POST", "/api/v1/enrollments", body, &res); err != nil {
						return nil, err
					}
					return map[string]any{"enrollment_id": res.Enrollment["id"], "expires_at": res.Enrollment["expires_at"], "servers": uses,
						"install_command": installCommand(s.BaseURL, res.Code),
						"note": "Run the command as root on each Linux server. The code is shown only now; each server appears in list_assets " +
							"after its first report, usually within a minute."}, nil
				}}, nil
		}},
	}
	tools["assign"] = tool{
		description: "Assign issues (findings) to a person: by finding_ids, or every open issue of a fix (fix_group). " +
			"assignee is \"me\", a user id, or an email from the people directory. Needs engineer on the issues' assets. " +
			"Without confirm it only previews.",
		schema: obj(with(issueTarget, map[string]any{
			"assignee": str(`"me", a user id, or a person's email`),
			"confirm":  confirmProp(),
		}), "assignee"),
		write: &writeTool{title: "Assign issues", idempotent: true, destructive: true, plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			set, err := resolveIssues(ctx, s.API, a)
			if err != nil {
				return nil, err
			}
			uid, who, err := assignee(ctx, s.API, text(a, "assignee"))
			if err != nil {
				return nil, err
			}
			d := set.details()
			d["assignee"] = who
			return &change{summary: fmt.Sprintf("Assign %s to %s", issues(len(set.ids)), who), details: d,
				key: fmt.Sprintf("%d|%s", uid, idsKey(set.ids)),
				apply: func(ctx context.Context) (any, error) {
					return bulkAction(ctx, s.API, set.ids, map[string]any{"action": "assign", "user_id": uid})
				}}, nil
		}},
	}
	tools["snooze"] = tool{
		description: "Snooze issues until a date, or until a free fix exists (until_fix): they leave the to-do lists and come " +
			"back by themselves. Needs the security role; others can use ignore, which asks for approval. Without confirm it only previews.",
		schema: obj(with(issueTarget, map[string]any{
			"until":     str("Snooze until this date (2026-12-31), at most the organisation's exception limit ahead"),
			"until_fix": map[string]any{"type": "boolean", "description": "Snooze until a free fixed version exists instead of a date"},
			"note":      str("Why (kept in each issue's history)"),
			"confirm":   confirmProp(),
		})),
		write: &writeTool{title: "Snooze issues", idempotent: true, destructive: true, plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			until, err := dateArg(a, "until")
			if err != nil {
				return nil, err
			}
			untilFix, _ := a["until_fix"].(bool)
			if (until == nil) == !untilFix {
				return nil, fmt.Errorf("give until (a date) or until_fix: true")
			}
			m, err := whoAmI(ctx, s.API)
			if err != nil {
				return nil, err
			}
			if rank[m.highest()] < rank["security"] {
				return nil, fmt.Errorf("snoozing needs the security role (you are %s); use ignore instead, which files a request for approval", roleWord(m.highest()))
			}
			set, err := resolveIssues(ctx, s.API, a)
			if err != nil {
				return nil, err
			}
			body := map[string]any{"action": "suppress", "note": text(a, "note")}
			when := "until a free fix exists"
			if until != nil {
				body["until"] = until.UTC().Format(time.RFC3339)
				when = "until " + until.UTC().Format("2 Jan 2006")
			} else {
				body["until_fix"] = true
			}
			return &change{summary: fmt.Sprintf("Snooze %s %s", issues(len(set.ids)), when), details: set.details(), key: idsKey(set.ids),
				apply: func(ctx context.Context) (any, error) { return bulkAction(ctx, s.API, set.ids, body) }}, nil
		}},
	}
	tools["ignore"] = tool{
		description: "Ignore issues with a reason and an expiry, on their asset or on every asset. With the security role " +
			"(on the issues' assets) the issues are ignored at once; otherwise a request is filed for a security or admin " +
			"user to approve, and nothing changes until then. The preview says which. Without confirm it only previews.",
		schema: obj(with(issueTarget, map[string]any{
			"reason":     map[string]any{"type": "string", "enum": []string{"accepted_risk", "false_positive", "mitigated", "no_fix"}, "description": "Why the issues can be ignored"},
			"note":       str("The explanation, kept with the rule and in each issue's history (required)"),
			"scope":      map[string]any{"type": "string", "enum": []string{"asset", "everywhere"}, "description": "asset (default): on these assets only; everywhere: on every asset with the same component and advisory, including future ones (organisation-wide security or admin only)"},
			"expiry":     map[string]any{"type": "string", "enum": []string{"date", "until_fix", "never"}, "description": "date (with until), until_fix (until a free fix exists), or never (false positives only)"},
			"until":      str("With expiry date: the date the ignore ends (2026-12-31)"),
			"mitigation": str("What reduces the risk meanwhile (for mitigated and accepted_risk)"),
			"confirm":    confirmProp(),
		}), "reason", "note", "expiry"),
		write: &writeTool{title: "Ignore issues (or ask to)", idempotent: true, destructive: true, plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			reason, note, expiry, scope := text(a, "reason"), text(a, "note"), text(a, "expiry"), text(a, "scope")
			if scope == "" {
				scope = "asset"
			}
			if note == "" {
				return nil, fmt.Errorf("note is required: say why the issues can be ignored")
			}
			until, err := dateArg(a, "until")
			if err != nil {
				return nil, err
			}
			if (expiry == "date") != (until != nil) {
				return nil, fmt.Errorf("give until exactly when expiry is date")
			}
			m, err := whoAmI(ctx, s.API)
			if err != nil {
				return nil, err
			}
			set, err := resolveIssues(ctx, s.API, a)
			if err != nil {
				return nil, err
			}
			spec := map[string]any{"reason": reason, "note": note, "scope": scope, "expiry": expiry, "mitigation": text(a, "mitigation")}
			if until != nil {
				spec["until"] = until.UTC().Format(time.RFC3339)
			}
			when := map[string]string{"until_fix": "until a free fix exists", "never": "with no end date"}[expiry]
			if until != nil {
				when = "until " + until.UTC().Format("2 Jan 2006")
			}
			where := "on their assets"
			if scope == "everywhere" {
				where = "on every asset"
			}
			d := set.details()
			d["reason"], d["scope"], d["expiry"] = reason, scope, expiry
			if rank[m.highest()] >= rank["security"] {
				return &change{summary: fmt.Sprintf("Ignore %s %s %s (%s)", issues(len(set.ids)), where, when, reason), details: d,
					key: "ignore|" + idsKey(set.ids),
					apply: func(ctx context.Context) (any, error) {
						body := with(spec, map[string]any{"action": "ignore"})
						return bulkAction(ctx, s.API, set.ids, body)
					}}, nil
			}
			c := &change{summary: fmt.Sprintf("Ask to ignore %s %s %s (%s); a security or admin user decides, nothing changes until then",
				issues(len(set.ids)), where, when, reason), details: d, key: "request|" + idsKey(set.ids),
				apply: func(ctx context.Context) (any, error) {
					body := with(spec, map[string]any{})
					if set.fixGroup != "" {
						body["fix_group"] = set.fixGroup
					} else {
						body["finding_ids"] = set.ids
					}
					var req map[string]any
					if err := send(ctx, s.API, "POST", "/api/v1/ignore-requests", body, &req); err != nil {
						return nil, err
					}
					return map[string]any{"ignore_request_id": req["id"], "status": req["status"], "issues": len(set.ids)}, nil
				}}
			c.notes = []string{fmt.Sprintf("You are %s here, so this files a request for approval rather than ignoring.", roleWord(m.highest()))}
			return c, nil
		}},
	}
	tools["check_again"] = tool{
		description: "Check again: ask for a fresh report of a fix (fix_group) or a whole asset (asset_id) from its agent, or a " +
			"server-side scan, to confirm a fix. Issues close by themselves when the fresh report no longer has them. " +
			"Needs engineer on the asset. Without confirm it only previews.",
		schema: obj(map[string]any{
			"fix_group": str("A fix's group_id: check that fix"),
			"asset_id":  num("Or an asset: check all of it"),
			"confirm":   confirmProp(),
		}),
		write: &writeTool{title: "Check again", idempotent: true, plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			fix := text(a, "fix_group")
			_, hasAsset := a["asset_id"]
			if (fix == "") == !hasAsset {
				return nil, fmt.Errorf("give fix_group or asset_id")
			}
			var path, what string
			if fix != "" {
				var res struct {
					Group struct {
						Title     string `json:"title"`
						AssetName string `json:"asset_name"`
					} `json:"group"`
				}
				if err := s.API.Do(ctx, "GET", "/api/v1/fix-groups/"+url.PathEscape(fix)+"?limit=1", nil, nil, &res); err != nil {
					return nil, fmt.Errorf("fix %s: %w", fix, err)
				}
				path, what = "/api/v1/fix-groups/"+url.PathEscape(fix)+"/check", fmt.Sprintf("the fix %q on %s", res.Group.Title, res.Group.AssetName)
			} else {
				id, err := positive(a, "asset_id")
				if err != nil {
					return nil, err
				}
				as, err := getAssets(ctx, s.API, []int64{id})
				if err != nil {
					return nil, err
				}
				path, what = fmt.Sprintf("/api/v1/assets/%d/check", id), fmt.Sprintf("the asset %q (%d)", as[0].Name, id)
			}
			return &change{summary: "Ask for a fresh report to check " + what, details: map[string]any{"fix_group": fix, "asset_id": a["asset_id"]},
				apply: func(ctx context.Context) (any, error) {
					var chk map[string]any
					if err := send(ctx, s.API, "POST", path, nil, &chk); err != nil {
						return nil, err
					}
					return map[string]any{"check_id": chk["id"], "method": chk["method"], "status": chk["status"],
						"note": "Use verify_since or get the check later to see the outcome."}, nil
				}}, nil
		}},
	}
	tools["invite_to_project"] = tool{
		description: "Invite someone by email to a project with a role (viewer, engineer, security or admin on that project " +
			"only). Someone already in the organisation gets the role at once. Needs the admin role. Without confirm it only previews.",
		schema: obj(map[string]any{
			"email":      str("Their email address"),
			"project_id": num("The project"),
			"role":       map[string]any{"type": "string", "enum": []string{"viewer", "engineer", "security", "admin"}, "description": "Their role on the project"},
			"name":       str("Their name (optional)"),
			"confirm":    confirmProp(),
		}, "email", "project_id", "role"),
		write: &writeTool{title: "Invite someone to a project", openWorld: true, plan: func(ctx context.Context, s *Server, a map[string]any) (*change, error) {
			email, role := strings.ToLower(text(a, "email")), text(a, "role")
			if !strings.Contains(email, "@") || len(email) > 254 {
				return nil, fmt.Errorf("a valid email is required")
			}
			if rank[role] == 0 {
				return nil, fmt.Errorf("role must be viewer, engineer, security or admin")
			}
			id, err := positive(a, "project_id")
			if err != nil {
				return nil, err
			}
			p, err := getProject(ctx, s.API, id)
			if err != nil {
				return nil, err
			}
			return &change{summary: fmt.Sprintf("Invite %s to the project %q as %s", email, p.Name, role),
				details: map[string]any{"email": email, "project": p.Name, "project_id": id, "role": role},
				notes:   []string{"Someone already in the organisation gets the role at once; others get an email with a link when email is set up on this server."},
				apply: func(ctx context.Context) (any, error) {
					var res struct {
						Emailed bool `json:"emailed"`
						Granted bool `json:"granted"`
					}
					// The answer may carry the invitation link (when it was not
					// emailed): it is a credential, so it never reaches the model.
					err := send(ctx, s.API, "POST", "/api/v1/invitations", map[string]any{"email": email, "name": text(a, "name"), "role": role, "project_id": id}, &res)
					if err != nil {
						return nil, err
					}
					switch {
					case res.Granted:
						return map[string]any{"result": email + " is already in the organisation and now has the " + role + " role on " + p.Name + "."}, nil
					case res.Emailed:
						return map[string]any{"result": "Invitation emailed to " + email + "."}, nil
					}
					return map[string]any{"result": "Invitation created for " + email + ", but this server does not send email. To get a link to " +
						"pass on privately, invite them again in Stackurity (Settings, Projects and access, the project, Invite by email): that replaces this invitation and shows the link once."}, nil
				}}, nil
		}},
	}
}

func roleWord(r string) string {
	if r == "" {
		return "without a role"
	}
	return "a " + r
}

// assignee resolves "me", a user id or an email to a user id the caller may
// assign to (the people directory lists exactly those).
func assignee(ctx context.Context, api API, v string) (int64, string, error) {
	if v == "" {
		return 0, "", fmt.Errorf(`assignee is required: "me", a user id or an email`)
	}
	if strings.EqualFold(v, "me") {
		m, err := whoAmI(ctx, api)
		if err != nil {
			return 0, "", err
		}
		return m.User.ID, m.User.Email + " (you)", nil
	}
	var dir []struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	var res struct {
		Items json.RawMessage `json:"items"`
	}
	if err := api.Do(ctx, "GET", "/api/v1/users/directory", nil, nil, &res); err != nil {
		return 0, "", err
	}
	_ = json.Unmarshal(res.Items, &dir)
	id, _ := strconv.ParseInt(v, 10, 64)
	for _, u := range dir {
		if (id > 0 && u.ID == id) || strings.EqualFold(u.Email, v) {
			who := u.Email
			if u.Name != "" {
				who = u.Name + " <" + u.Email + ">"
			}
			return u.ID, who, nil
		}
	}
	return 0, "", fmt.Errorf("no one you can assign to matches %q", v)
}

// installCommand is the dashboard's one-line agent installer. The
// installer refuses plain HTTP to anything but localhost unless told to.
func installCommand(base, code string) string {
	base = strings.TrimRight(base, "/")
	env := "STACKURITY_ENROLL_CODE=" + code
	if u, err := url.Parse(base); err == nil && u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			env += " STACKURITY_ALLOW_HTTP=1"
		}
	}
	return "curl -fsSL " + base + "/install/agent.sh | sudo " + env + " sh"
}
