package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/secrets"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/collect/image"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/plugins"
	"github.com/stackurity/stackurity/internal/store"
)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(us))
}

type userRequest struct {
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	Role     auth.Role `json:"role"`
	Password string    `json:"password"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !strings.Contains(req.Email, "@") {
		s.fail(w, r, badRequest("a valid email is required"))
		return
	}
	if !req.Role.ValidUser() && req.Role != store.RoleNone {
		s.fail(w, r, badRequest("role must be viewer, engineer, security, admin, or none (access through projects only)"))
		return
	}
	u, err := s.Store.CreateUser(r.Context(), req.Email, req.Name, req.Role, req.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "user.create", "user", itoa(u.ID), map[string]any{"email": u.Email, "role": u.Role})
	writeJSON(w, 201, u)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var u store.UserUpdate
	if err := decode(r, &u); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.UpdateUser(r.Context(), id, u, principal(r).User.InstanceAdmin); err != nil {
		s.fail(w, r, err)
		return
	}
	detail := map[string]any{"role": u.Role, "disabled": u.Disabled, "password_changed": u.Password != nil, "name": u.Name}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "user.update", "user", itoa(id), detail)
	us, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, us)
}

func (s *Server) listTeams(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Store.ListTeams(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(ts))
}

type teamRequest struct {
	Name    *string  `json:"name"`
	Email   *string  `json:"email"`
	Members *[]int64 `json:"members"`
}

func (s *Server) createTeam(w http.ResponseWriter, r *http.Request) {
	var req teamRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	// Community has one team; more need Pro.
	if !s.has(r, license.Teams) {
		ts, err := s.Store.ListTeams(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if len(ts) >= 1 {
			planRequired(w, license.Teams)
			return
		}
	}
	if req.Name == nil || strings.TrimSpace(*req.Name) == "" {
		s.fail(w, r, badRequest("name is required"))
		return
	}
	email := ""
	if req.Email != nil {
		email = *req.Email
	}
	t, err := s.Store.CreateTeam(r.Context(), *req.Name, email)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Members != nil {
		if err := s.Store.UpdateTeam(r.Context(), t.ID, nil, nil, req.Members); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "team.create", "team", itoa(t.ID), req)
	if t, err = s.Store.GetTeam(r.Context(), t.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 201, t)
}

func (s *Server) updateTeam(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req teamRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.UpdateTeam(r.Context(), id, req.Name, req.Email, req.Members); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "team.update", "team", itoa(id), req)
	w.WriteHeader(204)
}

func (s *Server) deleteTeam(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteTeam(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "team.delete", "team", itoa(id), nil)
	w.WriteHeader(204)
}

func (s *Server) listConflicts(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.ListConflicts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(cs))
}

func (s *Server) resolveConflict(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		TargetAssetID int64 `json:"target_asset_id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	var uid int64
	if p.User != nil {
		uid = p.User.ID
	}
	if err := s.Store.ResolveConflict(r.Context(), id, req.TargetAssetID, uid); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "conflict.resolve", "identity_conflict", itoa(id), req)
	w.WriteHeader(204)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items, total, err := s.Store.ListAudit(r.Context(), q.Get("object_type"), q.Get("object_id"), page(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, page(r)))
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	js, err := s.Store.ListJobs(r.Context(), r.URL.Query().Get("state"), 200)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(js))
}

// Integration kinds the server knows how to run.
const (
	KindGitRepository  = "git_repository"
	KindContainerImage = "container_image"
	KindPlugin         = "plugin"
)

// PluginConfig is the integration config for an external plugin.
type PluginConfig struct {
	Plugin string          `json:"plugin"`
	Config json.RawMessage `json:"config"`
	// ImageScans bounds how many images the plugin reports (as image assets
	// with an image-ref and no packages, like running Kubernetes images) are
	// queued for the image scanner per run. Nil means the default; 0 turns
	// scanning off.
	ImageScans *int `json:"image_scans,omitempty"`
}

const (
	DefaultImageScans = 25
	MaxImageScans     = 500
)

// ImageScanLimit is the number of image scans one run may queue.
func (c PluginConfig) ImageScanLimit() int {
	if c.ImageScans == nil {
		return DefaultImageScans
	}
	return *c.ImageScans
}

type integrationRequest struct {
	Kind            string          `json:"kind"`
	Name            *string         `json:"name"`
	Config          json.RawMessage `json:"config"`
	SecretRef       *string         `json:"secret_ref"`
	ScheduleMinutes *int            `json:"schedule_minutes"`
	Enabled         *bool           `json:"enabled"`
}

// checkSecretRef keeps the server's own secrets (env: and file:) to instance
// administrators: on a shared installation they belong to the operator, and
// whoever can point an integration somewhere could send them there.
func checkSecretRef(r *http.Request, ref string) error {
	if !secrets.ServerSecret(ref) {
		return nil
	}
	if p := principal(r); p == nil || p.User == nil || !p.User.InstanceAdmin {
		return forbidden("env: and file: secrets belong to the server; only an instance administrator can use them or change what uses them. " +
			"Store the credential in this workspace (Settings > Secrets) and reference it as secret:NAME")
	}
	return nil
}

func (s *Server) validateIntegration(ctx context.Context, kind string, cfg json.RawMessage, secretRef *string, minutes *int) error {
	if len(cfg) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(cfg)))
		dec.DisallowUnknownFields()
		var err error
		switch kind {
		case KindGitRepository:
			var c gitrepo.Config
			if err = dec.Decode(&c); err == nil {
				err = c.Validate()
			}
		case KindContainerImage:
			var c image.Config
			if err = dec.Decode(&c); err == nil {
				err = c.Validate()
			}
		case KindPlugin:
			var c PluginConfig
			if err = dec.Decode(&c); err == nil {
				// Plugin problems come back as a list in error.details.
				if verr := s.validatePluginConfig(c); verr != nil {
					var ve *model.ValidationError
					if errors.As(verr, &ve) {
						return ve
					}
					err = verr
				}
			}
		default:
			return badRequest("kind must be " + KindGitRepository + ", " + KindContainerImage + " or " + KindPlugin)
		}
		if err != nil {
			return badRequest("invalid config: " + err.Error())
		}
	} else if kind != KindGitRepository && kind != KindContainerImage && kind != KindPlugin {
		return badRequest("kind must be " + KindGitRepository + ", " + KindContainerImage + " or " + KindPlugin)
	}
	if secretRef != nil {
		if err := s.Secrets.Validate(*secretRef); err != nil {
			return badRequest(err.Error())
		}
	}
	// Without credentials a plugin falls back to the server's own (for AWS,
	// the instance role), which only the operator's workspace may use.
	if kind == KindPlugin && (secretRef == nil || *secretRef == "") && !netguard.AllowsPrivate(ctx) {
		return badRequest("plugins in this workspace need credentials: set secret_ref to a stored secret")
	}
	if minutes != nil && (*minutes < 15 || *minutes > 7*24*60) {
		return badRequest("schedule_minutes must be between 15 and 10080")
	}
	return nil
}

func (s *Server) listIntegrations(w http.ResponseWriter, r *http.Request) {
	is, err := s.Store.ListIntegrations(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(is))
}

func (s *Server) createIntegration(w http.ResponseWriter, r *http.Request) {
	var req integrationRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.Config) == 0 {
		s.fail(w, r, badRequest("config is required"))
		return
	}
	if err := s.validateIntegration(r.Context(), req.Kind, req.Config, req.SecretRef, req.ScheduleMinutes); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.SecretRef != nil {
		if err := checkSecretRef(r, *req.SecretRef); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	name := ""
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if name == "" {
		switch req.Kind {
		case KindGitRepository:
			var c gitrepo.Config
			_ = json.Unmarshal(req.Config, &c)
			name = gitrepo.RepoName(c.URL)
		case KindContainerImage:
			var c image.Config
			_ = json.Unmarshal(req.Config, &c)
			name = c.Image
		case KindPlugin:
			var c PluginConfig
			_ = json.Unmarshal(req.Config, &c)
			name = c.Plugin
		}
	}
	sched := 6 * time.Hour
	if req.ScheduleMinutes != nil {
		sched = time.Duration(*req.ScheduleMinutes) * time.Minute
	}
	ref := ""
	if req.SecretRef != nil {
		ref = *req.SecretRef
	}
	in, err := s.Store.CreateIntegration(r.Context(), req.Kind, name, req.Config, ref, sched)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "integration.create", "integration", itoa(in.ID), map[string]any{"kind": in.Kind, "name": in.Name})
	writeJSON(w, 201, in)
}

func (s *Server) updateIntegration(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := s.Store.GetIntegration(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req integrationRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ref := cur.SecretRef
	if req.SecretRef != nil {
		ref = *req.SecretRef
	}
	if err := s.validateIntegration(r.Context(), cur.Kind, req.Config, &ref, req.ScheduleMinutes); err != nil {
		s.fail(w, r, err)
		return
	}
	// Changing anything about an integration that reads a server secret
	// could redirect that secret, so it needs an instance administrator.
	if err := checkSecretRef(r, ref); err != nil {
		s.fail(w, r, err)
		return
	}
	u := store.IntegrationUpdate{Name: req.Name, Config: req.Config, SecretRef: req.SecretRef, Enabled: req.Enabled}
	if req.ScheduleMinutes != nil {
		d := time.Duration(*req.ScheduleMinutes) * time.Minute
		u.Schedule = &d
	}
	if err := s.Store.UpdateIntegration(r.Context(), id, u); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "integration.update", "integration", itoa(id), req)
	in, _ := s.Store.GetIntegration(r.Context(), id)
	writeJSON(w, 200, in)
}

func (s *Server) deleteIntegration(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteIntegration(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "integration.delete", "integration", itoa(id), nil)
	w.WriteHeader(204)
}

// runIntegration queues an immediate run (manual refresh, FR-03).
func (s *Server) runIntegration(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.Store.GetIntegration(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	jobID, err := s.Store.Enqueue(r.Context(), "integration.run", map[string]int64{"integration_id": id}, "integration:"+itoa(id), time.Time{})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "integration.run", "integration", itoa(id), nil)
	writeJSON(w, 202, map[string]any{"job_id": jobID, "queued": jobID != 0})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Store.GetJob(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, j)
}

func (s *Server) facets(w http.ResponseWriter, r *http.Request) {
	f, err := s.Store.Facets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, f)
}

func (s *Server) validatePluginConfig(c PluginConfig) error {
	if c.ImageScans != nil && (*c.ImageScans < 0 || *c.ImageScans > MaxImageScans) {
		return errors.New("image_scans must be between 0 and " + strconv.Itoa(MaxImageScans))
	}
	if s.Plugins == nil {
		return errors.New("plugins are not enabled on this server (set STACKURITY_PLUGIN_DIR)")
	}
	if len(c.Config) == 0 {
		c.Config = json.RawMessage("{}")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := s.Plugins.Validate(ctx, c.Plugin, c.Config)
	if err != nil {
		return err
	}
	if !v.OK {
		return &model.ValidationError{Problems: v.Problems}
	}
	return nil
}

// listPlugins shows installed plugins and their declared permissions,
// credentials and network access for review before use.
func (s *Server) listPlugins(w http.ResponseWriter, r *http.Request) {
	if s.Plugins == nil {
		writeJSON(w, 200, map[string]any{"items": []any{}, "total": 0, "enabled": false})
		return
	}
	list, err := s.Plugins.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if list == nil {
		list = []plugins.Installed{}
	}
	for i := range list {
		list[i].Path = "" // do not expose server paths
	}
	writeJSON(w, 200, map[string]any{"items": list, "total": len(list), "enabled": true})
}

// adminHealth reports whether the platform itself is working: feeds, periodic
// tasks, jobs, integrations, notifications, collectors and production
// coverage across all workspaces. Instance admins only. Problems that span
// workspaces count every workspace but name objects (and show their errors)
// only in the caller's active workspace.
func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	if s.Health == nil {
		writeError(w, 404, "not_found", "health checks are not enabled on this server")
		return
	}
	rep, err := s.Health.CheckFor(r.Context(), principal(r).Workspace)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, rep)
}
