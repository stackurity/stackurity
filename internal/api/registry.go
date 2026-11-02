package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/collect/registry"
	"github.com/stackurity/stackurity/internal/registrysync"
	"github.com/stackurity/stackurity/internal/store"
)

// KindContainerRegistry is a connected registry: its repositories are
// listed and their recent tags scanned (internal/registrysync).
const KindContainerRegistry = registrysync.Kind

// checkRegistryConfig checks what validation of the configuration alone
// cannot: an ECR registry has credentials somewhere, and borrowing an
// aws-managed integration's server secret (env:, file:) needs an instance
// administrator, like using it directly.
func (s *Server) checkRegistryConfig(r *http.Request, c registry.Config, secretRef string) error {
	if c.Provider != registry.ECR {
		return nil
	}
	if c.AWSIntegrationID == 0 {
		if secretRef == "" {
			return badRequest(`Amazon ECR needs access keys: set secret_ref to a secret holding {"aws_access_key_id": "...", "aws_secret_access_key": "..."}, or aws_integration_id`)
		}
		return nil
	}
	in, _, _, err := registrysync.AWSIntegration(r.Context(), s.Store, c.AWSIntegrationID)
	if errors.Is(err, registrysync.ErrAWSIntegration) {
		return badRequest(err.Error())
	}
	if err != nil {
		return err
	}
	if secretRef == "" && in.SecretRef == "" {
		return badRequest("the aws-managed integration has no stored access keys; the instance role is not used for registries: set secret_ref")
	}
	return checkSecretRef(r, in.SecretRef)
}

type discoverRequest struct {
	Config json.RawMessage `json:"config"`
	// SecretRef, or the stored one of IntegrationID (changing the
	// repositories of an existing registry).
	SecretRef     *string `json:"secret_ref"`
	IntegrationID int64   `json:"integration_id"`
}

// discoverRegistry lists a registry's repositories for an admin to pick
// from, with whether the configuration's choices track each. The secret
// is used and never returned.
func (s *Server) discoverRegistry(w http.ResponseWriter, r *http.Request) {
	var req discoverRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	dec := json.NewDecoder(strings.NewReader(string(req.Config)))
	dec.DisallowUnknownFields()
	var c registry.Config
	if err := dec.Decode(&c); err != nil {
		s.fail(w, r, badRequest("invalid config: "+err.Error()))
		return
	}
	if err := c.Validate(); err != nil {
		s.fail(w, r, badRequest("invalid config: "+err.Error()))
		return
	}
	ref := ""
	if req.SecretRef != nil {
		ref = *req.SecretRef
	} else if req.IntegrationID != 0 {
		in, err := s.Store.GetIntegration(r.Context(), req.IntegrationID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if in.Kind != KindContainerRegistry {
			s.fail(w, r, badRequest("integration_id must name a container registry integration"))
			return
		}
		ref = in.SecretRef
	}
	if ref != "" {
		if err := s.Secrets.Validate(ref); err != nil {
			s.fail(w, r, badRequest(err.Error()))
			return
		}
	}
	if err := checkSecretRef(r, ref); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.checkRegistryConfig(r, c, ref); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	c, cr, err := registrysync.Credentials(ctx, s.Store, s.Secrets, c, ref)
	if err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	names, complete, err := registry.ListRepositories(ctx, c, cr)
	if err != nil {
		writeError(w, 502, "registry_error", "the registry could not be listed: "+err.Error())
		return
	}
	sel := registry.NewSelector(registry.Config{Namespace: c.Namespace, Include: c.Include, Exclude: c.Exclude})
	type repo struct {
		Name     string `json:"name"`
		Included bool   `json:"included"`
	}
	out := make([]repo, 0, len(names))
	for _, n := range names {
		out = append(out, repo{Name: n, Included: sel.Repository(n)})
	}
	writeJSON(w, 200, map[string]any{"registry": c.DisplayName(), "repositories": out, "complete": complete})
}

// registryImages lists the images a registry integration tracks, has
// stopped tracking, and found removed.
func (s *Server) registryImages(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := s.Store.GetIntegration(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Kind != KindContainerRegistry {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	items, err := s.Store.RegistryImages(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(items))
}
