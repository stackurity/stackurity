package api

import (
	"errors"
	"net/http"

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/tenant"
)

// cloudSetup returns the commands that connect a Google Cloud project or an
// Azure subscription to this workspace: keyless when the server can offer it
// (a workload identity naming the workspace, or the Stackurity Entra app with
// the workspace's proof), and the credential fallback. Nothing in it is
// secret: the server's signing key and app secret never leave the server.
func (s *Server) cloudSetup(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws, ok := tenant.Workspace(r.Context())
		if !ok {
			s.fail(w, r, errors.New("no workspace"))
			return
		}
		q := r.URL.Query()
		var setup *cloudconnect.Setup
		var err error
		if provider == "gcp" {
			setup, err = s.Cloud.GCPSetup(ws, q.Get("project_id"), q.Get("project_number"))
		} else {
			setup, err = s.Cloud.AzureSetup(ws, q.Get("tenant_id"), q.Get("subscription_id"))
		}
		if err != nil {
			s.fail(w, r, badRequest(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, setup)
	}
}
