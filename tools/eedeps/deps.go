//go:build eedeps

package eedeps

import (
	// Single sign-on with OpenID Connect (internal/sso in stackurity-pro).
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "golang.org/x/oauth2"

	// Single sign-on with SAML 2.0 (internal/sso in stackurity-pro). Its
	// XML signature library is required at a version without
	// GO-2026-4753 (signature bypass), newer than crewjam/saml asks for.
	_ "github.com/crewjam/saml"
	_ "github.com/russellhaering/goxmldsig"
)
