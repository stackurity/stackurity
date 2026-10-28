//go:build eedeps

package eedeps

import (
	// Single sign-on with OpenID Connect (internal/sso in stackurity-pro).
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "golang.org/x/oauth2"
)
