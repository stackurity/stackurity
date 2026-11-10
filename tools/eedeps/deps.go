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

	// Disposable email domains refused at Stackurity Cloud sign-up
	// (internal/cloud in stackurity-pro): international domain names and
	// the public suffix list.
	_ "golang.org/x/net/idna"
	_ "golang.org/x/net/publicsuffix"

	// Tax-invoice PDFs of Stackurity Cloud (internal/cloud in
	// stackurity-pro): signintech/gopdf (MIT) embeds a TrueType font, so
	// customer names and addresses in any EU language print correctly. The
	// fonts are golang.org/x/image's Go fonts (BSD-3-Clause), already a
	// dependency.
	_ "github.com/signintech/gopdf"
	_ "golang.org/x/image/font/gofont/gobold"
	_ "golang.org/x/image/font/gofont/goregular"
	_ "golang.org/x/image/font/sfnt"
	// Country names on the invoice ("Germany" for DE).
	_ "golang.org/x/text/language"
	_ "golang.org/x/text/language/display"
)
