package cloudconnect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/secrets"
)

// Credential names the server fills in for a plugin that declares them. A
// workspace's stored secret can never supply them (StripPlatform).
const (
	PlatformPrefix     = "stackurity_"
	CredIdentityToken  = "stackurity_identity_token"  // a JWT naming the workspace (Google Cloud federation)
	CredWorkspaceProof = "stackurity_workspace_proof" // the workspace's proof value (Azure role assignment description)
	CredAzureAppID     = "stackurity_azure_app_id"
	CredAzureAppSecret = "stackurity_azure_app_secret"
)

// GCPAudience is the audience of identity tokens for Google Cloud; the
// generated provider allows only it.
const GCPAudience = "stackurity-gcp"

// ProofPrefix starts the description of the Azure role assignment, followed
// by the workspace's proof value.
const ProofPrefix = "stackurity-workspace-proof:"

// identityTTL bounds an identity token: the plugin exchanges it at once.
const identityTTL = 10 * time.Minute

// Platform is the server's own identity towards customers' clouds. A nil
// *Platform, or one without a key, offers only the credential fallbacks.
type Platform struct {
	Issuer         string // STACKURITY_BASE_URL, https
	key            *ecdsa.PrivateKey
	kid            string
	proofKey       []byte
	AzureAppID     string
	azureAppSecret string
}

// FromEnv builds the platform identity: the signing key is derived from
// STACKURITY_SECRET_KEY, the issuer is STACKURITY_BASE_URL, and the Azure app
// is STACKURITY_AZURE_APP_ID with STACKURITY_AZURE_APP_SECRET (or _FILE).
// Missing pieces leave the matching option unavailable (see GCPStatus,
// AzureStatus); only a malformed value is an error.
func FromEnv() (*Platform, error) {
	p := &Platform{Issuer: strings.TrimRight(strings.TrimSpace(os.Getenv("STACKURITY_BASE_URL")), "/")}
	key, err := secrets.KeyFromEnv()
	switch {
	case errors.Is(err, secrets.ErrNoKey):
	case err != nil:
		return nil, err
	default:
		if err := p.setKey(key); err != nil {
			return nil, err
		}
	}
	p.AzureAppID = strings.TrimSpace(os.Getenv("STACKURITY_AZURE_APP_ID"))
	p.azureAppSecret = strings.TrimSpace(os.Getenv("STACKURITY_AZURE_APP_SECRET"))
	if f := os.Getenv("STACKURITY_AZURE_APP_SECRET_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read STACKURITY_AZURE_APP_SECRET_FILE: %w", err)
		}
		p.azureAppSecret = strings.TrimSpace(string(b))
	}
	if p.AzureAppID != "" && !guidRE.MatchString(p.AzureAppID) {
		return nil, errors.New("STACKURITY_AZURE_APP_ID must be the application (client) ID, a GUID")
	}
	if (p.AzureAppID == "") != (p.azureAppSecret == "") {
		return nil, errors.New("set both STACKURITY_AZURE_APP_ID and STACKURITY_AZURE_APP_SECRET (or _FILE), or neither")
	}
	return p, nil
}

// New builds a platform from explicit values (tests).
func New(issuer string, secretKey []byte, azureAppID, azureAppSecret string) (*Platform, error) {
	p := &Platform{Issuer: strings.TrimRight(issuer, "/"), AzureAppID: azureAppID, azureAppSecret: azureAppSecret}
	if secretKey != nil {
		if err := p.setKey(secretKey); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *Platform) setKey(secretKey []byte) error {
	// HKDF keeps the derived keys independent of each other and of the
	// stored-secrets key itself.
	for i := 0; i < 16; i++ {
		raw, err := hkdf.Key(sha256.New, secretKey, nil, "stackurity workload identity ES256 v1/"+strconv.Itoa(i), 32)
		if err != nil {
			return err
		}
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
		if err != nil {
			continue // outside the curve order: try the next counter
		}
		p.key = k
		break
	}
	if p.key == nil {
		return errors.New("could not derive the workload identity key")
	}
	pk, err := hkdf.Key(sha256.New, secretKey, nil, "stackurity workspace proof v1", 32)
	if err != nil {
		return err
	}
	p.proofKey = pk
	x, y := p.publicXY()
	sum := sha256.Sum256(append(x, y...))
	p.kid = base64.RawURLEncoding.EncodeToString(sum[:12])
	return nil
}

func (p *Platform) publicXY() ([]byte, []byte) {
	pub, err := p.key.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil || len(pub) != 65 {
		panic("cloudconnect: P-256 public key encoding")
	}
	return pub[1:33], pub[33:]
}

// GCPStatus says whether keyless Google Cloud access is available, and why not.
func (p *Platform) GCPStatus() (bool, string) {
	switch {
	case p == nil || p.key == nil:
		return false, "the server has no STACKURITY_SECRET_KEY, from which its signing key is derived"
	case !strings.HasPrefix(p.Issuer, "https://"):
		return false, "STACKURITY_BASE_URL must be the server's https:// address (the token issuer)"
	}
	if u, err := url.Parse(p.Issuer); err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return false, "STACKURITY_BASE_URL is not a valid https:// URL"
	}
	return true, ""
}

// AzureStatus says whether the Stackurity Entra app is configured.
func (p *Platform) AzureStatus() (bool, string) {
	switch {
	case p == nil || p.key == nil:
		return false, "the server has no STACKURITY_SECRET_KEY, from which workspace proofs are derived"
	case p.AzureAppID == "":
		return false, "the server operator has not registered a Stackurity Entra app (STACKURITY_AZURE_APP_ID, STACKURITY_AZURE_APP_SECRET)"
	}
	return true, ""
}

// Subject is the identity token subject for a workspace.
func Subject(workspace int64) string { return "workspace:" + strconv.FormatInt(workspace, 10) }

// IdentityToken returns a short-lived ES256 JWT naming the workspace.
func (p *Platform) IdentityToken(workspace int64, audience string, now time.Time) (string, error) {
	if ok, why := p.GCPStatus(); !ok {
		return "", errors.New(why)
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": p.kid})
	claims, _ := json.Marshal(map[string]any{
		"iss": p.Issuer, "sub": Subject(workspace), "aud": audience,
		"iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(identityTTL).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(nonce),
	})
	signing := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// JWKS is the public key set customers upload to their workload identity
// provider, so Google Cloud never has to reach this server.
func (p *Platform) JWKS() string {
	if p == nil || p.key == nil {
		return ""
	}
	x, y := p.publicXY()
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": p.kid,
		"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
	}}})
	return string(b)
}

// WorkspaceProof is a value only this server can compute for a workspace.
// An Azure customer writes it into the role assignment for the Stackurity
// app; the plugin then refuses a subscription whose assignment names
// another workspace, so one workspace cannot read a subscription another
// workspace's customer granted to the shared app.
func (p *Platform) WorkspaceProof(workspace int64) string {
	if p == nil || p.proofKey == nil {
		return ""
	}
	m := hmac.New(sha256.New, p.proofKey)
	m.Write([]byte("azure|" + strconv.FormatInt(workspace, 10)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:18])
}

// PluginCredentials fills the platform credentials a plugin declares, for
// one run in one workspace. Ones this server cannot provide are left out;
// the plugin then explains what is missing.
func (p *Platform) PluginCredentials(declared []string, workspace int64, now time.Time) map[string]string {
	out := map[string]string{}
	if p == nil {
		return out
	}
	for _, d := range declared {
		name := strings.TrimSpace(strings.SplitN(d, " ", 2)[0])
		switch name {
		case CredIdentityToken:
			if t, err := p.IdentityToken(workspace, GCPAudience, now); err == nil {
				out[name] = t
			}
		case CredWorkspaceProof:
			if v := p.WorkspaceProof(workspace); v != "" {
				out[name] = v
			}
		case CredAzureAppID:
			if ok, _ := p.AzureStatus(); ok {
				out[name] = p.AzureAppID
			}
		case CredAzureAppSecret:
			if ok, _ := p.AzureStatus(); ok {
				out[name] = p.azureAppSecret
			}
		}
	}
	return out
}

// DeclaresPlatform reports whether a plugin's declared credentials include
// one the server provides. Such a plugin never falls back to the server's
// ambient credentials (instance roles, metadata services).
func DeclaresPlatform(declared []string) bool {
	for _, d := range declared {
		if strings.HasPrefix(strings.TrimSpace(d), PlatformPrefix) {
			return true
		}
	}
	return false
}

// StripPlatform removes platform credential names from a workspace's stored
// secret, so a workspace cannot supply its own identity token or proof.
func StripPlatform(m map[string]string) {
	for k := range m {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(k)), PlatformPrefix) {
			delete(m, k)
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// PlatformPlugins are the plugins the server gives platform credentials to.
// Other plugins never receive them, whatever they declare.
var PlatformPlugins = map[string]bool{"gcp-managed": true, "azure-managed": true}

// UsesPlatform reports whether the plugin installed as name, declaring these
// credentials, is given platform credentials. Such a plugin never falls back
// to the server's ambient credentials, so it may run without a stored secret
// in any workspace.
func UsesPlatform(name string, declared []string) bool {
	return PlatformPlugins[name] && DeclaresPlatform(declared)
}

// ForPlugin returns the credentials for one plugin run: the workspace's
// stored values without platform names, plus the platform credentials when
// the plugin is entitled to them.
func (p *Platform) ForPlugin(name string, declared []string, stored map[string]string, workspace int64, now time.Time) map[string]string {
	out := map[string]string{}
	for k, v := range stored {
		out[k] = v
	}
	StripPlatform(out)
	if UsesPlatform(name, declared) {
		for k, v := range p.PluginCredentials(declared, workspace, now) {
			out[k] = v
		}
	}
	return out
}
