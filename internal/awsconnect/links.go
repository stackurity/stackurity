package awsconnect

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// RegionRE matches commercial and GovCloud region codes (as the
	// aws-managed plugin does).
	RegionRE = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-\d$`)
	// RoleARNRE matches an IAM role ARN in the aws partition.
	RoleARNRE = regexp.MustCompile(`^arn:aws:iam::(\d{12}):role/[\w+=,.@/-]{1,512}$`)
	// PrincipalRE matches what a role may trust: an IAM user, a role or an
	// account root.
	PrincipalRE = regexp.MustCompile(`^arn:aws:iam::\d{12}:(root|user/[\w+=,.@/-]+|role/[\w+=,.@/-]+)$`)
	// ExternalIDRE matches the external IDs Stackurity generates.
	ExternalIDRE = regexp.MustCompile(`^stk-[0-9a-f]{32}$`)
	// InstanceIDRE matches EC2 instance and SSM managed-instance IDs.
	InstanceIDRE = regexp.MustCompile(`^(i|mi)-[0-9a-f]{8,32}$`)
)

// NewExternalID returns a fresh external ID: "stk-" and 128 random bits.
func NewExternalID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "stk-" + hex.EncodeToString(b), nil
}

// AccountOf returns the account ID in a role ARN, or "".
func AccountOf(roleARN string) string {
	if m := RoleARNRE.FindStringSubmatch(roleARN); m != nil {
		return m[1]
	}
	return ""
}

// LaunchParams are what a quick-create link fills in.
type LaunchParams struct {
	TemplateURL  string // https://<bucket>.s3.<region>.amazonaws.com/... (CloudFormation only accepts S3)
	Region       string // where the stack is created
	StackName    string
	Principal    string
	ExternalID   string
	AgentInstall bool
	CallbackURL  string // empty: no callback; the ARN is pasted
	Token        string
}

// QuickCreateURL is the CloudFormation console's quick-create link: the
// administrator reviews the stack, ticks the IAM acknowledgement and creates
// it. The parameters live in the fragment, which the console reads; each
// value is query-escaped.
func QuickCreateURL(p LaunchParams) (string, error) {
	switch {
	case !RegionRE.MatchString(p.Region):
		return "", fmt.Errorf("invalid region %q", p.Region)
	case !PrincipalRE.MatchString(p.Principal):
		return "", errors.New("the server's AWS principal is not an IAM user, role or account root ARN")
	case !ExternalIDRE.MatchString(p.ExternalID):
		return "", errors.New("invalid external ID")
	}
	u, err := url.Parse(p.TemplateURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("the template URL must be an https:// address")
	}
	q := []string{
		"templateURL=" + url.QueryEscape(p.TemplateURL),
		"stackName=" + url.QueryEscape(p.StackName),
		"param_StackurityPrincipal=" + url.QueryEscape(p.Principal),
		"param_ExternalId=" + url.QueryEscape(p.ExternalID),
		"param_EnableAgentInstall=" + fmt.Sprint(p.AgentInstall),
	}
	if p.CallbackURL != "" && p.Token != "" {
		q = append(q, "param_CallbackUrl="+url.QueryEscape(p.CallbackURL), "param_CallbackToken="+url.QueryEscape(p.Token))
	}
	return "https://" + p.Region + ".console.aws.amazon.com/cloudformation/home?region=" + p.Region +
		"#/stacks/create/review?" + strings.Join(q, "&"), nil
}

// CallbackClaims bind a callback token to one connection of one workspace and
// its external ID. Nonce is random; the server keeps only its hash and
// forgets it once used.
type CallbackClaims struct {
	Version    int    `json:"v"`
	Connection int64  `json:"c"`
	Workspace  int64  `json:"w"`
	ExternalID string `json:"x"`
	Nonce      string `json:"n"`
	Expires    int64  `json:"e"`
}

// ErrBadToken hides why a callback token was refused.
var ErrBadToken = errors.New("invalid or expired callback token")

// NewCallbackToken signs fresh claims for a connection with key. It returns
// the token and the SHA-256 of its nonce, which is what the server stores.
func NewCallbackToken(key []byte, connection, workspace int64, externalID string, expires time.Time) (string, []byte, error) {
	n := make([]byte, 24)
	if _, err := rand.Read(n); err != nil {
		return "", nil, err
	}
	c := CallbackClaims{Version: 1, Connection: connection, Workspace: workspace, ExternalID: externalID,
		Nonce: base64.RawURLEncoding.EncodeToString(n), Expires: expires.Unix()}
	return SignCallbackClaims(key, c), NonceHash(c.Nonce), nil
}

// SignCallbackClaims makes the token for claims.
func SignCallbackClaims(key []byte, c CallbackClaims) string {
	body, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("stackurity-aws-callback." + payload))
	return "stkcb_" + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// NonceHash is what is stored for a nonce.
func NonceHash(nonce string) []byte {
	h := sha256.Sum256([]byte("stackurity-aws-callback-nonce." + nonce))
	return h[:]
}

// ParseCallbackToken checks a token's signature and expiry. Whether it was
// already used is for the caller to check, atomically, against the store.
func ParseCallbackToken(key []byte, token string, now time.Time) (CallbackClaims, error) {
	var c CallbackClaims
	rest, ok := strings.CutPrefix(token, "stkcb_")
	if !ok || len(rest) > 2048 {
		return c, ErrBadToken
	}
	payload, sig, ok := strings.Cut(rest, ".")
	if !ok {
		return c, ErrBadToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return c, ErrBadToken
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("stackurity-aws-callback." + payload))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return c, ErrBadToken
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(body, &c) != nil {
		return CallbackClaims{}, ErrBadToken
	}
	if c.Version != 1 || c.Connection <= 0 || c.Workspace <= 0 || !ExternalIDRE.MatchString(c.ExternalID) || c.Nonce == "" ||
		now.Unix() >= c.Expires {
		return CallbackClaims{}, ErrBadToken
	}
	return c, nil
}
