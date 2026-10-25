// Package netguard stops server-side requests made on behalf of a workspace
// (Git clones, webhooks, email, registries) from reaching internal addresses:
// loopback, private networks, link-local addresses such as cloud metadata
// services, and Stackurity itself. Where the connection is made in this
// process the check runs on the address actually dialled, so a hostname that
// resolves differently later (DNS rebinding) is caught too.
//
// Which workspaces may reach private networks is set by the operator:
//
//	STACKURITY_PRIVATE_TARGETS   default: only the default workspace (1)
//	                             all:     every workspace (single-organisation installs)
//	                             none:    no workspace (multi-tenant platforms)
//	STACKURITY_PRIVATE_CIDRS     comma-separated ranges every workspace may reach,
//	                             e.g. an internal Git server
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// ErrBlocked means the destination is an internal address the caller's
// workspace may not reach.
var ErrBlocked = errors.New("destination is an internal address")

// Config is the operator's policy, normally read once with FromEnv.
type Config struct {
	Mode    string // "default", "all" or "none"
	Allowed []netip.Prefix
}

var current = FromEnv()

// Set replaces the policy (tests, or a server that read its configuration).
func Set(c Config) { current = c }

func FromEnv() Config {
	c := Config{Mode: strings.ToLower(strings.TrimSpace(os.Getenv("STACKURITY_PRIVATE_TARGETS")))}
	if c.Mode == "" {
		c.Mode = "default"
	}
	for _, s := range strings.Split(os.Getenv("STACKURITY_PRIVATE_CIDRS"), ",") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			c.Allowed = append(c.Allowed, p.Masked())
		}
	}
	return c
}

// Validate reports a configuration mistake.
func (c Config) Validate() error {
	switch c.Mode {
	case "default", "all", "none":
		return nil
	}
	return fmt.Errorf("STACKURITY_PRIVATE_TARGETS must be default, all or none, not %q", c.Mode)
}

// AllowsPrivate reports whether the workspace in ctx may reach private
// networks. System scope (the platform's own work) may.
func AllowsPrivate(ctx context.Context) bool {
	if tenant.IsSystem(ctx) {
		return true
	}
	switch current.Mode {
	case "all":
		return true
	case "none":
		return false
	}
	ws, ok := tenant.Workspace(ctx)
	return ok && ws == tenant.DefaultWorkspace
}

var blocked = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "2001:db8::/32",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// CheckIP returns ErrBlocked when ctx's workspace may not connect to ip.
func CheckIP(ctx context.Context, ip netip.Addr) error {
	return PolicyFor(ctx).CheckIP(ip)
}

// Policy is the rule for one workspace in a form that can be handed to a
// process dialling on its behalf (a plugin), which has no workspace context
// of its own.
type Policy struct {
	AllowPrivate bool           `json:"allow_private"`
	Allowed      []netip.Prefix `json:"allowed_cidrs,omitempty"`
}

// PolicyFor returns the policy that applies to ctx's workspace.
func PolicyFor(ctx context.Context) Policy {
	return Policy{AllowPrivate: AllowsPrivate(ctx), Allowed: current.Allowed}
}

// CheckIP returns ErrBlocked when the policy does not allow connecting to ip.
func (p Policy) CheckIP(ip netip.Addr) error {
	ip = ip.Unmap()
	if p.AllowPrivate {
		return nil
	}
	for _, a := range p.Allowed {
		if a.Contains(ip) {
			return nil
		}
	}
	for _, b := range blocked {
		if b.Contains(ip) {
			return fmt.Errorf("%w (%s)", ErrBlocked, ip)
		}
	}
	return nil
}

// DialContext dials like net.Dialer, refusing addresses the policy blocks
// at connect time (so DNS rebinding is caught too).
func (p Policy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			return p.CheckIP(ap.Addr())
		},
	}
	return d.DialContext(ctx, network, addr)
}

// Resolve looks host up and returns its addresses, failing if any of them is
// blocked for ctx's workspace.
func Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{ip}, CheckIP(ctx, ip)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if err := CheckIP(ctx, a); err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
	}
	return addrs, nil
}

// DialContext dials like net.Dialer, refusing blocked addresses at connect
// time. Use it as an http.Transport's DialContext; the request's context
// carries the workspace.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return PolicyFor(ctx).DialContext(ctx, network, addr)
}
