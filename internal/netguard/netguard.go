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
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
		// IPv6: unspecified, loopback and IPv4-compatible (::/96), discard,
		// unique local (fd00:ec2::254 is the EC2 metadata service), deprecated
		// site-local, link-local, multicast, NAT64 (which reaches IPv4
		// through a translator) and documentation.
		"::/96", "100::/64", "fc00::/7", "fec0::/10", "fe80::/10", "ff00::/8", "64:ff9b::/96", "64:ff9b:1::/48",
		"2001:db8::/32",
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
	// A zone (fe80::1%eth0) makes netip.Prefix.Contains report false for
	// every prefix, so it is dropped before the comparison; the address
	// itself decides.
	ip = ip.WithZone("").Unmap()
	if !ip.IsValid() {
		return fmt.Errorf("%w (invalid address)", ErrBlocked)
	}
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

// DialContext dials like net.Dialer, refusing addresses the policy blocks.
// The host is resolved here and every address is checked, and the check
// runs again on the address actually dialled, so a hostname that resolves
// differently between the two (DNS rebinding) is still caught.
func (p Policy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
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
	addrs, err := p.resolve(ctx, ipNetwork(network), host)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

func ipNetwork(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	}
	return "ip"
}

// ErrAmbiguousHost means a host name is an IPv4 address in a notation other
// than four decimal parts (2130706433, 0x7f.1, 0177.0.0.1). Some clients,
// such as curl inside git, read those as addresses while Go reads them as
// names, so the address that was checked would not be the one used.
var ErrAmbiguousHost = errors.New("host is a numeric address in a non-standard notation")

// CheckHost refuses host names whose last label is a number (decimal, or
// hexadecimal with 0x), which URL parsers treat as an IPv4 address. Real
// names never end in a numeric label. Canonical IP literals pass.
func CheckHost(host string) error {
	h := strings.Trim(host, "[]")
	if _, err := netip.ParseAddr(h); err == nil {
		return nil
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return errors.New("empty host")
	}
	last := h[strings.LastIndexByte(h, '.')+1:]
	numeric := last != ""
	digits := last
	if l := strings.ToLower(last); strings.HasPrefix(l, "0x") {
		digits = l[2:]
		for _, c := range digits {
			if !strings.ContainsRune("0123456789abcdef", c) {
				numeric = false
			}
		}
	} else {
		for _, c := range digits {
			if c < '0' || c > '9' {
				numeric = false
			}
		}
	}
	if numeric {
		return fmt.Errorf("%w: %q", ErrAmbiguousHost, host)
	}
	return nil
}

// lookup resolves names; tests replace it to simulate DNS answers.
var lookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// SetResolver replaces name resolution (tests) and returns a function that
// restores the previous one.
func SetResolver(fn func(ctx context.Context, network, host string) ([]netip.Addr, error)) (restore func()) {
	prev := lookup
	lookup = fn
	return func() { lookup = prev }
}

// resolve returns host's addresses, failing if the host is ambiguous, has
// no address, or any of its addresses is blocked.
func (p Policy) resolve(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{ip}, p.CheckIP(ip)
	}
	if err := CheckHost(host); err != nil {
		return nil, err
	}
	addrs, err := lookup(ctx, network, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: no addresses", host)
	}
	for _, a := range addrs {
		if err := p.CheckIP(a); err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
	}
	return addrs, nil
}

// Resolve looks host up and returns its addresses, failing if any of them is
// blocked for ctx's workspace, or if host is a numeric address in a
// non-standard notation.
func Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return PolicyFor(ctx).resolve(ctx, "ip", host)
}

// DialContext dials like net.Dialer, refusing blocked addresses at connect
// time. Use it as an http.Transport's DialContext; the request's context
// carries the workspace.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return PolicyFor(ctx).DialContext(ctx, network, addr)
}
