package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
)

// DigitalOcean fleet discovery: an administrator stores a read-only
// DigitalOcean API token (an encrypted workspace secret, never returned),
// and the dashboard lists the account's droplets with whether a Stackurity
// agent already reports from each, so the ones not covered can be installed
// with a fleet code.
//
// Stackurity never installs on a droplet itself. DigitalOcean has no API to
// run a command on an existing droplet (the Droplet Agent serves the web
// console, with no public exec API), user data only runs when a droplet is
// created, and the remaining path, the Stackurity server connecting to
// customer machines over SSH with a key the customer adds, would turn a
// read-only, outbound-only agent into a server that holds root access to the
// fleet. That needs its own design decision; until then the dashboard gives
// the commands and the cloud-init user data to run, and the person runs
// them (docs/install.md, "Many servers at once").

// doTokenSecret names the stored secret that holds the token.
const doTokenSecret = "digitalocean-token"

// doDefaultAPI is DigitalOcean's API; Server.DigitalOceanAPI overrides it
// (tests).
const doDefaultAPI = "https://api.digitalocean.com"

// Listing bounds: 200 droplets a page (DigitalOcean's maximum), at most
// doMaxPages pages.
const (
	doPerPage  = 200
	doMaxPages = 25
)

var doHTTP = &http.Client{
	Timeout: 20 * time.Second,
	// Through the outbound guard like every request made for a workspace,
	// and no redirects, so the token is only ever sent to the API host. The
	// guard checks each address when it is dialled, so connections are not
	// kept for reuse: a connection one workspace may open is never handed
	// to a request made for another.
	Transport: &http.Transport{DialContext: netguard.DialContext, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second, DisableKeepAlives: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (s *Server) doAPI() string {
	if s.DigitalOceanAPI != "" {
		return strings.TrimRight(s.DigitalOceanAPI, "/")
	}
	return doDefaultAPI
}

// errDOToken: DigitalOcean refused the token (401/403).
var errDOToken = errors.New("DigitalOcean refused the token; it needs read access to droplets (a token with the droplet:read scope)")

type doDroplet struct {
	ID     int64    `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Tags   []string `json:"tags"`
	Region struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"region"`
	Image struct {
		Distribution string `json:"distribution"`
		Name         string `json:"name"`
	} `json:"image"`
	Networks struct {
		V4 []doAddress `json:"v4"`
		V6 []doAddress `json:"v6"`
	} `json:"networks"`
}

type doAddress struct {
	IP   string `json:"ip_address"`
	Type string `json:"type"` // public or private
}

// doDroplets lists the account's droplets, optionally only those with tag,
// page by page. truncated reports that there were more than the bound.
func (s *Server) doDroplets(ctx context.Context, token, tag string, maxPages int) (out []doDroplet, truncated bool, err error) {
	for page := 1; ; page++ {
		if page > maxPages {
			return out, true, nil
		}
		q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(doPerPage)}}
		if tag != "" {
			q.Set("tag_name", tag)
		}
		var body struct {
			Droplets []doDroplet `json:"droplets"`
			Links    struct {
				Pages struct {
					Next string `json:"next"`
				} `json:"pages"`
			} `json:"links"`
		}
		if err := s.doGet(ctx, token, "/v2/droplets?"+q.Encode(), &body); err != nil {
			return nil, false, err
		}
		out = append(out, body.Droplets...)
		// The next page is requested from the configured API host by page
		// number; the absolute "next" URL in the answer is only read as a
		// flag, never followed, so the token cannot be sent elsewhere.
		if body.Links.Pages.Next == "" || len(body.Droplets) == 0 {
			return out, false, nil
		}
	}
}

func (s *Server) doGet(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.doAPI()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity/"+s.Version)
	resp, err := doHTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		if errors.Is(err, netguard.ErrBlocked) {
			return badRequest("the DigitalOcean API address is an internal address this organisation may not reach")
		}
		return fmt.Errorf("DigitalOcean API: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return errDOToken
	case resp.StatusCode == 429:
		return errors.New("DigitalOcean is rate limiting this token; try again in a minute")
	case resp.StatusCode != 200:
		return fmt.Errorf("DigitalOcean API answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
		return fmt.Errorf("DigitalOcean API: unreadable answer: %w", err)
	}
	return nil
}

// doFail answers a failed call to DigitalOcean: our own refusals as usual,
// anything else as 502 with the reason (which never contains the token).
func (s *Server) doFail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errBadRequest) || errors.Is(err, context.Canceled) {
		s.fail(w, r, err)
		return
	}
	writeError(w, http.StatusBadGateway, "upstream", err.Error())
}

// doStatus: GET /integrations/digitalocean.
func (s *Server) doStatus(w http.ResponseWriter, r *http.Request) {
	connected, at, err := s.doConnected(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"connected": connected, "connected_at": at, "secrets_enabled": s.SecretBox != nil})
}

func (s *Server) doConnected(ctx context.Context) (bool, *time.Time, error) {
	list, err := s.Store.ListSecrets(ctx)
	if err != nil {
		return false, nil, err
	}
	for _, sec := range list {
		if sec.Name == doTokenSecret {
			at := sec.UpdatedAt
			return true, &at, nil
		}
	}
	return false, nil, nil
}

// doConnect: PUT /integrations/digitalocean/token. The token is checked
// against the API (it must list droplets) before it is stored.
func (s *Server) doConnect(w http.ResponseWriter, r *http.Request) {
	if s.SecretBox == nil {
		writeError(w, 409, "conflict", secrets.ErrNoKey.Error())
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		s.fail(w, r, badRequest("token is required: a DigitalOcean personal access token with read access to droplets"))
		return
	}
	var probe struct {
		Droplets []doDroplet `json:"droplets"`
	}
	if err := s.doGet(r.Context(), token, "/v2/droplets?page=1&per_page=1", &probe); err != nil {
		if errors.Is(err, errDOToken) {
			err = badRequest(errDOToken.Error())
		}
		s.doFail(w, r, err)
		return
	}
	p := principal(r)
	if err := s.Store.PutSecret(r.Context(), s.SecretBox, doTokenSecret, token, userID(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "digitalocean.connect", "secret", doTokenSecret, nil)
	w.WriteHeader(204)
}

// doDisconnect: DELETE /integrations/digitalocean/token.
func (s *Server) doDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteSecret(r.Context(), doTokenSecret); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "digitalocean.disconnect", "secret", doTokenSecret, nil)
	w.WriteHeader(204)
}

// FleetMachine is a droplet and whether Stackurity covers it.
type FleetMachine struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Region      string   `json:"region"`
	Image       string   `json:"image"`
	Tags        []string `json:"tags"`
	PublicIPv4  string   `json:"public_ipv4"`
	PrivateIPv4 string   `json:"private_ipv4"`
	PublicIPv6  string   `json:"public_ipv6"`
	// Coverage: "reporting" (a host asset reports this droplet's name),
	// "enrolled" (an agent enrolled from one of its addresses but no host
	// with its name reports), or "not_covered".
	Coverage string `json:"coverage"`
	// Match says how it was matched: "hostname" or "address".
	Match    string     `json:"match,omitempty"`
	AssetID  int64      `json:"asset_id,omitempty"`
	Asset    string     `json:"asset_name,omitempty"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
	// EnrolledAs is the hostname an agent gave when it enrolled from one of
	// the droplet's addresses.
	EnrolledAs string `json:"enrolled_as,omitempty"`
}

// doListDroplets: GET /integrations/digitalocean/droplets[?tag=].
func (s *Server) doListDroplets(w http.ResponseWriter, r *http.Request) {
	if s.SecretBox == nil {
		writeError(w, 409, "conflict", secrets.ErrNoKey.Error())
		return
	}
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	if len(tag) > 255 || strings.ContainsAny(tag, " \t\r\n") {
		s.fail(w, r, badRequest("tag is a DigitalOcean tag name"))
		return
	}
	token, err := s.Store.SecretValue(r.Context(), s.SecretBox, doTokenSecret)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 409, "not_connected", "DigitalOcean is not connected: add a read-only API token first")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	droplets, truncated, err := s.doDroplets(r.Context(), token, tag, doMaxPages)
	if errors.Is(err, errDOToken) {
		writeError(w, 409, "token_refused", errDOToken.Error()+"; replace it under Add server > DigitalOcean")
		return
	}
	if err != nil {
		s.doFail(w, r, err)
		return
	}
	hosts, err := s.Store.ReportingHosts(r.Context(), 50_000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	addrs, err := s.Store.EnrolledAddresses(r.Context(), 50_000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := matchDroplets(droplets, hosts, addrs)
	covered := 0
	for _, m := range items {
		if m.Coverage != "not_covered" {
			covered++
		}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": len(items), "covered": covered, "truncated": truncated})
}

// matchDroplets decides, for each droplet, whether a Stackurity agent
// covers it. A host asset matches when the hostname it reports equals the
// droplet's name, ignoring case and, when one of them is a full name and the
// other is not, the domain (DigitalOcean sets a new droplet's hostname to
// its name). Failing that, an enrollment from one of the droplet's public or
// private addresses counts as enrolled.
func matchDroplets(droplets []doDroplet, hosts []store.ReportingHost, addrs []store.EnrolledAddress) []FleetMachine {
	byName := map[string]store.ReportingHost{}
	byShort := map[string]store.ReportingHost{}
	for _, h := range hosts { // newest report first: keep the first seen
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h.Hostname), "."))
		if n == "" {
			continue
		}
		if _, ok := byName[n]; !ok {
			byName[n] = h
		}
		short, _, _ := strings.Cut(n, ".")
		if _, ok := byShort[short]; !ok {
			byShort[short] = h
		}
	}
	byAddr := map[string]store.EnrolledAddress{}
	for _, a := range addrs {
		if ip := net.ParseIP(a.RemoteAddr); ip != nil {
			byAddr[ip.String()] = a
		}
	}
	out := make([]FleetMachine, 0, len(droplets))
	for _, d := range droplets {
		m := FleetMachine{ID: d.ID, Name: d.Name, Status: d.Status, Region: d.Region.Slug, Tags: nonNil(d.Tags), Coverage: "not_covered"}
		m.Image = strings.TrimSpace(d.Image.Distribution + " " + d.Image.Name)
		var ips []string
		for _, a := range d.Networks.V4 {
			switch {
			case a.Type == "public" && m.PublicIPv4 == "":
				m.PublicIPv4 = a.IP
			case a.Type == "private" && m.PrivateIPv4 == "":
				m.PrivateIPv4 = a.IP
			}
			ips = append(ips, a.IP)
		}
		for _, a := range d.Networks.V6 {
			if a.Type == "public" && m.PublicIPv6 == "" {
				m.PublicIPv6 = a.IP
			}
			ips = append(ips, a.IP)
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Name), "."))
		h, ok := byName[name]
		if !ok && name != "" {
			short, _, full := strings.Cut(name, ".")
			if full {
				// A droplet named web-1.example.com whose host reports web-1.
				h, ok = byName[short]
			} else {
				// A droplet named web-1 whose host reports web-1.example.com.
				h, ok = byShort[short]
			}
		}
		if ok {
			ls := h.LastSeen
			m.Coverage, m.Match, m.AssetID, m.Asset, m.LastSeen = "reporting", "hostname", h.AssetID, h.Name, &ls
		}
		for _, raw := range ips {
			ip := net.ParseIP(raw)
			if ip == nil {
				continue
			}
			if a, ok := byAddr[ip.String()]; ok {
				m.EnrolledAs = a.Hostname
				if m.Coverage == "not_covered" {
					m.Coverage, m.Match = "enrolled", "address"
				}
				break
			}
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Coverage == "not_covered") != (out[j].Coverage == "not_covered") {
			return out[i].Coverage == "not_covered"
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}
