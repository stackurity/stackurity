package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/stackurity/stackurity/pkg/plugin"
)

// The service account files a pod is given; used with in_cluster.
var (
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

const inClusterServer = "https://kubernetes.default.svc"

// maxPage bounds one API response; lists are paged with limit=500.
const maxPage = 64 << 20

// client is a minimal read-only Kubernetes API client: GET requests with a
// bearer token or client certificate, TLS verified against the cluster CA.
type client struct {
	base    *url.URL
	http    *http.Client
	token   string
	cluster string // name from the kubeconfig, when there is one
}

// apiError is a non-2xx answer from the API server.
type apiError struct {
	Code    int
	Message string
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("HTTP %d", e.Code)
}

func isStatus(err error, code int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Code == code
}

// kubeconfig is the subset of a kubeconfig file the plugin understands.
type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			TLSServerName            string `yaml:"tls-server-name"`
			ProxyURL                 string `yaml:"proxy-url"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string         `yaml:"token"`
			TokenFile             string         `yaml:"tokenFile"`
			ClientCertificateData string         `yaml:"client-certificate-data"`
			ClientKeyData         string         `yaml:"client-key-data"`
			ClientCertificate     string         `yaml:"client-certificate"`
			ClientKey             string         `yaml:"client-key"`
			Username              string         `yaml:"username"`
			Exec                  map[string]any `yaml:"exec"`
			AuthProvider          map[string]any `yaml:"auth-provider"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// connection is everything needed to reach one API server.
type connection struct {
	server     string
	caPEM      []byte // nil: system roots
	serverName string
	token      string
	certPEM    []byte
	keyPEM     []byte
	cluster    string
}

// fromKubeconfig picks a context (the named one, or the current one) and
// returns its connection. Only embedded credentials are accepted: the plugin
// never runs exec credential helpers and cannot read files the kubeconfig
// points to.
func fromKubeconfig(raw, contextName string) (*connection, error) {
	var kc kubeconfig
	if err := yaml.Unmarshal([]byte(raw), &kc); err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	if contextName == "" {
		contextName = kc.CurrentContext
	}
	if contextName == "" && len(kc.Contexts) == 1 {
		contextName = kc.Contexts[0].Name
	}
	var clusterName, userName string
	found := false
	for _, c := range kc.Contexts {
		if c.Name == contextName {
			clusterName, userName, found = c.Context.Cluster, c.Context.User, true
		}
	}
	if !found {
		return nil, fmt.Errorf("kubeconfig: context %q not found", contextName)
	}
	conn := &connection{cluster: clusterName}
	found = false
	for _, c := range kc.Clusters {
		if c.Name != clusterName {
			continue
		}
		found = true
		cl := c.Cluster
		switch {
		case cl.InsecureSkipTLSVerify:
			return nil, errors.New("kubeconfig: insecure-skip-tls-verify is not supported; include certificate-authority-data")
		case cl.CertificateAuthority != "":
			return nil, errors.New("kubeconfig: certificate-authority points to a file; embed it as certificate-authority-data (kubectl config view --raw --flatten)")
		case cl.ProxyURL != "":
			return nil, errors.New("kubeconfig: proxy-url is not supported")
		}
		conn.server, conn.serverName = cl.Server, cl.TLSServerName
		if cl.CertificateAuthorityData != "" {
			ca, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cl.CertificateAuthorityData))
			if err != nil {
				return nil, errors.New("kubeconfig: certificate-authority-data is not base64")
			}
			conn.caPEM = ca
		}
	}
	if !found {
		return nil, fmt.Errorf("kubeconfig: cluster %q not found", clusterName)
	}
	found = false
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		found = true
		us := u.User
		switch {
		case len(us.Exec) > 0 || len(us.AuthProvider) > 0:
			return nil, errors.New("kubeconfig: exec and auth-provider credentials are not supported (the plugin never runs commands); use a service account token")
		case us.TokenFile != "" || us.ClientCertificate != "" || us.ClientKey != "":
			return nil, errors.New("kubeconfig: credentials point to files; embed them (token, client-certificate-data, client-key-data)")
		case us.Username != "":
			return nil, errors.New("kubeconfig: basic authentication is not supported; use a service account token")
		}
		conn.token = us.Token
		if us.ClientCertificateData != "" || us.ClientKeyData != "" {
			cert, err1 := base64.StdEncoding.DecodeString(strings.TrimSpace(us.ClientCertificateData))
			key, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(us.ClientKeyData))
			if err1 != nil || err2 != nil {
				return nil, errors.New("kubeconfig: client-certificate-data and client-key-data must be base64")
			}
			conn.certPEM, conn.keyPEM = cert, key
		}
	}
	if !found {
		return nil, fmt.Errorf("kubeconfig: user %q not found", userName)
	}
	if conn.token == "" && conn.certPEM == nil {
		return nil, errors.New("kubeconfig: the user has no token or client certificate")
	}
	return conn, nil
}

// connect works out how to reach the cluster: a kubeconfig secret, a token
// secret with server from config, or the pod's own service account.
func connect(ctx context.Context, s settings, secrets map[string]string) (*client, error) {
	var conn *connection
	var err error
	switch {
	case secrets["kubeconfig"] != "":
		if conn, err = fromKubeconfig(secrets["kubeconfig"], s.Context); err != nil {
			return nil, err
		}
	case secrets["token"] != "":
		if s.Server == "" {
			return nil, errors.New("a token secret needs server in the config")
		}
		conn = &connection{server: s.Server, token: strings.TrimSpace(secrets["token"])}
		if ca := secrets["ca_cert"]; ca != "" {
			conn.caPEM = []byte(ca)
		}
	case s.InCluster:
		// The service account belongs to the Stackurity server itself, so
		// only workspaces allowed to reach internal networks may use it.
		if !plugin.AllowsPrivate(ctx) {
			return nil, errors.New("in_cluster uses the server's own service account, which this workspace may not use; store a kubeconfig or token secret")
		}
		tok, err := os.ReadFile(inClusterTokenFile)
		if err != nil {
			return nil, fmt.Errorf("in_cluster: %w (is a service account token mounted?)", err)
		}
		ca, err := os.ReadFile(inClusterCAFile)
		if err != nil {
			return nil, fmt.Errorf("in_cluster: %w", err)
		}
		conn = &connection{server: inClusterServer, token: strings.TrimSpace(string(tok)), caPEM: ca}
	default:
		return nil, errors.New("no credentials: store a kubeconfig or token secret, or set in_cluster")
	}
	return newClient(ctx, conn)
}

func newClient(ctx context.Context, conn *connection) (*client, error) {
	u, err := url.Parse(conn.server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		// The URL is not quoted: it may carry credentials.
		return nil, errors.New("the API server must be an https:// URL without credentials")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: conn.serverName}
	if conn.caPEM != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(conn.caPEM) {
			return nil, errors.New("the cluster CA certificate is not valid PEM")
		}
		tc.RootCAs = pool
	}
	if conn.certPEM != nil {
		cert, err := tls.X509KeyPair(conn.certPEM, conn.keyPEM)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	tr := &http.Transport{
		TLSClientConfig:     tc,
		DialContext:         plugin.Dialer(ctx),
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConnsPerHost: 4,
		ForceAttemptHTTP2:   true,
	}
	return &client{
		base: u, token: conn.token, cluster: conn.cluster,
		http: &http.Client{Transport: tr, Timeout: 2 * time.Minute,
			// The API server does not redirect GETs; refuse rather than
			// follow one somewhere the dial policy has not seen.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// get reads one JSON document from the API server.
func (c *client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := *c.base
	u.Path += path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity-kubernetes-plugin")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, maxPage+1)
	if resp.StatusCode != http.StatusOK {
		var st struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(body, 64<<10)).Decode(&st)
		msg := st.Message
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return &apiError{Code: resp.StatusCode, Message: msg}
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if len(data) > maxPage {
		return fmt.Errorf("%s: response larger than %d MiB", path, maxPage>>20)
	}
	return json.Unmarshal(data, out)
}

// list reads every page of a collection.
func list[T any](ctx context.Context, c *client, path string) ([]T, error) {
	var out []T
	cont := ""
	for page := 0; page < 1000; page++ {
		q := url.Values{"limit": {"500"}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var l struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := c.get(ctx, path, q, &l); err != nil {
			return nil, err
		}
		out = append(out, l.Items...)
		if cont = l.Metadata.Continue; cont == "" {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%s: too many pages", path)
}
