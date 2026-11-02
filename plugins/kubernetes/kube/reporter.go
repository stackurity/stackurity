package kube

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/stackurity/stackurity/pkg/plugin"
)

// CollectorID is the collector both modes report under, so a cluster that
// moves from the plugin (pull) to stackurity kubernetes-reporter (push), or
// back, keeps one inventory history.
const CollectorID = "plugin:kubernetes"

// Version is the version of the collection code, reported with each batch.
const Version = "0.1.0"

// Settings is what to collect (the plugin's config).
type Settings = settings

// Client is a connection to one API server.
type Client = client

// ParseSettings checks settings given as the plugin's JSON config.
func ParseSettings(raw json.RawMessage) (Settings, []string) { return parse(raw) }

// inClusterNamespaceFile names the namespace the pod runs in.
var inClusterNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// InCluster connects with the service account of the pod this runs in,
// to https://kubernetes.default.svc, verified against the cluster CA.
func InCluster(ctx context.Context, userAgent string) (*Client, error) {
	conn, err := inClusterConnection()
	if err != nil {
		return nil, err
	}
	return NewClient(ctx, conn.server, conn.token, conn.caPEM, userAgent)
}

// NewClient connects to server (https) with a bearer token, verifying TLS
// against caPEM (nil: the system roots).
func NewClient(ctx context.Context, server, token string, caPEM []byte, userAgent string) (*Client, error) {
	c, err := newClient(ctx, &connection{server: server, token: token, caPEM: caPEM})
	if err != nil {
		return nil, err
	}
	c.ua = userAgent
	return c, nil
}

// PodNamespace is the namespace of the pod this runs in.
func PodNamespace() (string, error) {
	b, err := os.ReadFile(inClusterNamespaceFile)
	if err != nil {
		return "", err
	}
	ns := strings.TrimSpace(string(b))
	if !namespaceRE.MatchString(ns) {
		return "", errors.New("the service account namespace file does not name a namespace")
	}
	return ns, nil
}

// Collect reads the cluster and returns its batches in the order they must
// be ingested: the cluster, then its images, then its workloads. Each is
// stamped with CollectorID and Version.
func Collect(ctx context.Context, c *Client, s Settings) ([]*plugin.ObservationBatch, error) {
	snap, err := read(ctx, c, s)
	if err != nil {
		return nil, err
	}
	bs := snap.batches()
	for _, b := range bs {
		b.Collector.ID, b.Collector.Version = CollectorID, Version
	}
	return bs, nil
}

// IsNotFound, IsConflict, IsForbidden and IsUnauthorized classify an API
// server's answer.
func IsNotFound(err error) bool     { return isStatus(err, 404) }
func IsConflict(err error) bool     { return isStatus(err, 409) }
func IsForbidden(err error) bool    { return isStatus(err, 403) }
func IsUnauthorized(err error) bool { return isStatus(err, 401) }
