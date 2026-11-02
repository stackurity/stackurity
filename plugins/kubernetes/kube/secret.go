package kube

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
)

// Secret is one Secret, kept whole (labels, annotations, owner) so an
// update changes only the keys the reporter sets.
type Secret struct {
	raw map[string]any
}

// GetSecret reads one Secret by name. The reporter reads only its own,
// which is all its Role allows.
func (c *client) GetSecret(ctx context.Context, namespace, name string) (*Secret, error) {
	if !namespaceRE.MatchString(namespace) || !namespaceRE.MatchString(name) {
		return nil, errors.New("invalid Secret namespace or name")
	}
	s := &Secret{}
	if err := c.get(ctx, secretPath(namespace, name), nil, &s.raw); err != nil {
		return nil, err
	}
	return s, nil
}

// UpdateSecret replaces the Secret with s (PUT, update verb). The
// resourceVersion read with it makes a concurrent change fail with 409
// (IsConflict) instead of being overwritten.
func (c *client) UpdateSecret(ctx context.Context, s *Secret) error {
	md, _ := s.raw["metadata"].(map[string]any)
	ns, _ := md["namespace"].(string)
	name, _ := md["name"].(string)
	if !namespaceRE.MatchString(ns) || !namespaceRE.MatchString(name) {
		return errors.New("invalid Secret namespace or name")
	}
	var out map[string]any
	if err := c.do(ctx, http.MethodPut, secretPath(ns, name), nil, s.raw, &out); err != nil {
		return err
	}
	s.raw = out
	return nil
}

func secretPath(namespace, name string) string {
	return "/api/v1/namespaces/" + namespace + "/secrets/" + name
}

// Get returns the value of key, decoded.
func (s *Secret) Get(key string) string {
	data, _ := s.raw["data"].(map[string]any)
	v, _ := data[key].(string)
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// Set sets key; an empty value removes it.
func (s *Secret) Set(key, value string) {
	data, _ := s.raw["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	if value == "" {
		delete(data, key)
	} else {
		data[key] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	s.raw["data"] = data
	delete(s.raw, "stringData")
}
