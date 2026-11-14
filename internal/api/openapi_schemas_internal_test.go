package api

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// TestOpenAPIAuthSchemas: the sign-in and account operations, and the asset
// and finding lists, publish real request and response bodies, not a bare {"type": "object"} that tells an
// API reader nothing (UI review R003-31). Where the body is a named Go type,
// its JSON fields and the schema's properties must be the same set, so the
// reference cannot drift from the code.
func TestOpenAPIAuthSchemas(t *testing.T) {
	var spec struct {
		Paths      map[string]map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatal(err)
	}
	generic := func(s any) bool {
		m, ok := s.(map[string]any)
		return !ok || (len(m) == 1 && m["type"] == "object")
	}
	schemaAt := func(op map[string]any, keys ...string) any {
		var cur any = op
		for _, k := range keys {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = m[k]
		}
		return cur
	}
	for _, c := range []struct {
		method, path string
		request      bool
	}{
		{"post", "/auth/login", true},
		{"post", "/auth/mfa/verify", true},
		{"post", "/auth/password", true},
		{"get", "/auth/me", false},
		{"get", "/assets", false},
		{"get", "/assets/{id}", false},
		{"get", "/findings", false},
	} {
		op := spec.Paths[c.path][c.method]
		where := strings.ToUpper(c.method) + " " + c.path
		if op == nil {
			t.Errorf("%s is not in openapi.json", where)
			continue
		}
		if c.request && generic(schemaAt(op, "requestBody", "content", "application/json", "schema")) {
			t.Errorf("%s: the request body is a bare object; describe its fields", where)
		}
		if generic(schemaAt(op, "responses", "2XX", "content", "application/json", "schema")) {
			t.Errorf("%s: the success response is a bare object; describe its fields", where)
		}
	}
	if _, ok := spec.Paths["/auth/logout"]["post"]["requestBody"]; ok {
		t.Error("POST /auth/logout reads no body; the spec should not ask for one")
	}

	for name, typ := range map[string]reflect.Type{
		"User":         reflect.TypeFor[store.User](),
		"LoginRequest": reflect.TypeFor[loginRequest](),
		"Asset":        reflect.TypeFor[store.Asset](),
		"ProjectRef":   reflect.TypeFor[store.ProjectRef](),
		"Reporting":    reflect.TypeFor[store.Reporting](),
		"Identifier":   reflect.TypeFor[store.Identifier](),
		"Finding":      reflect.TypeFor[store.Finding](),
		"FindingVEX":   reflect.TypeFor[store.FindingVEX](),
		"AssetList":    reflect.TypeFor[list[store.Asset]](),
	} {
		props, _ := spec.Components.Schemas[name]["properties"].(map[string]any)
		var got, want []string
		for k := range props {
			got = append(got, k)
		}
		for i := range typ.NumField() {
			if tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ","); tag != "" && tag != "-" {
				want = append(want, tag)
			}
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("components.schemas.%s has properties %v; %s has JSON fields %v", name, got, typ, want)
		}
	}
}
