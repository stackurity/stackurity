package api

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
	"github.com/stackurity/stackurity/internal/why"
)

// TestOpenAPIAuthSchemas: the sign-in and account operations, the asset and
// finding lists, finding detail and the fix (action plan) operations publish
// real request and response bodies, not a bare {"type": "object"} that tells
// an API reader nothing (UI review R003-31). Where the body is a named Go type,
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
		{"get", "/findings/{id}", false},
		{"get", "/fix-groups", false},
		{"get", "/fix-groups/{id}", false},
		{"get", "/fix-groups/summary", false},
		{"get", "/fix-groups/work", false},
		{"post", "/fix-groups/{id}/applied", false},
		{"get", "/settings/fix-grouping", false},
		{"put", "/settings/fix-grouping", true},
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
	for _, path := range []string{"/auth/logout", "/fix-groups/{id}/applied", "/fix-groups/{id}/check"} {
		if _, ok := spec.Paths[path]["post"]["requestBody"]; ok {
			t.Errorf("POST %s reads no body; the spec should not ask for one", path)
		}
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

		"Advisory":              reflect.TypeFor[store.Advisory](),
		"Explanation":           reflect.TypeFor[why.Explanation](),
		"WhyInstalled":          reflect.TypeFor[why.Installed](),
		"WhySource":             reflect.TypeFor[why.Source](),
		"WhyRule":               reflect.TypeFor[why.Rule](),
		"UpgradeRecommendation": reflect.TypeFor[upgrade.Recommendation](),
		"SupportLine":           reflect.TypeFor[upgrade.Line](),
		"FixGroup":              reflect.TypeFor[fixplan.Group](),
		"FixPlace":              reflect.TypeFor[fixplan.Place](),
		"FixGroupList":          reflect.TypeFor[list[fixplan.Group]](),
		"FixOwner":              reflect.TypeFor[store.OwnerCount](),
		"FixWork":               reflect.TypeFor[store.FixWork](),
		"FixGrouping":           reflect.TypeFor[fixGroupingBody](),
		"FixFocus":              reflect.TypeFor[store.FixFocus](),
		"FocusAsset":            reflect.TypeFor[store.FocusAsset](),
		// GET /fix-groups/summary: store.FixPlanSummary's fields and focus.
		"FixPlanSummary": reflect.StructOf(append(fields(reflect.TypeFor[store.FixPlanSummary]()),
			reflect.StructField{Name: "Focus", Type: reflect.TypeFor[store.FixFocus](), Tag: `json:"focus"`})),
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

// fields returns a struct type's fields, for building the type of a body
// that embeds it.
func fields(t reflect.Type) []reflect.StructField {
	out := make([]reflect.StructField, t.NumField())
	for i := range out {
		out[i] = t.Field(i)
	}
	return out
}
