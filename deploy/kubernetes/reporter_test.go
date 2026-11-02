// Package kubernetes holds the manifests for connecting a cluster. These
// tests keep the reporter's Helm chart (deploy/helm/stackurity-reporter)
// and the manifest the server serves (/install/kubernetes.yaml) in step
// with each other and with the RBAC rules the code needs
// (plugins/kubernetes/kube/rbac_test.go checks the rules files against the
// API calls the code makes).
//
// helm is not needed: the chart is rendered with Go's text/template and the
// few Helm and Sprig functions it uses. When helm is on PATH the same
// renders are checked with helm template too (CI's helm job lints and
// renders the chart as well).
package kubernetes

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"text/template"

	"go.yaml.in/yaml/v3"

	"github.com/stackurity/stackurity/internal/api"
)

const chartDir = "../helm/stackurity-reporter"

// --- a minimal Helm

type files struct{ dir string }

func (f files) Get(name string) string {
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		return ""
	}
	return string(b)
}

type release struct{ Name, Namespace, Service string }

func strval(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func empty(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String, reflect.Slice, reflect.Map:
		return rv.Len() == 0
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int64, reflect.Float64:
		return rv.IsZero()
	}
	return false
}

func toYAML(v any) string {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func indent(n int, s string) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

// render renders the chart's templates the way helm template does, with
// values.yaml under set (nested maps), and returns the manifest.
func render(t *testing.T, releaseName string, set map[string]any) (string, error) {
	t.Helper()
	var values map[string]any
	raw, err := os.ReadFile(filepath.Join(chartDir, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	merge(values, set)
	var chart struct {
		Name       string `yaml:"name"`
		AppVersion string `yaml:"appVersion"`
	}
	raw, _ = os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err := yaml.Unmarshal(raw, &chart); err != nil {
		t.Fatal(err)
	}
	root := template.New("chart").Option("missingkey=zero")
	funcs := template.FuncMap{
		"include": func(name string, data any) (string, error) {
			var b bytes.Buffer
			err := root.ExecuteTemplate(&b, name, data)
			return b.String(), err
		},
		"quote":   func(v any) string { return fmt.Sprintf("%q", strval(v)) },
		"nindent": func(n int, s string) string { return "\n" + indent(n, s) },
		"toYaml":  toYAML,
		"required": func(msg string, v any) (any, error) {
			if empty(v) {
				return nil, errors.New(msg)
			}
			return v, nil
		},
		"fail": func(msg string) (string, error) { return "", errors.New(msg) },
		"default": func(d any, v ...any) any {
			if len(v) == 0 || empty(v[0]) {
				return d
			}
			return v[0]
		},
		"trunc": func(n int, s string) string {
			if len(s) > n {
				return s[:n]
			}
			return s
		},
		"trimSuffix": func(suf, s string) string { return strings.TrimSuffix(s, suf) },
		"contains":   func(sub, s string) bool { return strings.Contains(s, sub) },
		"hasPrefix":  func(p, s string) bool { return strings.HasPrefix(s, p) },
		"join": func(sep string, v any) string {
			var out []string
			for _, x := range v.([]any) {
				out = append(out, strval(x))
			}
			return strings.Join(out, sep)
		},
	}
	root.Funcs(funcs)
	names, _ := filepath.Glob(filepath.Join(chartDir, "templates", "*"))
	sort.Strings(names)
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := root.New(filepath.Base(n)).Parse(string(b)); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	data := map[string]any{
		"Values":  values,
		"Release": release{Name: releaseName, Namespace: "stackurity", Service: "Helm"},
		"Chart":   map[string]any{"Name": chart.Name, "AppVersion": chart.AppVersion},
		"Files":   files{dir: chartDir},
	}
	var out strings.Builder
	for _, n := range names {
		base := filepath.Base(n)
		if strings.HasPrefix(base, "_") || base == "NOTES.txt" {
			continue
		}
		var b bytes.Buffer
		if err := root.ExecuteTemplate(&b, base, data); err != nil {
			return "", err
		}
		out.WriteString("---\n# Source: " + base + "\n" + b.String() + "\n")
	}
	return out.String(), nil
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		if m, ok := v.(map[string]any); ok {
			if d, ok := dst[k].(map[string]any); ok {
				merge(d, m)
				continue
			}
		}
		dst[k] = v
	}
}

// helmTemplate renders with the real helm when it is installed.
func helmTemplate(t *testing.T, releaseName string, args ...string) (string, bool) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		return "", false
	}
	cmd := exec.Command(helm, append([]string{"template", releaseName, chartDir, "--namespace", "stackurity"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	return string(out), true
}

// --- reading manifests

type object struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Namespace   string            `yaml:"namespace"`
		Labels      map[string]string `yaml:"labels"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Rules      []rule            `yaml:"rules"`
	StringData map[string]string `yaml:"stringData"`
	Data       map[string]string `yaml:"data"`
	RoleRef    struct {
		Kind string `yaml:"kind"`
		Name string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		Kind      string `yaml:"kind"`
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"subjects"`
	Spec struct {
		Replicas int `yaml:"replicas"`
		Strategy struct {
			Type string `yaml:"type"`
		} `yaml:"strategy"`
		Template struct {
			Spec struct {
				ServiceAccountName           string `yaml:"serviceAccountName"`
				AutomountServiceAccountToken *bool  `yaml:"automountServiceAccountToken"`
				SecurityContext              struct {
					RunAsNonRoot bool `yaml:"runAsNonRoot"`
				} `yaml:"securityContext"`
				Containers []struct {
					Image string   `yaml:"image"`
					Args  []string `yaml:"args"`
					Env   []struct {
						Name  string `yaml:"name"`
						Value string `yaml:"value"`
					} `yaml:"env"`
					SecurityContext struct {
						AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
						ReadOnlyRootFilesystem   bool  `yaml:"readOnlyRootFilesystem"`
						Capabilities             struct {
							Drop []string `yaml:"drop"`
						} `yaml:"capabilities"`
					} `yaml:"securityContext"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type rule struct {
	APIGroups       []string `yaml:"apiGroups"`
	Resources       []string `yaml:"resources"`
	ResourceNames   []string `yaml:"resourceNames"`
	NonResourceURLs []string `yaml:"nonResourceURLs"`
	Verbs           []string `yaml:"verbs"`
}

func parse(t *testing.T, manifest string) []object {
	t.Helper()
	var out []object
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	for {
		var o object
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("not YAML: %v\n%s", err, manifest)
		}
		if o.Kind != "" {
			out = append(out, o)
		}
	}
}

func find(objs []object, kind, name string) *object {
	for i := range objs {
		if objs[i].Kind == kind && (name == "" || objs[i].Metadata.Name == name) {
			return &objs[i]
		}
	}
	return nil
}

func count(objs []object, kind string) int {
	n := 0
	for _, o := range objs {
		if o.Kind == kind {
			n++
		}
	}
	return n
}

func rulesFile(t *testing.T, name string) []rule {
	t.Helper()
	var r []rule
	raw, err := os.ReadFile(filepath.Join(chartDir, "files", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func env(o *object) map[string]string {
	m := map[string]string{}
	for _, e := range o.Spec.Template.Spec.Containers[0].Env {
		m[e.Name] = e.Value
	}
	return m
}

// checkReporter checks what every way of installing has in common: one
// reporter running the image's kubernetes-reporter, unprivileged, with its
// own service account, reading and updating only its own Secret.
func checkReporter(t *testing.T, objs []object, secret string) *object {
	t.Helper()
	d := find(objs, "Deployment", "")
	if d == nil {
		t.Fatal("no Deployment")
	}
	ps := d.Spec.Template.Spec
	c := ps.Containers[0]
	if d.Spec.Replicas != 1 || d.Spec.Strategy.Type != "Recreate" || !reflect.DeepEqual(c.Args, []string{"kubernetes-reporter"}) {
		t.Errorf("deployment: replicas %d, strategy %q, args %v", d.Spec.Replicas, d.Spec.Strategy.Type, c.Args)
	}
	if !ps.SecurityContext.RunAsNonRoot || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation ||
		!c.SecurityContext.ReadOnlyRootFilesystem || !reflect.DeepEqual(c.SecurityContext.Capabilities.Drop, []string{"ALL"}) {
		t.Errorf("container security context = %+v", c.SecurityContext)
	}
	if ps.AutomountServiceAccountToken == nil || !*ps.AutomountServiceAccountToken {
		t.Error("the reporter needs its service account token")
	}
	if find(objs, "ServiceAccount", ps.ServiceAccountName) == nil {
		t.Errorf("service account %q not created", ps.ServiceAccountName)
	}
	if e := env(d); e["STACKURITY_REPORTER_SECRET"] != secret {
		t.Errorf("STACKURITY_REPORTER_SECRET = %q, want %q", e["STACKURITY_REPORTER_SECRET"], secret)
	}
	// Every binding is to the reporter's service account, in its namespace.
	for _, o := range objs {
		if o.Kind == "RoleBinding" || o.Kind == "ClusterRoleBinding" {
			if len(o.Subjects) != 1 || o.Subjects[0].Kind != "ServiceAccount" || o.Subjects[0].Name != ps.ServiceAccountName || o.Subjects[0].Namespace != "stackurity" {
				t.Errorf("%s %s binds %+v", o.Kind, o.Metadata.Name, o.Subjects)
			}
			if find(objs, o.RoleRef.Kind, o.RoleRef.Name) == nil {
				t.Errorf("%s %s refers to %s %s, which is not in the manifest", o.Kind, o.Metadata.Name, o.RoleRef.Kind, o.RoleRef.Name)
			}
		}
	}
	// The one Role in the reporter's namespace that touches Secrets.
	want := []rule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{secret}, Verbs: []string{"get", "update"}}}
	n := 0
	for _, o := range objs {
		for _, r := range o.Rules {
			for _, res := range r.Resources {
				if res == "secrets" {
					n++
					if o.Kind != "Role" || o.Metadata.Namespace != "stackurity" || !reflect.DeepEqual(o.Rules, want) {
						t.Errorf("%s %s/%s grants %+v", o.Kind, o.Metadata.Namespace, o.Metadata.Name, o.Rules)
					}
				}
			}
		}
	}
	if n != 1 {
		t.Errorf("%d rules on Secrets, want 1", n)
	}
	return d
}

func TestChartClusterWide(t *testing.T) {
	set := map[string]any{"server": "https://stackurity.example.com", "enrollCode": "enr_test", "clusterName": "prod-eu"}
	out, err := render(t, "stackurity-reporter", set)
	if err != nil {
		t.Fatal(err)
	}
	objs := parse(t, out)
	d := checkReporter(t, objs, "stackurity-reporter")
	cr := find(objs, "ClusterRole", "stackurity-reporter")
	if cr == nil || !reflect.DeepEqual(cr.Rules, rulesFile(t, "rbac-cluster.yaml")) || count(objs, "ClusterRole") != 1 {
		t.Errorf("cluster role = %+v", cr)
	}
	sec := find(objs, "Secret", "stackurity-reporter")
	if sec == nil || sec.StringData["enroll-code"] != "enr_test" || sec.Data != nil {
		t.Errorf("secret = %+v", sec)
	}
	e := env(d)
	if e["STACKURITY_SERVER"] != "https://stackurity.example.com" || e["STACKURITY_CLUSTER_NAME"] != "prod-eu" || e["STACKURITY_ALLOW_HTTP"] != "" ||
		e["STACKURITY_INTERVAL"] != "1h" || e["STACKURITY_IMAGE_SCANS"] != "25" || e["STACKURITY_MAX_IMAGES"] != "300" {
		t.Errorf("env = %v", e)
	}
	raw, _ := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	_ = yaml.Unmarshal(raw, &chart)
	if img := d.Spec.Template.Spec.Containers[0].Image; img != "ghcr.io/stackurity/stackurity:"+chart.AppVersion {
		t.Errorf("image = %s", img)
	}

	if h, ok := helmTemplate(t, "stackurity-reporter", "--set", "server=https://stackurity.example.com", "--set", "enrollCode=enr_test", "--set", "clusterName=prod-eu"); ok {
		hobjs := parse(t, h)
		checkReporter(t, hobjs, "stackurity-reporter")
		if cr := find(hobjs, "ClusterRole", "stackurity-reporter"); cr == nil || !reflect.DeepEqual(cr.Rules, rulesFile(t, "rbac-cluster.yaml")) {
			t.Errorf("helm template: cluster role = %+v", cr)
		}
		if !reflect.DeepEqual(env(find(hobjs, "Deployment", "")), e) {
			t.Errorf("helm template env %v, this render %v", env(find(hobjs, "Deployment", "")), e)
		}
	} else {
		t.Log("helm is not installed: checked the Go render only")
	}
}

func TestChartNamespaced(t *testing.T) {
	set := map[string]any{"server": "https://stackurity.example.com", "rbac": map[string]any{"clusterWide": false}, "namespaces": []any{"shop", "blog"}}
	out, err := render(t, "stackurity-reporter", set)
	if err != nil {
		t.Fatal(err)
	}
	objs := parse(t, out)
	d := checkReporter(t, objs, "stackurity-reporter")
	if count(objs, "ClusterRole") != 1 || find(objs, "ClusterRole", "stackurity-reporter-identity") == nil ||
		!reflect.DeepEqual(find(objs, "ClusterRole", "").Rules, rulesFile(t, "rbac-identity.yaml")) {
		t.Errorf("namespaced install: cluster roles %+v", find(objs, "ClusterRole", ""))
	}
	got := map[string]bool{}
	for _, o := range objs {
		if o.Kind == "Role" && o.Metadata.Name == "stackurity-reporter" {
			got[o.Metadata.Namespace] = true
			if !reflect.DeepEqual(o.Rules, rulesFile(t, "rbac-namespace.yaml")) {
				t.Errorf("role in %s = %+v", o.Metadata.Namespace, o.Rules)
			}
		}
	}
	if len(got) != 2 || !got["shop"] || !got["blog"] {
		t.Errorf("roles in %v", got)
	}
	if env(d)["STACKURITY_NAMESPACES"] != "shop,blog" {
		t.Errorf("env = %v", env(d))
	}
	// Without an enrollment code the Secret is created empty, for the code
	// to be patched in; the reporter waits for it.
	if sec := find(objs, "Secret", ""); sec == nil || sec.StringData != nil {
		t.Errorf("secret = %+v", sec)
	}
}

func TestChartOptions(t *testing.T) {
	// Another release name, and a Secret made elsewhere: names follow.
	out, err := render(t, "lab", map[string]any{"server": "https://s.example.com", "secret": map[string]any{"create": false, "name": "sealed-reporter"}})
	if err != nil {
		t.Fatal(err)
	}
	objs := parse(t, out)
	checkReporter(t, objs, "sealed-reporter")
	if find(objs, "Secret", "") != nil || find(objs, "Deployment", "lab-stackurity-reporter") == nil {
		t.Error("secret.create=false or the release name not applied")
	}
	for _, tc := range []struct {
		set  map[string]any
		want string
	}{
		{map[string]any{}, "server is required"},
		{map[string]any{"server": "http://s.example.com"}, "https://"},
		{map[string]any{"server": "https://s.example.com", "rbac": map[string]any{"clusterWide": false}}, "needs namespaces"},
	} {
		if _, err := render(t, "stackurity-reporter", tc.set); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.set, err, tc.want)
		}
	}
	out, err = render(t, "stackurity-reporter", map[string]any{"server": "http://localhost:8080", "allowHTTP": true})
	if err != nil {
		t.Fatal(err)
	}
	if env(find(parse(t, out), "Deployment", ""))["STACKURITY_ALLOW_HTTP"] != "1" {
		t.Error("allowHTTP not passed on")
	}
}

// The manifest the server serves has the chart's RBAC, word for word.
func TestServedManifestMatchesChart(t *testing.T) {
	p := api.KubernetesManifestParams{Server: "https://stackurity.example.com", Image: "ghcr.io/stackurity/stackurity:1.2.3", ClusterName: "prod-eu"}
	out, err := api.RenderKubernetesManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	objs := parse(t, string(out))
	d := checkReporter(t, objs, "stackurity-reporter")
	if cr := find(objs, "ClusterRole", ""); cr == nil || !reflect.DeepEqual(cr.Rules, rulesFile(t, "rbac-cluster.yaml")) || count(objs, "ClusterRole") != 1 {
		t.Errorf("served cluster role = %+v", cr)
	}
	if find(objs, "Secret", "") != nil {
		t.Error("the served manifest must not carry the Secret (it would hold the code)")
	}
	if e := env(d); e["STACKURITY_SERVER"] != p.Server || e["STACKURITY_CLUSTER_NAME"] != "prod-eu" || e["STACKURITY_ALLOW_HTTP"] != "" {
		t.Errorf("env = %v", e)
	}

	p.Namespaces = []string{"shop", "blog"}
	out, err = api.RenderKubernetesManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	objs = parse(t, string(out))
	checkReporter(t, objs, "stackurity-reporter")
	if cr := find(objs, "ClusterRole", ""); cr == nil || !reflect.DeepEqual(cr.Rules, rulesFile(t, "rbac-identity.yaml")) || count(objs, "ClusterRole") != 1 {
		t.Errorf("served identity role = %+v", cr)
	}
	n := 0
	for _, o := range objs {
		if o.Kind == "Role" && o.Metadata.Name == "stackurity-reporter" {
			n++
			if !reflect.DeepEqual(o.Rules, rulesFile(t, "rbac-namespace.yaml")) {
				t.Errorf("served role in %s = %+v", o.Metadata.Namespace, o.Rules)
			}
		}
	}
	if n != 2 {
		t.Errorf("%d namespaced roles", n)
	}
}

// The pull-mode reader (stackurity-reader.yaml) still grants at least what
// the collection needs.
func TestReaderCoversCollection(t *testing.T) {
	objs := parse(t, readFile(t, "stackurity-reader.yaml"))
	cr := find(objs, "ClusterRole", "stackurity-reader")
	has := map[string]bool{}
	for _, r := range cr.Rules {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					has[v+" "+g+"/"+res] = true
				}
			}
		}
	}
	for _, r := range rulesFile(t, "rbac-cluster.yaml") {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					if !has[v+" "+g+"/"+res] {
						t.Errorf("stackurity-reader.yaml does not grant %s %s/%s", v, g, res)
					}
				}
			}
		}
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
