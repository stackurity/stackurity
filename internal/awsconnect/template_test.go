package awsconnect

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite deploy/aws from the generated template")

// The exact actions the role grants: what the aws-managed plugin calls
// (plugins/aws-managed: TestPermissionsMatchTemplate checks its metadata
// against ReadOnlyActions) and, opted in, the three SSM actions.
var (
	wantReadOnly = []string{
		"eks:DescribeCluster", "eks:ListClusters", "elasticache:DescribeCacheClusters", "es:DescribeDomains", "es:ListDomainNames",
		"lambda:ListFunctions", "rds:DescribeDBClusters", "rds:DescribeDBInstances",
	}
	wantAgentInstall = []string{"ssm:DescribeInstanceInformation", "ssm:GetCommandInvocation", "ssm:SendCommand"}
)

type tmpl map[string]any

func get(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

// policyProblems checks a parsed template the way a reviewer would: the
// role's trust policy, the exact actions of each policy, no wildcard
// actions, and the agent install behind its parameter.
func policyProblems(t map[string]any) []string {
	var p []string
	role := get(t, "Resources", "StackurityRole", "Properties")
	if role == nil {
		return []string{"no StackurityRole"}
	}
	trust, _ := get(role, "AssumeRolePolicyDocument", "Statement").([]any)
	if len(trust) != 1 {
		p = append(p, "trust policy must have exactly one statement")
	}
	for _, st := range trust {
		if !reflect.DeepEqual(get(st, "Principal"), map[string]any{"AWS": map[string]any{"Ref": "StackurityPrincipal"}}) {
			p = append(p, "trust principal is not the StackurityPrincipal parameter")
		}
		if !reflect.DeepEqual(get(st, "Condition"), map[string]any{"StringEquals": map[string]any{"sts:ExternalId": map[string]any{"Ref": "ExternalId"}}}) {
			p = append(p, "trust policy does not require the external ID")
		}
		if get(st, "Effect") != "Allow" || !reflect.DeepEqual(strs(get(st, "Action")), []string{"sts:AssumeRole"}) {
			p = append(p, "trust policy must allow sts:AssumeRole only")
		}
	}
	var readOnly, agent []string
	policies, _ := get(role, "Policies").([]any)
	for _, pol := range policies {
		doc := get(pol, "PolicyDocument")
		name := get(pol, "PolicyName")
		if name != nil && name != "stackurity-read-only" {
			p = append(p, fmt.Sprintf("policy %v is not behind the AgentInstall condition", name))
		}
		if c := get(pol, "Fn::If"); c != nil {
			args, _ := c.([]any)
			if len(args) != 3 || args[0] != "AgentInstall" || !reflect.DeepEqual(args[2], map[string]any{"Ref": "AWS::NoValue"}) {
				p = append(p, "a conditional policy must be AgentInstall or nothing")
				continue
			}
			doc, name = get(args[1], "PolicyDocument"), get(args[1], "PolicyName")
		}
		stmts, _ := get(doc, "Statement").([]any)
		for _, st := range stmts {
			if get(st, "Effect") != "Allow" {
				continue
			}
			acts := strs(get(st, "Action"))
			for _, a := range acts {
				if strings.Contains(a, "*") {
					p = append(p, "wildcard action "+a)
				}
			}
			if get(st, "NotAction") != nil || get(st, "NotResource") != nil {
				p = append(p, "NotAction/NotResource is not allowed")
			}
			if name == "stackurity-read-only" {
				readOnly = append(readOnly, acts...)
			} else {
				agent = append(agent, acts...)
				if contains(acts, "ssm:SendCommand") {
					res, _ := get(st, "Resource").([]any)
					if len(res) != 2 || !strings.Contains(get(res[0], "Fn::Sub").(string), "document/AWS-RunShellScript") ||
						!strings.Contains(get(res[1], "Fn::Sub").(string), ":${AWS::AccountId}:instance/") {
						p = append(p, "ssm:SendCommand must be limited to AWS-RunShellScript and the account's instances")
					}
				}
			}
		}
	}
	sort.Strings(readOnly)
	sort.Strings(agent)
	if !reflect.DeepEqual(readOnly, wantReadOnly) {
		p = append(p, "read-only actions are "+strings.Join(readOnly, ","))
	}
	if !reflect.DeepEqual(agent, wantAgentInstall) {
		p = append(p, "agent install actions are "+strings.Join(agent, ","))
	}
	if get(t, "Parameters", "EnableAgentInstall", "Default") != "false" {
		p = append(p, "agent install must default to off")
	}
	if get(t, "Parameters", "CallbackToken", "NoEcho") != true {
		p = append(p, "the callback token must be NoEcho")
	}
	if get(t, "Outputs", "RoleArn", "Value") == nil {
		p = append(p, "no RoleArn output")
	}
	return p
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func parsed(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(Template()))
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("template is not valid JSON: %v", err)
	}
	return m
}

func TestTemplatePolicies(t *testing.T) {
	m := parsed(t)
	if p := policyProblems(m); len(p) > 0 {
		t.Fatalf("template problems: %v", p)
	}
	if !reflect.DeepEqual(ReadOnlyActions, wantReadOnly) {
		t.Errorf("ReadOnlyActions = %v", ReadOnlyActions)
	}
	if bytes.Contains(Template(), []byte(`"*:*"`)) || bytes.Contains(Template(), []byte(`"Action": "*"`)) {
		t.Error("template grants everything")
	}
	// Every resource is the role, the callback function and its role, and
	// the custom resource; the last three only with a callback.
	res := get(m, "Resources").(map[string]any)
	var names []string
	for n, r := range res {
		names = append(names, n)
		if n != "StackurityRole" && get(r, "Condition") != "Callback" {
			t.Errorf("%s is created without a callback", n)
		}
	}
	sort.Strings(names)
	if want := []string{"Callback", "CallbackFunction", "CallbackFunctionRole", "StackurityRole"}; !reflect.DeepEqual(names, want) {
		t.Errorf("resources %v", names)
	}
	// The callback function sends the token only as a header and never
	// prints it.
	code := get(m, "Resources", "CallbackFunction", "Properties", "Code", "ZipFile").(string)
	for _, line := range strings.Split(code, "\n") {
		if strings.Contains(line, "print(") && strings.Contains(line, "Token") {
			t.Errorf("the function logs the token: %s", line)
		}
	}
	if !strings.Contains(code, `"Authorization": "Bearer " + p["Token"]`) {
		t.Error("the function does not send the token as a bearer token")
	}
	for _, r := range code {
		if r > 127 {
			t.Fatalf("inline function code must be ASCII, has %q", r)
		}
	}
}

// Negative controls: the checks above catch each way the role could grant
// more than it should.
func TestTemplateChecksCatchMistakes(t *testing.T) {
	for name, mutate := range map[string]func(m map[string]any){
		"wildcard action": func(m map[string]any) {
			st := get(m, "Resources", "StackurityRole", "Properties", "Policies").([]any)[0]
			s := get(st, "PolicyDocument", "Statement").([]any)[0].(map[string]any)
			s["Action"] = append(s["Action"].([]any), "s3:*")
		},
		"extra action": func(m map[string]any) {
			st := get(m, "Resources", "StackurityRole", "Properties", "Policies").([]any)[0]
			s := get(st, "PolicyDocument", "Statement").([]any)[0].(map[string]any)
			s["Action"] = append(s["Action"].([]any), "rds:DeleteDBInstance")
		},
		"no external id": func(m map[string]any) {
			s := get(m, "Resources", "StackurityRole", "Properties", "AssumeRolePolicyDocument", "Statement").([]any)[0].(map[string]any)
			delete(s, "Condition")
		},
		"other principal": func(m map[string]any) {
			s := get(m, "Resources", "StackurityRole", "Properties", "AssumeRolePolicyDocument", "Statement").([]any)[0].(map[string]any)
			s["Principal"] = map[string]any{"AWS": "*"}
		},
		"agent install unconditional": func(m map[string]any) {
			pols := get(m, "Resources", "StackurityRole", "Properties", "Policies").([]any)
			pols[1] = pols[1].(map[string]any)["Fn::If"].([]any)[1]
			get(m, "Resources", "StackurityRole", "Properties").(map[string]any)["Policies"] = pols
		},
		"send command anywhere": func(m map[string]any) {
			pol := get(m, "Resources", "StackurityRole", "Properties", "Policies").([]any)[1].(map[string]any)["Fn::If"].([]any)[1]
			s := get(pol, "PolicyDocument", "Statement").([]any)[1].(map[string]any)
			s["Resource"] = "*"
		},
		"agent install on by default": func(m map[string]any) {
			get(m, "Parameters", "EnableAgentInstall").(map[string]any)["Default"] = "true"
		},
	} {
		m := parsed(t)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: %v", name, r)
				}
			}()
			mutate(m)
			if p := policyProblems(m); len(p) == 0 {
				t.Errorf("%s: not caught", name)
			}
		}()
	}
}

// deploy/aws holds the template as published (the operator uploads it to S3
// for Launch Stack). It must be exactly what the code generates: run
// go test ./internal/awsconnect -run TestPublishedTemplate -update.
func TestPublishedTemplate(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "aws", TemplateFile)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, Template(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, Template()) {
		t.Fatalf("%s differs from the generated template; run with -update (and publish it under a new TemplateVersion if it was released)", path)
	}
}
