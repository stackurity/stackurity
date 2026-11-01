// Package awsfake is a stand-in for the AWS STS and SSM APIs, for tests of
// internal/awsconnect and the API handlers that use it. It speaks the wire
// protocols the AWS SDK uses (STS: query with XML answers; SSM: JSON 1.1)
// for the few operations Stackurity calls, and records what it was asked.
package awsfake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Role modes.
const (
	RoleOK         = "ok"          // assumable with the right external ID only
	RoleNoExternal = "no-external" // assumable with or without an external ID
)

// Server is a fake STS and SSM endpoint.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// Roles maps a role ARN to its mode and the external ID it requires.
	Roles map[string]Role
	// Instances are what DescribeInstanceInformation lists, PageSize per page.
	Instances []map[string]any
	PageSize  int
	// SendErrors maps an instance ID to the error code SendCommand answers.
	SendErrors map[string]string
	// Invocations maps an instance ID to the GetCommandInvocation answer
	// ("Status", "StandardOutputContent", ...); a missing instance answers
	// InvocationDoesNotExist.
	Invocations map[string]map[string]any

	// What was asked.
	AssumeCalls []url.Values
	Sent        []SentCommand
	Targets     []string
}

// Role is how a fake role behaves.
type Role struct {
	Mode       string
	ExternalID string
}

// SentCommand is one SendCommand request.
type SentCommand struct {
	CommandID    string
	DocumentName string
	InstanceIDs  []string
	Commands     []string
	AccessKey    string
}

// New starts a fake.
func New(t testing.TB) *Server {
	f := &Server{Roles: map[string]Role{}, SendErrors: map[string]string{}, Invocations: map[string]map[string]any{}, PageSize: 50}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		f.Targets = append(f.Targets, target)
		f.ssm(w, r, strings.TrimPrefix(target, "AmazonSSM."), body)
		return
	}
	form, _ := url.ParseQuery(string(body))
	if form.Get("Action") != "AssumeRole" {
		stsError(w, 400, "InvalidAction", "unsupported action "+form.Get("Action"))
		return
	}
	f.AssumeCalls = append(f.AssumeCalls, form)
	role, ok := f.Roles[form.Get("RoleArn")]
	ext := form.Get("ExternalId")
	switch {
	case !ok:
		stsError(w, 403, "AccessDenied", "User is not authorized to perform: sts:AssumeRole on resource: "+form.Get("RoleArn"))
		return
	case role.Mode == RoleOK && ext != role.ExternalID:
		stsError(w, 403, "AccessDenied", "User is not authorized to perform: sts:AssumeRole on resource: "+form.Get("RoleArn"))
		return
	}
	key := fmt.Sprintf("ASIAFAKE%04d", len(f.AssumeCalls))
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials>`+
		`<AccessKeyId>%s</AccessKeyId><SecretAccessKey>secret-%s</SecretAccessKey><SessionToken>token-%s</SessionToken>`+
		`<Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>%s/%s</Arn><AssumedRoleId>AROAFAKE:%s</AssumedRoleId></AssumedRoleUser>`+
		`</AssumeRoleResult><ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></AssumeRoleResponse>`,
		key, key, key, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), form.Get("RoleArn"), form.Get("RoleSessionName"), form.Get("RoleSessionName"))
}

func stsError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>req-1</RequestId></ErrorResponse>`, code, msg)
}

func ssmError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": msg})
}

func (f *Server) ssm(w http.ResponseWriter, r *http.Request, op string, body []byte) {
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	// The SDK signs with the session's key ID; a call signed with anything
	// but a session from AssumeRole is refused.
	auth := r.Header.Get("Authorization")
	ak := ""
	if i := strings.Index(auth, "Credential="); i >= 0 {
		ak, _, _ = strings.Cut(auth[i+len("Credential="):], "/")
	}
	if !strings.HasPrefix(ak, "ASIAFAKE") || r.Header.Get("X-Amz-Security-Token") == "" {
		ssmError(w, 400, "UnrecognizedClientException", "The security token included in the request is invalid.")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch op {
	case "DescribeInstanceInformation":
		start := 0
		if tok, _ := in["NextToken"].(string); tok != "" {
			fmt.Sscanf(tok, "page-%d", &start)
		}
		end := min(start+f.PageSize, len(f.Instances))
		out := map[string]any{"InstanceInformationList": f.Instances[start:end]}
		if end < len(f.Instances) {
			out["NextToken"] = fmt.Sprintf("page-%d", end)
		}
		_ = json.NewEncoder(w).Encode(out)
	case "SendCommand":
		var ids []string
		for _, x := range in["InstanceIds"].([]any) {
			ids = append(ids, x.(string))
		}
		for _, id := range ids {
			if code := f.SendErrors[id]; code != "" {
				ssmError(w, 400, code, "Instances ["+id+"] not in a valid state for account")
				return
			}
		}
		var cmds []string
		if p, ok := in["Parameters"].(map[string]any); ok {
			for _, x := range p["commands"].([]any) {
				cmds = append(cmds, x.(string))
			}
		}
		id := fmt.Sprintf("cmd-%d", len(f.Sent)+1)
		doc, _ := in["DocumentName"].(string)
		f.Sent = append(f.Sent, SentCommand{CommandID: id, DocumentName: doc, InstanceIDs: ids, Commands: cmds, AccessKey: ak})
		_ = json.NewEncoder(w).Encode(map[string]any{"Command": map[string]any{"CommandId": id, "DocumentName": doc, "InstanceIds": ids}})
	case "GetCommandInvocation":
		inv, ok := f.Invocations[fmt.Sprint(in["InstanceId"])]
		if !ok {
			ssmError(w, 400, "InvocationDoesNotExist", "")
			return
		}
		out := map[string]any{"CommandId": in["CommandId"], "InstanceId": in["InstanceId"]}
		for k, v := range inv {
			out[k] = v
		}
		_ = json.NewEncoder(w).Encode(out)
	default:
		ssmError(w, 400, "InvalidAction", "unsupported operation "+op)
	}
}

// Lock runs fn with the fake's state locked (to change or read it while
// requests may be served).
func (f *Server) Lock(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}
