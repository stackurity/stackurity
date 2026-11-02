package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/awsconnect"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Connecting AWS with a CloudFormation stack (docs/install.md, "AWS managed
// services"; internal/awsconnect). The stack's role trusts the server's AWS
// principal with an external ID generated here, so a workspace can only
// ever read the account whose stack was made from its own link.

const (
	// awsCallbackTTL is how long a Launch Stack link can report its role.
	awsCallbackTTL = 24 * time.Hour
	// awsSchedule is how often a connected account is read.
	awsSchedule = 12 * time.Hour
	// awsMaxInstallBatch bounds one install request.
	awsMaxInstallBatch = 25
	// awsInstallGiveUp marks an install timed out when SSM never said it
	// ended (SSM's own limits are 10 minutes to deliver and 10 to run).
	awsInstallGiveUp = 25 * time.Minute
	// awsInstallRecheck is how often one install's state is read from SSM.
	awsInstallRecheck = 4 * time.Second
)

func (s *Server) awsEnabled(w http.ResponseWriter) bool {
	if !s.AWS.Enabled() {
		writeError(w, 404, "not_found", "AWS connections are not set up on this server: the operator sets STACKURITY_AWS_PRINCIPAL_ARN (docs/install.md)")
		return false
	}
	return true
}

// awsTemplate serves the CloudFormation template, for review, for the
// CLI, and for the operator to upload to S3 (the console only takes S3).
func (s *Server) awsTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+awsconnect.TemplateFile+`"`)
	_, _ = w.Write(awsconnect.Template())
}

type awsConnectionView struct {
	store.AWSConnection
	// IntegrationRemoved: the connection is active but its integration
	// was deleted; verifying again creates a new one.
	IntegrationRemoved bool `json:"integration_removed"`
}

func awsView(c *store.AWSConnection) awsConnectionView {
	return awsConnectionView{AWSConnection: *c, IntegrationRemoved: c.Status == "active" && c.IntegrationID == nil}
}

// listAWSConnections also says whether this server can make connections,
// and with which principal, for the Settings page.
func (s *Server) listAWSConnections(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.ListAWSConnections(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]awsConnectionView, 0, len(cs))
	for i := range cs {
		items = append(items, awsView(&cs[i]))
	}
	out := map[string]any{"items": items, "total": len(items), "enabled": s.AWS.Enabled(),
		"template_download": "/aws/" + awsconnect.TemplateFile, "permissions": awsconnect.ReadOnlyActions,
		"agent_install_permissions": append(append([]string{}, awsconnect.AgentInstallListActions...), awsconnect.AgentInstallRunAction)}
	if s.AWS.Enabled() {
		out["principal"] = s.AWS.Principal
		out["launch_stack"] = s.AWS.TemplateURL != ""
	}
	writeJSON(w, 200, out)
}

type awsLaunchRequest struct {
	Regions      []string `json:"regions"`
	StackRegion  string   `json:"stack_region"`
	AgentInstall bool     `json:"agent_install"`
}

func checkRegions(regions []string) ([]string, error) {
	if len(regions) == 0 || len(regions) > 40 {
		return nil, badRequest("regions must list 1-40 AWS regions")
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range regions {
		r = strings.TrimSpace(r)
		if !awsconnect.RegionRE.MatchString(r) {
			return nil, badRequest(fmt.Sprintf("invalid region %q", r))
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// awsLaunch is what the page needs to create the stack.
type awsLaunch struct {
	// QuickCreateURL opens the CloudFormation console with everything
	// filled in; empty when the operator has not hosted the template in S3.
	QuickCreateURL string `json:"quick_create_url"`
	TemplateURL    string `json:"template_url"`
	// TemplateDownload is the template on this server.
	TemplateDownload string `json:"template_download"`
	StackName        string `json:"stack_name"`
	StackRegion      string `json:"stack_region"`
	ExternalID       string `json:"external_id"`
	Principal        string `json:"principal"`
	// Callback: the stack reports its role by itself (this server's
	// address is https). Otherwise the role ARN is pasted.
	Callback bool `json:"callback"`
	// CLI creates the same stack with the AWS CLI, from the downloaded
	// template.
	CLI string `json:"cli"`
}

// newAWSLaunch signs a new callback token for the connection (replacing any
// earlier one) and builds the links.
func (s *Server) newAWSLaunch(ctx context.Context, r *http.Request, c *store.AWSConnection, stackRegion string, agentInstall bool) (*awsLaunch, error) {
	if !awsconnect.RegionRE.MatchString(stackRegion) {
		return nil, badRequest(fmt.Sprintf("invalid stack region %q", stackRegion))
	}
	l := &awsLaunch{TemplateURL: s.AWS.TemplateURL, TemplateDownload: "/aws/" + awsconnect.TemplateFile,
		StackName: fmt.Sprintf("Stackurity-%d", c.ID), StackRegion: stackRegion, ExternalID: c.ExternalID, Principal: s.AWS.Principal}
	base, err := s.publicURL(r)
	if err != nil {
		return nil, err
	}
	callbackURL := base + "/api/v1/aws/callback"
	var token string
	if u, err := url.Parse(callbackURL); err == nil && u.Scheme == "https" {
		key, err := s.Store.PlatformKey(ctx, "aws-callback")
		if err != nil {
			return nil, err
		}
		exp := time.Now().Add(awsCallbackTTL)
		var nonce []byte
		token, nonce, err = awsconnect.NewCallbackToken(key, c.ID, c.WorkspaceID, c.ExternalID, exp)
		if err != nil {
			return nil, err
		}
		if err := s.Store.SetAWSCallback(ctx, c.ID, nonce, exp); err != nil {
			return nil, err
		}
		l.Callback = true
	} else {
		callbackURL = ""
	}
	if err := s.Store.SetAWSOptions(ctx, c.ID, agentInstall); err != nil {
		return nil, err
	}
	p := awsconnect.LaunchParams{TemplateURL: s.AWS.TemplateURL, Region: stackRegion, StackName: l.StackName, Principal: s.AWS.Principal,
		ExternalID: c.ExternalID, AgentInstall: agentInstall, CallbackURL: callbackURL, Token: token}
	if s.AWS.TemplateURL != "" {
		u, err := awsconnect.QuickCreateURL(p)
		if err != nil {
			return nil, err
		}
		l.QuickCreateURL = u
	}
	params := fmt.Sprintf("ParameterKey=StackurityPrincipal,ParameterValue=%s ParameterKey=ExternalId,ParameterValue=%s ParameterKey=EnableAgentInstall,ParameterValue=%t",
		p.Principal, p.ExternalID, agentInstall)
	if token != "" {
		params += fmt.Sprintf(" ParameterKey=CallbackUrl,ParameterValue=%s ParameterKey=CallbackToken,ParameterValue=%s", callbackURL, token)
	}
	l.CLI = fmt.Sprintf("aws cloudformation create-stack --region %s --stack-name %s --capabilities CAPABILITY_IAM "+
		"--template-body file://%s --parameters %s", stackRegion, l.StackName, awsconnect.TemplateFile, params)
	return l, nil
}

func (s *Server) createAWSConnection(w http.ResponseWriter, r *http.Request) {
	if !s.awsEnabled(w) {
		return
	}
	var req awsLaunchRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	regions, err := checkRegions(req.Regions)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if req.StackRegion == "" {
		req.StackRegion = regions[0]
	}
	if !awsconnect.RegionRE.MatchString(req.StackRegion) {
		s.fail(w, r, badRequest(fmt.Sprintf("invalid stack region %q", req.StackRegion)))
		return
	}
	// A connection exists to add assets; at the limit it could add none.
	if err := s.Store.AssetLimitReached(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	var by int64
	if p.User != nil {
		by = p.User.ID
	}
	c, err := s.Store.CreateAWSConnection(r.Context(), regions, req.AgentInstall, by)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	l, err := s.newAWSLaunch(r.Context(), r, c, req.StackRegion, req.AgentInstall)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "aws.connection.create", "aws_connection", itoa(c.ID), map[string]any{
		"regions": regions, "agent_install": req.AgentInstall, "external_id": c.ExternalID})
	c, err = s.Store.GetAWSConnection(r.Context(), c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]any{"connection": awsView(c), "launch": l})
}

func (s *Server) awsConnection(w http.ResponseWriter, r *http.Request) (*store.AWSConnection, bool) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	c, err := s.Store.GetAWSConnection(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	return c, true
}

func (s *Server) getAWSConnection(w http.ResponseWriter, r *http.Request) {
	c, ok := s.awsConnection(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"connection": awsView(c)})
}

// relaunchAWSConnection makes a new Launch Stack link (a new single-use
// token; the earlier one stops working) for a connection not active yet.
func (s *Server) relaunchAWSConnection(w http.ResponseWriter, r *http.Request) {
	if !s.awsEnabled(w) {
		return
	}
	c, ok := s.awsConnection(w, r)
	if !ok {
		return
	}
	var req struct {
		StackRegion  string `json:"stack_region"`
		AgentInstall bool   `json:"agent_install"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if c.Status == "active" {
		s.fail(w, r, fmt.Errorf("this connection is already active: %w", store.ErrConflict))
		return
	}
	if req.StackRegion == "" {
		req.StackRegion = c.Regions[0]
	}
	l, err := s.newAWSLaunch(r.Context(), r, c, req.StackRegion, req.AgentInstall)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "aws.connection.link", "aws_connection", itoa(c.ID), map[string]any{"agent_install": req.AgentInstall})
	c, _ = s.Store.GetAWSConnection(r.Context(), c.ID)
	writeJSON(w, 200, map[string]any{"connection": awsView(c), "launch": l})
}

func (s *Server) deleteAWSConnection(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.DeleteAWSConnection(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "aws.connection.delete", "aws_connection", itoa(id), map[string]any{
		"account_id": c.AccountID, "integration_id": c.IntegrationID})
	w.WriteHeader(204)
}

// verifyAWS assumes the role with the connection's external ID (and checks
// it cannot be assumed without), then activates the connection: its
// integration is created and run. attempts > 1 retries while a new role is
// not usable yet. Failures are recorded on the connection.
func (s *Server) verifyAWS(ctx context.Context, c *store.AWSConnection, roleARN string, attempts int) (*store.AWSConnection, error) {
	if err := s.Store.AssetLimitReached(ctx); err != nil {
		_ = s.Store.FailAWSConnection(ctx, c.ID, err.Error())
		return nil, err
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(s.AWS.PropagationDelay):
			}
		}
		_, err = s.AWS.Verify(ctx, roleARN, c.ExternalID, awsconnect.SessionName(c.WorkspaceID, c.ID))
		if err == nil || errors.Is(err, awsconnect.ErrNoExternalIDCondition) {
			break
		}
	}
	if err != nil {
		if ferr := s.Store.FailAWSConnection(ctx, c.ID, err.Error()); ferr != nil {
			return nil, ferr
		}
		return s.Store.GetAWSConnection(ctx, c.ID)
	}
	integ, err := s.Store.ActivateAWSConnection(ctx, c.ID, roleARN, awsSchedule)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.Enqueue(ctx, "integration.run", map[string]int64{"integration_id": integ}, "integration:"+itoa(integ), time.Time{}); err != nil {
		s.Log.Warn("first AWS run not queued", "integration", integ, "err", err)
	}
	return s.Store.GetAWSConnection(ctx, c.ID)
}

// verifyAWSConnection checks a pasted role ARN, or the one already
// recorded (verify again after fixing the role).
func (s *Server) verifyAWSConnection(w http.ResponseWriter, r *http.Request) {
	if !s.awsEnabled(w) {
		return
	}
	c, ok := s.awsConnection(w, r)
	if !ok {
		return
	}
	var req struct {
		RoleARN string `json:"role_arn"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	role := strings.TrimSpace(req.RoleARN)
	if role != "" && role != c.RoleARN {
		if !awsconnect.RoleARNRE.MatchString(role) {
			s.fail(w, r, badRequest("paste the RoleArn output of the stack (arn:aws:iam::123456789012:role/...)"))
			return
		}
		if c.Status == "active" {
			s.fail(w, r, fmt.Errorf("this connection is active with another role; remove it and connect again: %w", store.ErrConflict))
			return
		}
		if err := s.Store.SetAWSRole(r.Context(), c.ID, role); err != nil {
			s.fail(w, r, err)
			return
		}
	} else {
		role = c.RoleARN
	}
	if role == "" {
		s.fail(w, r, badRequest("paste the RoleArn output of the stack"))
		return
	}
	out, err := s.verifyAWS(r.Context(), c, role, 1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "aws.connection.verify", "aws_connection", itoa(c.ID), map[string]any{
		"role_arn": role, "status": out.Status, "error": out.LastError})
	writeJSON(w, 200, map[string]any{"connection": awsView(out)})
}

// awsCallback receives the role ARN from the stack's custom resource. It
// has no session: the bearer token, signed with the installation's key,
// names the connection, its workspace and external ID, and is used up by
// the first request that presents it. Every refusal looks the same.
func (s *Server) awsCallback(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"aws-callback", clientIP(r), limitPerAddress}) {
		return
	}
	if !s.awsEnabled(w) {
		return
	}
	refuse := func() { writeError(w, 403, "forbidden", awsconnect.ErrBadToken.Error()) }
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		refuse()
		return
	}
	var req struct {
		RoleARN    string `json:"role_arn"`
		ExternalID string `json:"external_id"`
		StackID    string `json:"stack_id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	sys := tenant.System(r.Context())
	key, err := s.Store.PlatformKey(sys, "aws-callback")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	claims, err := awsconnect.ParseCallbackToken(key, strings.TrimSpace(token), time.Now())
	if err != nil || req.ExternalID != claims.ExternalID {
		refuse()
		return
	}
	account := awsconnect.AccountOf(req.RoleARN)
	if account == "" {
		s.fail(w, r, badRequest("role_arn must be an IAM role ARN"))
		return
	}
	// The stack and the role are in the same account.
	if req.StackID != "" {
		parts := strings.Split(req.StackID, ":")
		if len(parts) < 6 || parts[0] != "arn" || parts[2] != "cloudformation" || parts[4] != account {
			s.fail(w, r, badRequest("stack_id is not a stack in the role's account"))
			return
		}
	}
	c, err := s.Store.ConsumeAWSCallback(sys, claims, req.RoleARN)
	if errors.Is(err, store.ErrNotFound) {
		refuse() // used, replaced, expired, or the connection is gone
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := tenant.WithWorkspace(r.Context(), c.WorkspaceID)
	actor := store.Actor{Type: "aws-stack", Name: "stack in " + account, RemoteAddr: clientIP(r)}
	out, err := s.verifyAWS(ctx, c, req.RoleARN, 3)
	if err != nil {
		_ = s.Store.Audit(ctx, actor, "aws.connection.callback", "aws_connection", itoa(c.ID), map[string]any{"role_arn": req.RoleARN, "error": err.Error()})
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, actor, "aws.connection.callback", "aws_connection", itoa(c.ID), map[string]any{
		"role_arn": req.RoleARN, "stack_id": req.StackID, "status": out.Status, "error": out.LastError})
	writeJSON(w, 200, map[string]string{"status": out.Status})
}

// awsSession assumes an active connection's role.
func (s *Server) awsSession(ctx context.Context, c *store.AWSConnection) (*awsconnect.Session, error) {
	if c.Status != "active" {
		return nil, errAWSInactive
	}
	return s.AWS.AssumeRole(ctx, c.RoleARN, c.ExternalID, awsconnect.SessionName(c.WorkspaceID, c.ID))
}

var errAWSInactive = &wrapped{store.ErrAWSInactive.Error(), store.ErrConflict}

func awsRegion(c *store.AWSConnection, region string) (string, error) {
	if region == "" {
		return c.Regions[0], nil
	}
	for _, x := range c.Regions {
		if x == region {
			return region, nil
		}
	}
	return "", badRequest("region must be one of the connection's regions: " + strings.Join(c.Regions, ", "))
}

type awsInstanceView struct {
	awsconnect.Instance
	// Eligible: a Linux instance SSM can reach now.
	Eligible bool `json:"eligible"`
	// AssetID: a host asset reports with this instance's hostname.
	AssetID *int64 `json:"asset_id"`
	// LastInstall is the newest install sent to the instance.
	LastInstall *store.AWSAgentInstall `json:"last_install"`
}

// listAWSInstances lists the instances SSM manages in one region, and
// which of them already report through the agent (matched by hostname).
func (s *Server) listAWSInstances(w http.ResponseWriter, r *http.Request) {
	if !s.awsEnabled(w) {
		return
	}
	c, ok := s.awsConnection(w, r)
	if !ok {
		return
	}
	region, err := awsRegion(c, r.URL.Query().Get("region"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sess, err := s.awsSession(r.Context(), c)
	if err != nil {
		s.awsFail(w, r, err)
		return
	}
	list, truncated, err := s.AWS.ListInstances(r.Context(), sess, region)
	if err != nil {
		s.awsFail(w, r, err)
		return
	}
	names := make([]string, 0, len(list))
	for _, i := range list {
		names = append(names, i.ComputerName)
	}
	hosts, err := s.Store.ReportingHostnames(r.Context(), names)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	installs, err := s.Store.ListAWSInstalls(r.Context(), c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	last := map[string]*store.AWSAgentInstall{}
	for i := range installs {
		if in := &installs[i]; in.Region == region && last[in.InstanceID] == nil {
			last[in.InstanceID] = in
		}
	}
	items := make([]awsInstanceView, 0, len(list))
	for _, i := range list {
		v := awsInstanceView{Instance: i, LastInstall: last[i.InstanceID],
			Eligible: strings.EqualFold(i.PlatformType, "Linux") && strings.EqualFold(i.PingStatus, "Online")}
		n := strings.ToLower(i.ComputerName)
		short, _, _ := strings.Cut(n, ".")
		if id, ok := hosts[n]; ok {
			v.AssetID = &id
		} else if id, ok := hosts[short]; ok && short != "" {
			v.AssetID = &id
		}
		items = append(items, v)
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": len(items), "region": region, "truncated": truncated})
}

// awsFail reports an AWS error to the administrator as a bad gateway with
// the explained message; other errors go through fail.
func (s *Server) awsFail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrConflict) || errors.Is(err, errBadRequest) || errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	writeError(w, 502, "aws_error", err.Error())
}

type awsInstallRequest struct {
	Region    string `json:"region"`
	Instances []struct {
		InstanceID   string `json:"instance_id"`
		ComputerName string `json:"computer_name"`
	} `json:"instances"`
}

// installAWSAgents runs the agent installer on the chosen instances through
// SSM, each with its own single-use enrollment code (two hours), which is
// sent to SSM and never stored. The results are read back by
// listAWSInstalls.
func (s *Server) installAWSAgents(w http.ResponseWriter, r *http.Request) {
	if !s.awsEnabled(w) {
		return
	}
	c, ok := s.awsConnection(w, r)
	if !ok {
		return
	}
	var req awsInstallRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	region, err := awsRegion(c, req.Region)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.Instances) == 0 || len(req.Instances) > awsMaxInstallBatch {
		s.fail(w, r, badRequest(fmt.Sprintf("choose 1-%d instances", awsMaxInstallBatch)))
		return
	}
	seen := map[string]bool{}
	for _, in := range req.Instances {
		if !awsconnect.InstanceIDRE.MatchString(in.InstanceID) || seen[in.InstanceID] {
			s.fail(w, r, badRequest(fmt.Sprintf("invalid or repeated instance id %q", in.InstanceID)))
			return
		}
		seen[in.InstanceID] = true
	}
	if err := s.Store.AssetLimitReached(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	// The command carries this server's address; check it before making codes.
	base, err := s.publicURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := awsconnect.InstallCommand(base, "enr_check"); err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	sess, err := s.awsSession(r.Context(), c)
	if err != nil {
		s.awsFail(w, r, err)
		return
	}
	p := principal(r)
	var by int64
	var byPtr *int64
	if p.User != nil {
		by = p.User.ID
		byPtr = &by
	}
	out := make([]store.AWSAgentInstall, 0, len(req.Instances))
	for _, in := range req.Instances {
		row := store.AWSAgentInstall{ConnectionID: c.ID, Region: region, InstanceID: in.InstanceID, ComputerName: strings.TrimSpace(in.ComputerName),
			CreatedBy: byPtr, Status: "failed"}
		e, code, err := s.Store.CreateEnrollment(r.Context(), store.Enrollment{Label: "AWS SSM " + in.InstanceID, UsesLeft: 1, AppDirs: []string{}},
			2*time.Hour, by)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		row.EnrollmentID = &e.ID
		cmd, err := awsconnect.InstallCommand(base, code)
		if err == nil {
			row.CommandID, err = s.AWS.SendInstall(r.Context(), sess, region, in.InstanceID, cmd)
		}
		if err != nil {
			row.Detail = err.Error()
			_ = s.Store.RevokeEnrollment(r.Context(), e.ID)
		} else {
			row.Status = "pending"
		}
		saved, err := s.Store.CreateAWSInstall(r.Context(), row)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, *saved)
		_ = s.Store.Audit(r.Context(), p.Actor(r), "aws.agent.install", "aws_connection", itoa(c.ID), map[string]any{
			"instance_id": in.InstanceID, "region": region, "enrollment_id": e.ID, "command_id": saved.CommandID, "status": saved.Status, "error": saved.Detail})
	}
	writeJSON(w, 202, map[string]any{"items": out, "total": len(out)})
}

// listAWSInstalls returns a connection's installs, first reading from SSM
// how the unfinished ones went. A failed or timed-out install's code is
// revoked.
func (s *Server) listAWSInstalls(w http.ResponseWriter, r *http.Request) {
	c, ok := s.awsConnection(w, r)
	if !ok {
		return
	}
	items, err := s.Store.ListAWSInstalls(r.Context(), c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	refreshErr := ""
	if s.AWS.Enabled() && c.Status == "active" {
		if err := s.refreshAWSInstalls(r.Context(), c, items); err != nil {
			refreshErr = err.Error()
		} else if items, err = s.Store.ListAWSInstalls(r.Context(), c.ID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if items == nil {
		items = []store.AWSAgentInstall{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": len(items), "refresh_error": refreshErr})
}

func (s *Server) refreshAWSInstalls(ctx context.Context, c *store.AWSConnection, items []store.AWSAgentInstall) error {
	var sess *awsconnect.Session
	checked := 0
	for _, in := range items {
		if in.Status != "pending" && in.Status != "running" {
			continue
		}
		if in.CheckedAt != nil && time.Since(*in.CheckedAt) < awsInstallRecheck {
			continue
		}
		if checked == 50 {
			break
		}
		checked++
		status, detail := in.Status, in.Detail
		if time.Since(in.CreatedAt) > awsInstallGiveUp {
			status, detail = "timed_out", "SSM did not report the end of the command within "+awsInstallGiveUp.String()
		} else {
			if sess == nil {
				var err error
				if sess, err = s.awsSession(ctx, c); err != nil {
					return err
				}
			}
			inv, err := s.AWS.GetInvocation(ctx, sess, in.Region, in.CommandID, in.InstanceID)
			if err != nil {
				return err
			}
			status, detail = inv.Status, inv.Detail
		}
		if err := s.Store.UpdateAWSInstall(ctx, in.ID, status, detail); err != nil {
			return err
		}
		if (status == "failed" || status == "timed_out") && in.EnrollmentID != nil {
			if err := s.Store.RevokeEnrollment(ctx, *in.EnrollmentID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
	}
	return nil
}

// checkAWSLinkedUpdate keeps an AWS connection's integration running the
// aws-managed plugin with the server's session: it takes no secret, and its
// config cannot name a role or an external ID (or another plugin, which
// would then be handed the session). It reports whether id is such an
// integration.
func (s *Server) checkAWSLinkedUpdate(ctx context.Context, id int64, cfg json.RawMessage, secretRef string) (bool, error) {
	_, err := s.Store.AWSConnectionForIntegration(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if secretRef != "" {
		return true, badRequest("this integration reads AWS through its connection's role and takes no secret")
	}
	if len(cfg) > 0 {
		var c PluginConfig
		if err := json.Unmarshal(cfg, &c); err != nil {
			return true, badRequest("invalid config: " + err.Error())
		}
		if c.Plugin != "aws-managed" {
			return true, badRequest("this integration belongs to an AWS connection and runs the aws-managed plugin")
		}
		var inner map[string]json.RawMessage
		_ = json.Unmarshal(c.Config, &inner)
		if _, ok := inner["role_arn"]; ok {
			return true, badRequest("the role is the AWS connection's: remove role_arn")
		}
		if _, ok := inner["external_id"]; ok {
			return true, badRequest("the external ID is the AWS connection's: remove external_id")
		}
	}
	return true, nil
}

// AWSPluginRun prepares a run of an AWS connection's integration
// (cmd/stackurity, integration.run): it assumes the connection's role with
// the server's principal and returns the plugin config without any role or
// external ID, and the session as the plugin's credentials. linked is false
// for an integration that belongs to no connection; the caller then runs it
// as before. The plugin never sees the server's own credentials.
func AWSPluginRun(ctx context.Context, st *store.Store, client *awsconnect.Client, integrationID int64, cfg PluginConfig) (out PluginConfig, creds map[string]string, linked bool, err error) {
	c, err := st.AWSConnectionForIntegration(ctx, integrationID)
	if errors.Is(err, store.ErrNotFound) {
		return cfg, nil, false, nil
	}
	if err != nil {
		return cfg, nil, true, err
	}
	switch {
	case c.Status != "active":
		return cfg, nil, true, errors.New("the AWS connection is not active: verify its role under Settings > Integrations > AWS")
	case !client.Enabled():
		return cfg, nil, true, errors.New("AWS connections are not set up on this server (STACKURITY_AWS_PRINCIPAL_ARN)")
	case cfg.Plugin != "aws-managed":
		return cfg, nil, true, errors.New("an AWS connection's integration runs only the aws-managed plugin")
	}
	inner := map[string]json.RawMessage{}
	if len(cfg.Config) > 0 {
		if err := json.Unmarshal(cfg.Config, &inner); err != nil {
			return cfg, nil, true, fmt.Errorf("plugin config: %w", err)
		}
	}
	delete(inner, "role_arn")
	delete(inner, "external_id")
	if _, ok := inner["regions"]; !ok {
		inner["regions"], _ = json.Marshal(c.Regions)
	}
	if cfg.Config, err = json.Marshal(inner); err != nil {
		return cfg, nil, true, err
	}
	sess, err := client.AssumeRole(ctx, c.RoleARN, c.ExternalID, awsconnect.SessionName(c.WorkspaceID, c.ID))
	if err != nil {
		return cfg, nil, true, err
	}
	return cfg, sess.PluginSecrets(), true, nil
}
