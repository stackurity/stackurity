package awsconnect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/stackurity/stackurity/internal/netguard"
)

// Client makes Stackurity's own AWS calls for connections: sts:AssumeRole
// into customer roles with Stackurity's principal, and SSM calls with the
// session that returns. Every connection goes through netguard with the
// request's workspace, like the server's other outbound requests.
type Client struct {
	// Principal is the ARN customer roles trust (STACKURITY_AWS_PRINCIPAL_ARN).
	Principal string
	// TemplateURL is where the CloudFormation template is hosted in S3
	// (STACKURITY_AWS_TEMPLATE_URL); empty means there is no Launch Stack
	// link and the template is downloaded instead.
	TemplateURL string
	// Credentials are Stackurity's own (the AWS SDK's default chain on the
	// server: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, a profile, or an
	// instance or task role). They are only ever used for sts:AssumeRole and
	// never reach a plugin.
	Credentials aws.CredentialsProvider
	// STSRegion is the STS endpoint's region; empty is us-east-1, which
	// every AWS account has enabled. Sessions from a regional STS endpoint
	// are valid in every region.
	STSRegion string
	// STSEndpoint and SSMEndpoint replace the regional AWS endpoints (tests).
	STSEndpoint string
	SSMEndpoint string
	// PropagationDelay is the wait between attempts to assume a role a
	// stack has just created, which IAM can refuse for a few seconds.
	PropagationDelay time.Duration
	// HTTP replaces the netguard client (tests that check the guard leave it nil).
	HTTP *http.Client
}

var guarded = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		DialContext:           netguard.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
	},
	// AWS APIs do not redirect; following one would leave the guard's
	// view of where the request goes.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return guarded
}

// Enabled reports whether connections can be made on this server.
func (c *Client) Enabled() bool { return c != nil && c.Principal != "" && c.Credentials != nil }

// Session is a customer role's temporary credentials.
type Session struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time
	Account         string
}

// PluginSecrets are the session as the aws-managed plugin reads its
// credentials.
func (s *Session) PluginSecrets() map[string]string {
	return map[string]string{"aws_access_key_id": s.AccessKeyID, "aws_secret_access_key": s.SecretAccessKey, "aws_session_token": s.SessionToken}
}

func (s *Session) provider() aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(s.AccessKeyID, s.SecretAccessKey, s.SessionToken)
}

func (c *Client) sts() *sts.Client {
	region := c.STSRegion
	if region == "" {
		region = "us-east-1"
	}
	o := sts.Options{Region: region, Credentials: c.Credentials, HTTPClient: c.http(), RetryMaxAttempts: 2}
	if c.STSEndpoint != "" {
		o.BaseEndpoint = aws.String(c.STSEndpoint)
	}
	return sts.New(o)
}

func (c *Client) ssm(s *Session, region string) *ssm.Client {
	o := ssm.Options{Region: region, Credentials: s.provider(), HTTPClient: c.http(), RetryMaxAttempts: 2}
	if c.SSMEndpoint != "" {
		o.BaseEndpoint = aws.String(c.SSMEndpoint)
	}
	return ssm.New(o)
}

// SessionName names Stackurity's sessions in the customer's CloudTrail.
func SessionName(workspace, connection int64) string {
	return fmt.Sprintf("stackurity-w%d-c%d", workspace, connection)
}

// AssumeRole assumes the role with the external ID for an hour.
func (c *Client) AssumeRole(ctx context.Context, roleARN, externalID, sessionName string) (*Session, error) {
	if !c.Enabled() {
		return nil, errors.New("AWS connections are not set up on this server (STACKURITY_AWS_PRINCIPAL_ARN)")
	}
	if !RoleARNRE.MatchString(roleARN) {
		return nil, errors.New("not an IAM role ARN (arn:aws:iam::123456789012:role/NAME)")
	}
	in := &sts.AssumeRoleInput{RoleArn: aws.String(roleARN), RoleSessionName: aws.String(sessionName), DurationSeconds: aws.Int32(3600)}
	if externalID != "" {
		in.ExternalId = aws.String(externalID)
	}
	out, err := c.sts().AssumeRole(ctx, in)
	if err != nil {
		return nil, Explain(err)
	}
	if out.Credentials == nil {
		return nil, errors.New("AWS returned no credentials")
	}
	return &Session{AccessKeyID: aws.ToString(out.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken: aws.ToString(out.Credentials.SessionToken), Expires: aws.ToTime(out.Credentials.Expiration), Account: AccountOf(roleARN)}, nil
}

// ErrNoExternalIDCondition: the role can be assumed without the external
// ID, so any Stackurity workspace that learnt its ARN could use it.
var ErrNoExternalIDCondition = errors.New("the role can be assumed without the external ID: its trust policy must require sts:ExternalId " +
	"(use the Stackurity template, or add the condition and verify again)")

// Verify proves the role works with the connection's external ID and only
// with it: it is assumed with the ID (which must succeed) and without it
// (which must be refused).
func (c *Client) Verify(ctx context.Context, roleARN, externalID, sessionName string) (*Session, error) {
	s, err := c.AssumeRole(ctx, roleARN, externalID, sessionName)
	if err != nil {
		return nil, err
	}
	if _, err := c.AssumeRole(ctx, roleARN, "", sessionName); err == nil {
		return nil, ErrNoExternalIDCondition
	} else if !isAccessDenied(err) {
		return nil, fmt.Errorf("checking that the role requires the external ID: %w", err)
	}
	return s, nil
}

func isAccessDenied(err error) bool {
	var ae smithy.APIError
	return errors.As(err, &ae) && ae.ErrorCode() == "AccessDenied"
}

// Explain turns an AWS error into a message an administrator can act on,
// keeping the API error as the cause.
func Explain(err error) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		msg := ae.ErrorMessage()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		switch ae.ErrorCode() {
		case "AccessDenied":
			return &apiErr{fmt.Sprintf("AWS refused: %s (AccessDenied). Check that the stack finished, that the role trusts %s, "+
				"and that the external ID matches", msg, "Stackurity's principal"), err}
		case "InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken", "UnrecognizedClientException":
			return &apiErr{"Stackurity's own AWS credentials were refused (" + ae.ErrorCode() + "): the server operator must fix them", err}
		}
		return &apiErr{fmt.Sprintf("AWS: %s (%s)", msg, ae.ErrorCode()), err}
	}
	if errors.Is(err, netguard.ErrBlocked) {
		return &apiErr{"the AWS endpoint is an internal address this organisation may not reach", err}
	}
	return err
}

type apiErr struct {
	msg   string
	cause error
}

func (e *apiErr) Error() string { return e.msg }
func (e *apiErr) Unwrap() error { return e.cause }

// Instance is an instance SSM manages.
type Instance struct {
	InstanceID   string    `json:"instance_id"`
	ComputerName string    `json:"computer_name"`
	PlatformType string    `json:"platform_type"`
	PlatformName string    `json:"platform_name"`
	PingStatus   string    `json:"ping_status"`
	IPAddress    string    `json:"ip_address"`
	LastPing     time.Time `json:"last_ping,omitempty"`
}

// MaxInstances bounds how many instances one listing returns.
const MaxInstances = 1000

// ListInstances returns the instances SSM manages in a region.
func (c *Client) ListInstances(ctx context.Context, s *Session, region string) ([]Instance, bool, error) {
	if !RegionRE.MatchString(region) {
		return nil, false, fmt.Errorf("invalid region %q", region)
	}
	p := ssm.NewDescribeInstanceInformationPaginator(c.ssm(s, region), &ssm.DescribeInstanceInformationInput{MaxResults: aws.Int32(50)})
	var out []Instance
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, false, Explain(err)
		}
		for _, i := range page.InstanceInformationList {
			if len(out) == MaxInstances {
				return out, true, nil
			}
			out = append(out, Instance{InstanceID: aws.ToString(i.InstanceId), ComputerName: aws.ToString(i.ComputerName),
				PlatformType: string(i.PlatformType), PlatformName: aws.ToString(i.PlatformName), PingStatus: string(i.PingStatus),
				IPAddress: aws.ToString(i.IPAddress), LastPing: aws.ToTime(i.LastPingDateTime)})
		}
	}
	return out, false, nil
}

// InstallCommand is the shell command SSM runs (as root) on an instance: the
// server's own installer with a single-use code made for that instance.
// Both values are checked to need no quoting beyond the single quotes.
func InstallCommand(serverURL, code string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || !shellSafe.MatchString(serverURL) {
		return "", errors.New("the server's public URL (STACKURITY_BASE_URL) is not a plain http(s) address")
	}
	if !shellSafe.MatchString(code) {
		return "", errors.New("invalid enrollment code")
	}
	return fmt.Sprintf("curl -fsSL --proto '=https,http' '%s/install/agent.sh' | STACKURITY_ENROLL_CODE='%s' sh", strings.TrimRight(serverURL, "/"), code), nil
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+$`)

// InstallTimeout is how long SSM lets the installer run.
const InstallTimeout = 10 * time.Minute

// SendInstall runs the installer on one instance and returns the command ID.
func (c *Client) SendInstall(ctx context.Context, s *Session, region, instanceID, command string) (string, error) {
	out, err := c.ssm(s, region).SendCommand(ctx, &ssm.SendCommandInput{
		DocumentName:   aws.String("AWS-RunShellScript"),
		InstanceIds:    []string{instanceID},
		Comment:        aws.String("Install the Stackurity agent"),
		TimeoutSeconds: aws.Int32(600),
		Parameters: map[string][]string{
			"commands":         {command},
			"executionTimeout": {fmt.Sprint(int(InstallTimeout.Seconds()))},
		},
	})
	if err != nil {
		return "", Explain(err)
	}
	if out.Command == nil || aws.ToString(out.Command.CommandId) == "" {
		return "", errors.New("SSM returned no command ID")
	}
	return aws.ToString(out.Command.CommandId), nil
}

// Invocation is a command's state on one instance.
type Invocation struct {
	// Status is pending, running, success, failed or timed_out.
	Status string
	Detail string
}

// GetInvocation reads how the command went on the instance.
func (c *Client) GetInvocation(ctx context.Context, s *Session, region, commandID, instanceID string) (Invocation, error) {
	out, err := c.ssm(s, region).GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{CommandId: aws.String(commandID), InstanceId: aws.String(instanceID)})
	if err != nil {
		var nf *ssmtypes.InvocationDoesNotExist
		if errors.As(err, &nf) {
			return Invocation{Status: "pending"}, nil // SSM has not registered it yet
		}
		return Invocation{}, Explain(err)
	}
	detail := strings.TrimSpace(aws.ToString(out.StandardErrorContent))
	if o := strings.TrimSpace(aws.ToString(out.StandardOutputContent)); o != "" {
		if detail != "" {
			detail = o + "\n" + detail
		} else {
			detail = o
		}
	}
	if len(detail) > 2000 {
		detail = "…" + detail[len(detail)-2000:]
	}
	var st string
	switch out.Status {
	case ssmtypes.CommandInvocationStatusPending, ssmtypes.CommandInvocationStatusDelayed:
		st = "pending"
	case ssmtypes.CommandInvocationStatusInProgress, ssmtypes.CommandInvocationStatusCancelling:
		st = "running"
	case ssmtypes.CommandInvocationStatusSuccess:
		st = "success"
	case ssmtypes.CommandInvocationStatusTimedOut:
		st = "timed_out"
	default: // Failed, Cancelled, and anything newer
		st = "failed"
		if detail == "" {
			detail = "SSM status " + string(out.Status) + fmt.Sprintf(" (exit code %d)", out.ResponseCode)
		}
	}
	return Invocation{Status: st, Detail: detail}, nil
}
