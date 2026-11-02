package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/stackurity/stackurity/internal/awsconnect"
)

// awsConnectFromEnv sets up connecting AWS with a CloudFormation stack
// (docs/install.md, "AWS managed services"). It is off unless
// STACKURITY_AWS_PRINCIPAL_ARN names the IAM user or role this server calls
// AWS as; its credentials come from the AWS SDK's default chain
// (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, AWS_PROFILE, or an instance
// or task role). Nothing is sent to AWS until an administrator connects an
// account.
func awsConnectFromEnv(ctx context.Context, log *slog.Logger) (*awsconnect.Client, error) {
	principal := strings.TrimSpace(os.Getenv("STACKURITY_AWS_PRINCIPAL_ARN"))
	tmpl := strings.TrimSpace(os.Getenv("STACKURITY_AWS_TEMPLATE_URL"))
	if principal == "" {
		if tmpl != "" {
			log.Warn("STACKURITY_AWS_TEMPLATE_URL is ignored without STACKURITY_AWS_PRINCIPAL_ARN")
		}
		return nil, nil
	}
	if !awsconnect.PrincipalRE.MatchString(principal) {
		return nil, fmt.Errorf("STACKURITY_AWS_PRINCIPAL_ARN must be an IAM user, role or account root ARN (arn:aws:iam::123456789012:user/stackurity), not %q", principal)
	}
	if tmpl != "" {
		u, err := url.Parse(tmpl)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("STACKURITY_AWS_TEMPLATE_URL must be an https:// URL of the template in S3")
		}
		if !strings.HasSuffix(u.Hostname(), ".amazonaws.com") {
			log.Warn("the CloudFormation console only opens templates stored in Amazon S3", "STACKURITY_AWS_TEMPLATE_URL", tmpl)
		}
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credentials for STACKURITY_AWS_PRINCIPAL_ARN: %w", err)
	}
	log.Info("AWS connections enabled", "principal", principal, "launch_stack", tmpl != "")
	return &awsconnect.Client{Principal: principal, TemplateURL: tmpl, Credentials: cfg.Credentials, PropagationDelay: 4 * time.Second}, nil
}
