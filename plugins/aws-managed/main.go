// Command aws-managed is a first-party Stackurity plugin that inventories
// AWS managed services through read-only APIs: RDS and Aurora engines,
// ElastiCache, EKS, Lambda runtimes and OpenSearch. Each resource becomes a
// managed_service asset whose engine/runtime version is matched against
// endoflife.date lifecycle data (amazon-rds-postgresql, amazon-eks,
// aws-lambda, ...).
//
// Provider-managed internals (OS packages inside RDS, etc.) are not
// visible through these APIs and are not reported (PRD §4 non-goal).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/pkg/plugin"
)

var allServices = []string{"rds", "elasticache", "eks", "lambda", "opensearch"}

type settings struct {
	Regions        []string `json:"regions"`
	Services       []string `json:"services,omitempty"` // default: all
	RoleARN        string   `json:"role_arn,omitempty"` // optional role to assume (read-only)
	ExternalID     string   `json:"external_id,omitempty"`
	EnvironmentTag string   `json:"environment_tag,omitempty"` // e.g. "Environment"
}

var regionRE = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-\d$`)

func parse(raw json.RawMessage) (settings, []string) {
	var s settings
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, []string{"config: " + err.Error()}
	}
	var p []string
	if len(s.Regions) == 0 || len(s.Regions) > 40 {
		p = append(p, "regions must list 1-40 AWS regions")
	}
	for _, r := range s.Regions {
		if !regionRE.MatchString(r) {
			p = append(p, fmt.Sprintf("invalid region %q", r))
		}
	}
	if len(s.Services) == 0 {
		s.Services = allServices
	}
	for _, sv := range s.Services {
		if !contains(allServices, sv) {
			p = append(p, fmt.Sprintf("unknown service %q (supported: %s)", sv, strings.Join(allServices, ", ")))
		}
	}
	if s.RoleARN != "" && !strings.HasPrefix(s.RoleARN, "arn:aws") {
		p = append(p, "role_arn must be an IAM role ARN")
	}
	return s, p
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

type awsPlugin struct {
	// newClients is replaceable in tests.
	newClients func(ctx context.Context, s settings, secrets map[string]string, region string) (clients, error)
}

func (awsPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		ID: "aws-managed", Name: "AWS managed services", Version: "0.1.0",
		Maintainer: "Stackurity contributors", License: "Apache-2.0",
		Homepage:     "https://github.com/stackurity/stackurity/tree/main/plugins/aws-managed",
		Description:  "Engine and runtime versions of RDS, Aurora, ElastiCache, EKS, Lambda and OpenSearch, for lifecycle and upgrade tracking.",
		Capabilities: []string{"inventory:managed_service"},
		Permissions: []string{
			"rds:DescribeDBInstances", "rds:DescribeDBClusters", "elasticache:DescribeCacheClusters",
			"eks:ListClusters", "eks:DescribeCluster", "lambda:ListFunctions",
			"es:ListDomainNames", "es:DescribeDomains", "sts:GetCallerIdentity", "sts:AssumeRole (only with role_arn)",
		},
		Credentials:   []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token (optional)"},
		NetworkAccess: []string{"*.amazonaws.com (regional API endpoints)", "169.254.169.254 (instance metadata, when no keys are given)"},
		ConfigSchema: []plugin.ConfigField{
			{Name: "regions", Type: "string_list", Required: true, Description: "AWS regions to scan"},
			{Name: "services", Type: "string_list", Description: "subset of rds, elasticache, eks, lambda, opensearch"},
			{Name: "role_arn", Type: "string", Description: "read-only role to assume"},
			{Name: "external_id", Type: "string", Description: "external id for the role"},
			{Name: "environment_tag", Type: "string", Description: "resource tag whose value is used as the environment"},
		},
		Frequency:  "12h",
		RateLimits: "one paginated List/Describe call sequence per service and region",
		Limitations: []string{
			"provider-managed operating system and engine internals are not visible",
			"Lambda function tags are not read (environment comes from config only)",
			"vulnerability data for managed engines is published by AWS, not tracked here; lifecycle is",
		},
	}
}

func (awsPlugin) Validate(raw json.RawMessage) plugin.ValidationResult {
	_, p := parse(raw)
	return plugin.ValidationResult{OK: len(p) == 0, Problems: p}
}

func (a awsPlugin) Collect(ctx context.Context, raw json.RawMessage, secrets map[string]string) ([]*plugin.ObservationBatch, error) {
	s, p := parse(raw)
	if len(p) > 0 {
		return nil, errors.New(strings.Join(p, "; "))
	}
	if len(s.Services) == 0 {
		s.Services = allServices
	}
	var out []*plugin.ObservationBatch
	var account string
	for _, region := range s.Regions {
		cl, err := a.newClients(ctx, s, secrets, region)
		if err != nil {
			return nil, err
		}
		if account == "" {
			account, err = cl.account(ctx)
			if err != nil {
				return nil, fmt.Errorf("credentials check failed: %w", err)
			}
		}
		for _, svc := range s.Services {
			res, err := collectService(ctx, cl, svc, region, s.EnvironmentTag)
			if err != nil {
				// A service the role cannot read is reported, not hidden.
				out = append(out, coverageOnly(account, region, svc, err))
				continue
			}
			for _, r := range res {
				out = append(out, r.batch(account, region))
			}
		}
	}
	return out, nil
}

func (a awsPlugin) Health(ctx context.Context, raw json.RawMessage, secrets map[string]string) plugin.HealthStatus {
	s, p := parse(raw)
	if len(p) > 0 {
		return plugin.HealthStatus{Message: strings.Join(p, "; ")}
	}
	cl, err := a.newClients(ctx, s, secrets, s.Regions[0])
	if err != nil {
		return plugin.HealthStatus{Message: err.Error()}
	}
	acct, err := cl.account(ctx)
	if err != nil {
		return plugin.HealthStatus{Message: "credentials: " + err.Error()}
	}
	return plugin.HealthStatus{OK: true, Message: "authenticated to account " + acct}
}

// resource is one managed service instance.
type resource struct {
	ARN         string
	Name        string
	Service     string // rds, elasticache, ...
	Product     string // endoflife.date product, e.g. amazon-rds-postgresql
	Version     string
	Environment string
	Attributes  map[string]string
}

func (r resource) batch(account, region string) *plugin.ObservationBatch {
	attrs := map[string]string{"service": r.Service, "account": account}
	for k, v := range r.Attributes {
		attrs[k] = v
	}
	b := plugin.NewBatch(plugin.Collector{ID: "aws-managed"}, plugin.AssetRef{
		Kind: plugin.AssetManagedService, Name: r.Name, Provider: "aws", Region: region, Environment: r.Environment,
		Identifiers: []plugin.Identifier{{Scheme: "arn", Value: r.ARN}}, Attributes: attrs,
	})
	b.Complete = true
	if r.Version == "" {
		b.Cover(r.Service, "partial", "the API did not return a version")
		return b
	}
	b.Observations = append(b.Observations, plugin.Observation{
		Purl:       packageurl.NewPackageURL("generic", "", r.Product, r.Version, nil, "").ToString(),
		Version:    r.Version,
		Location:   r.ARN,
		Confidence: plugin.ConfidenceConfirmed,
		Evidence:   map[string]string{"kind": "managed-service", "source": "AWS " + r.Service + " API"},
	})
	b.Cover(r.Service, "checked", "")
	return b
}

// coverageOnly records a service/region that could not be read, as an
// account-level asset so the gap is visible.
func coverageOnly(account, region, svc string, err error) *plugin.ObservationBatch {
	b := plugin.NewBatch(plugin.Collector{ID: "aws-managed"}, plugin.AssetRef{
		Kind: plugin.AssetManagedService, Name: fmt.Sprintf("aws %s %s", account, region), Provider: "aws", Region: region,
		Identifiers: []plugin.Identifier{{Scheme: "aws-account-region", Value: account + "/" + region}},
		Attributes:  map[string]string{"account": account},
	})
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	b.Cover(svc, "failed", msg)
	return b
}

// engineProduct maps an engine name to an endoflife.date product.
func engineProduct(service, engine string) string {
	switch service + ":" + strings.ToLower(engine) {
	case "rds:postgres":
		return "amazon-rds-postgresql"
	case "rds:mysql":
		return "amazon-rds-mysql"
	case "rds:mariadb":
		return "amazon-rds-mariadb"
	case "rds:aurora-postgresql":
		return "amazon-aurora-postgresql"
	case "rds:aurora-mysql", "rds:aurora":
		return "amazon-aurora-mysql"
	case "elasticache:redis":
		return "amazon-elasticache-redis"
	case "elasticache:valkey":
		return "valkey"
	case "elasticache:memcached":
		return "memcached"
	}
	return "aws-" + service + "-" + strings.ToLower(engine)
}

func tagValue(tags map[string]string, key string) string {
	if key == "" {
		return ""
	}
	for k, v := range tags {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func main() {
	plugin.Serve(awsPlugin{newClients: sdkClients})
}

// --- SDK wiring

func sdkClients(ctx context.Context, s settings, secrets map[string]string, region string) (clients, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if id, key := secrets["aws_access_key_id"], secrets["aws_secret_access_key"]; id != "" && key != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, key, secrets["aws_session_token"])))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	if s.RoleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), s.RoleARN,
			func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = "stackurity-inventory"
				if s.ExternalID != "" {
					o.ExternalID = aws.String(s.ExternalID)
				}
			}))
	}
	return &sdk{cfg: cfg}, nil
}

type clients interface {
	account(ctx context.Context) (string, error)
	rds(ctx context.Context) ([]resource, error)
	elasticache(ctx context.Context) ([]resource, error)
	eks(ctx context.Context) ([]resource, error)
	lambda(ctx context.Context) ([]resource, error)
	opensearch(ctx context.Context) ([]resource, error)
}

func collectService(ctx context.Context, cl clients, svc, region, envTag string) ([]resource, error) {
	var res []resource
	var err error
	switch svc {
	case "rds":
		res, err = cl.rds(ctx)
	case "elasticache":
		res, err = cl.elasticache(ctx)
	case "eks":
		res, err = cl.eks(ctx)
	case "lambda":
		res, err = cl.lambda(ctx)
	case "opensearch":
		res, err = cl.opensearch(ctx)
	}
	if err != nil {
		return nil, err
	}
	for i := range res {
		res[i].Environment = tagValue(res[i].Attributes, "tag:"+envTag)
		if envTag != "" {
			if v, ok := res[i].Attributes["tag:"+envTag]; ok {
				res[i].Environment = v
			}
		}
		for k := range res[i].Attributes {
			if strings.HasPrefix(k, "tag:") {
				delete(res[i].Attributes, k) // tags are only used for environment
			}
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ARN < res[j].ARN })
	return res, nil
}

type sdk struct{ cfg aws.Config }

func (c *sdk) account(ctx context.Context) (string, error) {
	out, err := sts.NewFromConfig(c.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Account), nil
}

func (c *sdk) rds(ctx context.Context) ([]resource, error) {
	cl := rds.NewFromConfig(c.cfg)
	var out []resource
	clustered := map[string]bool{}
	cp := rds.NewDescribeDBClustersPaginator(cl, &rds.DescribeDBClustersInput{})
	for cp.HasMorePages() {
		page, err := cp.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range page.DBClusters {
			attrs := map[string]string{"engine": aws.ToString(d.Engine), "engine_mode": aws.ToString(d.EngineMode)}
			for _, t := range d.TagList {
				attrs["tag:"+aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			for _, m := range d.DBClusterMembers {
				clustered[aws.ToString(m.DBInstanceIdentifier)] = true
			}
			out = append(out, resource{ARN: aws.ToString(d.DBClusterArn), Name: aws.ToString(d.DBClusterIdentifier), Service: "rds",
				Product: engineProduct("rds", aws.ToString(d.Engine)), Version: aws.ToString(d.EngineVersion), Attributes: attrs})
		}
	}
	ip := rds.NewDescribeDBInstancesPaginator(cl, &rds.DescribeDBInstancesInput{})
	for ip.HasMorePages() {
		page, err := ip.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range page.DBInstances {
			if clustered[aws.ToString(d.DBInstanceIdentifier)] {
				continue // reported with its cluster
			}
			attrs := map[string]string{"engine": aws.ToString(d.Engine), "instance_class": aws.ToString(d.DBInstanceClass)}
			if d.PubliclyAccessible != nil {
				attrs["publicly_accessible"] = fmt.Sprint(*d.PubliclyAccessible)
			}
			if d.AutoMinorVersionUpgrade != nil {
				attrs["auto_minor_version_upgrade"] = fmt.Sprint(*d.AutoMinorVersionUpgrade)
			}
			for _, t := range d.TagList {
				attrs["tag:"+aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			out = append(out, resource{ARN: aws.ToString(d.DBInstanceArn), Name: aws.ToString(d.DBInstanceIdentifier), Service: "rds",
				Product: engineProduct("rds", aws.ToString(d.Engine)), Version: aws.ToString(d.EngineVersion), Attributes: attrs})
		}
	}
	return out, nil
}

func (c *sdk) elasticache(ctx context.Context) ([]resource, error) {
	p := elasticache.NewDescribeCacheClustersPaginator(elasticache.NewFromConfig(c.cfg), &elasticache.DescribeCacheClustersInput{})
	var out []resource
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cc := range page.CacheClusters {
			out = append(out, resource{ARN: aws.ToString(cc.ARN), Name: aws.ToString(cc.CacheClusterId), Service: "elasticache",
				Product: engineProduct("elasticache", aws.ToString(cc.Engine)), Version: aws.ToString(cc.EngineVersion),
				Attributes: map[string]string{"engine": aws.ToString(cc.Engine), "node_type": aws.ToString(cc.CacheNodeType)}})
		}
	}
	return out, nil
}

func (c *sdk) eks(ctx context.Context) ([]resource, error) {
	cl := eks.NewFromConfig(c.cfg)
	p := eks.NewListClustersPaginator(cl, &eks.ListClustersInput{})
	var out []resource
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, name := range page.Clusters {
			d, err := cl.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
			if err != nil {
				return nil, err
			}
			attrs := map[string]string{"platform_version": aws.ToString(d.Cluster.PlatformVersion)}
			for k, v := range d.Cluster.Tags {
				attrs["tag:"+k] = v
			}
			out = append(out, resource{ARN: aws.ToString(d.Cluster.Arn), Name: name, Service: "eks", Product: "amazon-eks",
				Version: aws.ToString(d.Cluster.Version), Attributes: attrs})
		}
	}
	return out, nil
}

func (c *sdk) lambda(ctx context.Context) ([]resource, error) {
	p := lambda.NewListFunctionsPaginator(lambda.NewFromConfig(c.cfg), &lambda.ListFunctionsInput{})
	var out []resource
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, f := range page.Functions {
			runtime := string(f.Runtime)
			if runtime == "" {
				continue // container-image functions: scan the image instead
			}
			out = append(out, resource{ARN: aws.ToString(f.FunctionArn), Name: aws.ToString(f.FunctionName), Service: "lambda",
				Product: "aws-lambda", Version: runtime, Attributes: map[string]string{"runtime": runtime}})
		}
	}
	return out, nil
}

func (c *sdk) opensearch(ctx context.Context) ([]resource, error) {
	cl := opensearch.NewFromConfig(c.cfg)
	names, err := cl.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, err
	}
	var list []string
	for _, d := range names.DomainNames {
		list = append(list, aws.ToString(d.DomainName))
	}
	var out []resource
	for i := 0; i < len(list); i += 5 {
		end := i + 5
		if end > len(list) {
			end = len(list)
		}
		desc, err := cl.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{DomainNames: list[i:end]})
		if err != nil {
			return nil, err
		}
		for _, d := range desc.DomainStatusList {
			v := aws.ToString(d.EngineVersion) // "OpenSearch_2.11" or "Elasticsearch_7.10"
			product, ver := "amazon-opensearch", v
			if eng, num, ok := strings.Cut(v, "_"); ok {
				ver = num
				if strings.EqualFold(eng, "Elasticsearch") {
					product = "amazon-elasticsearch"
				}
			}
			out = append(out, resource{ARN: aws.ToString(d.ARN), Name: aws.ToString(d.DomainName), Service: "opensearch",
				Product: product, Version: ver, Attributes: map[string]string{"engine_version": v}})
		}
	}
	return out, nil
}
