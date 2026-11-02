package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSKeys are access keys, stored as a workspace secret holding
// {"aws_access_key_id": "...", "aws_secret_access_key": "..."} (the same
// form the aws-managed plugin reads). The secret key is never sent: AWS
// requests are signed with it.
type AWSKeys struct {
	AccessKeyID     string `json:"aws_access_key_id"`
	SecretAccessKey string `json:"aws_secret_access_key"`
	SessionToken    string `json:"aws_session_token,omitempty"`
}

// ParseAWSKeys reads access keys from a secret.
func ParseAWSKeys(secret string) (AWSKeys, error) {
	var k AWSKeys
	if err := json.Unmarshal([]byte(secret), &k); err != nil || k.AccessKeyID == "" || k.SecretAccessKey == "" {
		return AWSKeys{}, errors.New(`Amazon ECR needs access keys: a secret holding {"aws_access_key_id": "...", "aws_secret_access_key": "..."}`)
	}
	return k, nil
}

// Endpoints of the AWS APIs; tests point them at fakes.
var (
	ecrEndpoint = func(region string) string {
		if strings.HasPrefix(region, "cn-") {
			return "https://api.ecr." + region + ".amazonaws.com.cn"
		}
		return "https://api.ecr." + region + ".amazonaws.com"
	}
	stsEndpoint = func(region string) string {
		if strings.HasPrefix(region, "cn-") {
			return "https://sts." + region + ".amazonaws.com.cn"
		}
		return "https://sts." + region + ".amazonaws.com"
	}
)

var ecrHostRE = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`)

type ecrSource struct {
	hc       *http.Client
	endpoint *url.URL
	region   string
	account  string
	creds    aws.CredentialsProvider
	registry string // <account>.dkr.ecr.<region>.amazonaws.com
}

func newECR(ctx context.Context, cfg Config, keys AWSKeys) (*ecrSource, error) {
	// Validate checked it already; the endpoint hosts are built from it.
	if !regionRE.MatchString(cfg.Region) {
		return nil, fmt.Errorf("invalid AWS region %q", cfg.Region)
	}
	hc := newHTTPClient()
	var prov aws.CredentialsProvider = credentials.NewStaticCredentialsProvider(keys.AccessKeyID, keys.SecretAccessKey, keys.SessionToken)
	if cfg.RoleARN != "" {
		ep := stsEndpoint(cfg.Region)
		client := sts.New(sts.Options{Region: cfg.Region, Credentials: prov, HTTPClient: hc, BaseEndpoint: &ep})
		prov = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(client, cfg.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "stackurity-ecr"
			if cfg.ExternalID != "" {
				o.ExternalID = aws.String(cfg.ExternalID)
			}
		}))
	}
	e := &ecrSource{hc: hc, endpoint: mustURL(ecrEndpoint(cfg.Region)), region: cfg.Region, account: cfg.AccountID, creds: prov}
	if cfg.AccountID != "" {
		e.registry = cfg.AccountID + ".dkr.ecr." + cfg.Region + ".amazonaws.com"
		if strings.HasPrefix(cfg.Region, "cn-") {
			e.registry += ".cn"
		}
		return e, nil
	}
	// The account is the one the keys (or role) belong to.
	if _, _, err := e.Login(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *ecrSource) refBase(repo string) string { return e.registry + "/" + repo }
func (e *ecrSource) host() string               { return e.registry }

// call makes one signed ECR API request.
func (e *ecrSource) call(ctx context.Context, action string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	u := *e.endpoint
	u.Path = "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921."+action)
	creds, err := e.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("AWS credentials: %s", firstLine(err.Error()))
	}
	sum := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "ecr", e.region, time.Now()); err != nil {
		return err
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		var ae struct {
			Type    string `json:"__type"`
			Message string `json:"message"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = json.Unmarshal(b, &ae)
		typ := ae.Type
		if i := strings.LastIndex(typ, "#"); i >= 0 {
			typ = typ[i+1:]
		}
		msg := strings.TrimSpace(typ + " " + ae.Message)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		code := resp.StatusCode
		if typ == "RepositoryNotFoundException" {
			code = http.StatusNotFound
		}
		return &StatusError{Code: code, msg: fmt.Sprintf("Amazon ECR %s answered %s %s", action, resp.Status, msg)}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxListBody)).Decode(out); err != nil {
		return fmt.Errorf("Amazon ECR %s sent an unreadable answer", action)
	}
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// Login gets a registry password for image scans (user AWS), valid for
// 12 hours, and learns the registry's host.
func (e *ecrSource) Login(ctx context.Context) (string, string, error) {
	var out struct {
		AuthorizationData []struct {
			AuthorizationToken string `json:"authorizationToken"`
			ProxyEndpoint      string `json:"proxyEndpoint"`
		} `json:"authorizationData"`
	}
	in := map[string]any{}
	if e.account != "" {
		in["registryIds"] = []string{e.account}
	}
	if err := e.call(ctx, "GetAuthorizationToken", in, &out); err != nil {
		return "", "", err
	}
	if len(out.AuthorizationData) == 0 {
		return "", "", errors.New("Amazon ECR returned no authorization")
	}
	ad := out.AuthorizationData[0]
	pu, err := url.Parse(ad.ProxyEndpoint)
	if err != nil || !ecrHostRE.MatchString(pu.Host) {
		return "", "", errors.New("Amazon ECR returned an unexpected registry address")
	}
	if e.registry == "" {
		e.registry = pu.Host
	} else if e.registry != pu.Host {
		return "", "", fmt.Errorf("Amazon ECR authorized %s, not %s", pu.Host, e.registry)
	}
	raw, err := base64.StdEncoding.DecodeString(ad.AuthorizationToken)
	if err != nil {
		return "", "", errors.New("Amazon ECR returned an unreadable authorization")
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user == "" || pass == "" {
		return "", "", errors.New("Amazon ECR returned an unreadable authorization")
	}
	return user, pass, nil
}

func (e *ecrSource) registryID(in map[string]any) map[string]any {
	if e.account != "" {
		in["registryId"] = e.account
	}
	return in
}

func (e *ecrSource) repositories(ctx context.Context) ([]string, bool, error) {
	var out []string
	token := ""
	for page := 0; page < maxPages; page++ {
		in := e.registryID(map[string]any{"maxResults": 1000})
		if token != "" {
			in["nextToken"] = token
		}
		var resp struct {
			Repositories []struct {
				RepositoryName string `json:"repositoryName"`
			} `json:"repositories"`
			NextToken string `json:"nextToken"`
		}
		if err := e.call(ctx, "DescribeRepositories", in, &resp); err != nil {
			return nil, false, err
		}
		for _, r := range resp.Repositories {
			if nameRE.MatchString(r.RepositoryName) {
				out = append(out, r.RepositoryName)
			}
		}
		if resp.NextToken == "" {
			return out, true, nil
		}
		if len(out) >= MaxTags {
			break
		}
		token = resp.NextToken
	}
	return out, false, nil
}

func (e *ecrSource) tags(ctx context.Context, repo string, _ *Selector, _ map[string]time.Time) ([]Tag, bool, error) {
	var out []Tag
	token := ""
	for page := 0; page < maxPages; page++ {
		in := e.registryID(map[string]any{"repositoryName": repo, "maxResults": 1000, "filter": map[string]string{"tagStatus": "TAGGED"}})
		if token != "" {
			in["nextToken"] = token
		}
		var resp struct {
			ImageDetails []struct {
				ImageDigest   string   `json:"imageDigest"`
				ImageTags     []string `json:"imageTags"`
				ImagePushedAt float64  `json:"imagePushedAt"`
			} `json:"imageDetails"`
			NextToken string `json:"nextToken"`
		}
		if err := e.call(ctx, "DescribeImages", in, &resp); err != nil {
			return nil, false, err
		}
		for _, d := range resp.ImageDetails {
			if !digestRE.MatchString(d.ImageDigest) {
				continue
			}
			sec, frac := math.Modf(d.ImagePushedAt)
			pushed := time.Unix(int64(sec), int64(frac*1e9)).UTC()
			for _, t := range d.ImageTags {
				out = append(out, Tag{Name: t, Digest: d.ImageDigest, Pushed: pushed})
			}
		}
		if resp.NextToken == "" {
			return out, true, nil
		}
		if len(out) >= MaxTags {
			break
		}
		token = resp.NextToken
	}
	return out, false, nil
}
