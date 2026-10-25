package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type fake struct{}

func (fake) account(context.Context) (string, error) { return "123456789012", nil }
func (fake) rds(context.Context) ([]resource, error) {
	return []resource{
		{ARN: "arn:aws:rds:eu-west-1:1:db:orders", Name: "orders", Service: "rds", Product: engineProduct("rds", "postgres"),
			Version: "13.12", Attributes: map[string]string{"engine": "postgres", "tag:Environment": "production"}},
		{ARN: "arn:aws:rds:eu-west-1:1:cluster:billing", Name: "billing", Service: "rds", Product: engineProduct("rds", "aurora-postgresql"),
			Version: "15.4", Attributes: map[string]string{}},
	}, nil
}
func (fake) elasticache(context.Context) ([]resource, error) {
	return nil, errors.New("AccessDenied: not authorized to perform elasticache:DescribeCacheClusters")
}
func (fake) eks(context.Context) ([]resource, error) {
	return []resource{{ARN: "arn:aws:eks:eu-west-1:1:cluster/main", Name: "main", Service: "eks", Product: "amazon-eks", Version: "1.27"}}, nil
}
func (fake) lambda(context.Context) ([]resource, error) {
	return []resource{{ARN: "arn:aws:lambda:eu-west-1:1:function:resize", Name: "resize", Service: "lambda", Product: "aws-lambda", Version: "python3.8"}}, nil
}
func (fake) opensearch(context.Context) ([]resource, error) { return nil, nil }

func TestCollect(t *testing.T) {
	p := awsPlugin{newClients: func(context.Context, settings, map[string]string, string) (clients, error) { return fake{}, nil }}
	cfg := json.RawMessage(`{"regions": ["eu-west-1"], "environment_tag": "Environment"}`)
	if v := p.Validate(cfg); !v.OK {
		t.Fatal(v.Problems)
	}
	batches, err := p.Collect(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for i, b := range batches {
		b.Collector.Method = "plugin"
		if err := b.Validate(); err != nil {
			t.Fatalf("batch %s: %v", b.Asset.Name, err)
		}
		byName[b.Asset.Name] = i
	}
	orders := batches[byName["orders"]]
	if orders.Asset.Environment != "production" || orders.Observations[0].Purl != "pkg:generic/amazon-rds-postgresql@13.12" ||
		orders.Asset.Provider != "aws" || orders.Asset.Region != "eu-west-1" || orders.Asset.Attributes["account"] != "123456789012" {
		t.Errorf("orders = %+v", orders)
	}
	if _, leaked := orders.Asset.Attributes["tag:Environment"]; leaked {
		t.Error("tags must not be copied into attributes")
	}
	if b := batches[byName["billing"]]; b.Observations[0].Purl != "pkg:generic/amazon-aurora-postgresql@15.4" {
		t.Errorf("billing = %+v", b.Observations)
	}
	if b := batches[byName["resize"]]; b.Observations[0].Purl != "pkg:generic/aws-lambda@python3.8" {
		t.Errorf("lambda = %+v", b.Observations)
	}
	denied, ok := byName["aws 123456789012 eu-west-1"]
	if !ok || batches[denied].Coverage[0].Status != "failed" || batches[denied].Coverage[0].Scope != "elasticache" {
		t.Errorf("denied service must show as failed coverage: %+v", byName)
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []string{`{}`, `{"regions": ["mars-1"]}`, `{"regions": ["eu-west-1"], "services": ["s3"]}`,
		`{"regions": ["eu-west-1"], "role_arn": "admin"}`, `{"regions": ["eu-west-1"], "secret_key": "x"}`} {
		if (awsPlugin{}).Validate(json.RawMessage(bad)).OK {
			t.Errorf("%s accepted", bad)
		}
	}
	if !(awsPlugin{}).Validate(json.RawMessage(`{"regions": ["us-gov-west-1", "ap-southeast-2"], "services": ["eks"]}`)).OK {
		t.Error("valid config rejected")
	}
}
