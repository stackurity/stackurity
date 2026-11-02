// Package awsconnect connects a customer's AWS account with a CloudFormation
// stack instead of a hand-made IAM role: the stack creates a read-only role
// that trusts Stackurity's AWS principal on condition of an external ID
// Stackurity generated for the connection, reports the role back (a custom
// resource that calls Stackurity once with a signed, single-use token, or
// the administrator pastes the ARN), and Stackurity checks it with
// sts:AssumeRole before anything runs. Optionally the role can also run the
// agent installer on EC2 instances through SSM Run Command.
package awsconnect

import (
	"bytes"
	"encoding/json"
)

// TemplateVersion changes whenever the template does; it is part of the file
// name the template is hosted under, so an existing stack link keeps working
// with the template it was made for.
const TemplateVersion = "1"

// TemplateFile is the name the template is published under (in S3 for the
// CloudFormation console, and at /aws/<TemplateFile> on every server).
const TemplateFile = "stackurity-aws-role-v" + TemplateVersion + ".json"

// ReadOnlyActions are the API calls the aws-managed plugin makes
// (plugins/aws-managed/main.go), and nothing else. None of these actions
// supports resource-level permissions, so the statement's resource is "*".
// sts:GetCallerIdentity needs no permission and is not listed.
var ReadOnlyActions = []string{
	"eks:DescribeCluster",
	"eks:ListClusters",
	"elasticache:DescribeCacheClusters",
	"es:DescribeDomains",
	"es:ListDomainNames",
	"lambda:ListFunctions",
	"rds:DescribeDBClusters",
	"rds:DescribeDBInstances",
}

// AgentInstallListActions are needed to list the instances SSM manages and
// read the result of a command; neither supports resource-level permissions.
var AgentInstallListActions = []string{
	"ssm:DescribeInstanceInformation",
	"ssm:GetCommandInvocation",
}

// AgentInstallRunAction runs the agent installer. It is limited to the
// AWS-RunShellScript document and the account's own instances.
const AgentInstallRunAction = "ssm:SendCommand"

// callbackFunction is the custom resource's code: on Create it waits for the
// new role to be usable, posts the role ARN to Stackurity with the token, and
// always reports success to CloudFormation (if the call fails, the
// administrator pastes the ARN from the stack outputs instead). It never
// logs the token.
const callbackFunction = `import json, time, urllib.request


def respond(event, context, status):
    body = json.dumps({
        "Status": status,
        "Reason": "See CloudWatch log stream " + context.log_stream_name,
        "PhysicalResourceId": event.get("PhysicalResourceId") or "stackurity-callback",
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": {},
    }).encode()
    req = urllib.request.Request(event["ResponseURL"], data=body, method="PUT",
                                 headers={"Content-Type": "", "Content-Length": str(len(body))})
    urllib.request.urlopen(req, timeout=20)


def handler(event, context):
    try:
        if event["RequestType"] == "Create":
            p = event["ResourceProperties"]
            time.sleep(10)  # a new IAM role takes a few seconds to be usable
            data = json.dumps({"role_arn": p["RoleArn"], "external_id": p["ExternalId"],
                               "stack_id": event["StackId"]}).encode()
            req = urllib.request.Request(p["Url"], data=data, method="POST", headers={
                "Content-Type": "application/json", "Authorization": "Bearer " + p["Token"]})
            try:
                urllib.request.urlopen(req, timeout=30)
                print("Stackurity has the role ARN")
            except Exception as e:
                print("Could not reach Stackurity (%s); paste the RoleArn output into Stackurity instead" % type(e).__name__)
    finally:
        respond(event, context, "SUCCESS")
`

type obj = map[string]any

func ref(name string) obj { return obj{"Ref": name} }

// Template returns the CloudFormation template (JSON). It is the same for
// every server and workspace: what differs (the external ID, the trusted
// principal, the callback) is passed as parameters.
func Template() []byte {
	readOnly := obj{
		"Version": "2012-10-17",
		"Statement": []obj{{
			"Sid":      "ReadManagedServiceVersions",
			"Effect":   "Allow",
			"Action":   ReadOnlyActions,
			"Resource": "*",
		}},
	}
	agentInstall := obj{
		"Version": "2012-10-17",
		"Statement": []obj{
			{
				"Sid":      "ListManagedInstances",
				"Effect":   "Allow",
				"Action":   AgentInstallListActions,
				"Resource": "*",
			},
			{
				"Sid":    "RunAgentInstaller",
				"Effect": "Allow",
				"Action": []string{AgentInstallRunAction},
				"Resource": []any{
					obj{"Fn::Sub": "arn:${AWS::Partition}:ssm:*::document/AWS-RunShellScript"},
					obj{"Fn::Sub": "arn:${AWS::Partition}:ec2:*:${AWS::AccountId}:instance/*"},
				},
			},
		},
	}
	t := obj{
		"AWSTemplateFormatVersion": "2010-09-09",
		"Description": "Stackurity read-only access (template v" + TemplateVersion + "). Creates an IAM role that Stackurity assumes with " +
			"your connection's external ID to read RDS, Aurora, ElastiCache, EKS, Lambda and OpenSearch versions, and optionally " +
			"to install the Stackurity agent on EC2 instances through SSM Run Command.",
		"Metadata": obj{
			"AWS::CloudFormation::Interface": obj{
				"ParameterGroups": []obj{
					{"Label": obj{"default": "Filled in by Stackurity: do not change"}, "Parameters": []string{"StackurityPrincipal", "ExternalId", "CallbackUrl", "CallbackToken"}},
					{"Label": obj{"default": "Options"}, "Parameters": []string{"EnableAgentInstall"}},
				},
				"ParameterLabels": obj{
					"StackurityPrincipal": obj{"default": "Stackurity's AWS principal (trusted to assume the role)"},
					"ExternalId":          obj{"default": "External ID of this connection"},
					"CallbackUrl":         obj{"default": "Where the stack reports the role ARN (empty: paste it yourself)"},
					"CallbackToken":       obj{"default": "Single-use token for the report"},
					"EnableAgentInstall":  obj{"default": "Allow installing the Stackurity agent on EC2 instances through SSM"},
				},
			},
		},
		"Parameters": obj{
			"StackurityPrincipal": obj{
				"Type":                  "String",
				"Description":           "ARN of the IAM user or role Stackurity calls AWS with, or arn:aws:iam::ACCOUNT:root.",
				"AllowedPattern":        `^arn:aws:iam::[0-9]{12}:(root|user/[\w+=,.@/-]+|role/[\w+=,.@/-]+)$`,
				"ConstraintDescription": "an IAM user, role or account root ARN",
			},
			"ExternalId": obj{
				"Type":                  "String",
				"Description":           "Generated by Stackurity for this connection; the role can only be assumed with it.",
				"AllowedPattern":        `^stk-[0-9a-f]{32}$`,
				"ConstraintDescription": "the external ID Stackurity shows for this connection",
			},
			"EnableAgentInstall": obj{
				"Type":          "String",
				"Description":   "true adds ssm:DescribeInstanceInformation, ssm:GetCommandInvocation and ssm:SendCommand (AWS-RunShellScript only).",
				"AllowedValues": []string{"false", "true"},
				"Default":       "false",
			},
			"CallbackUrl": obj{
				"Type":           "String",
				"Description":    "Stackurity's HTTPS address for the role ARN. Leave empty to paste the ARN from the outputs instead.",
				"AllowedPattern": `^(https://[^\s]+)?$`,
				"Default":        "",
			},
			"CallbackToken": obj{
				"Type":        "String",
				"Description": "Signed, single-use token that ties the report to this connection.",
				"NoEcho":      true,
				"Default":     "",
			},
		},
		"Conditions": obj{
			"AgentInstall": obj{"Fn::Equals": []any{ref("EnableAgentInstall"), "true"}},
			"Callback": obj{"Fn::And": []any{
				obj{"Fn::Not": []any{obj{"Fn::Equals": []any{ref("CallbackUrl"), ""}}}},
				obj{"Fn::Not": []any{obj{"Fn::Equals": []any{ref("CallbackToken"), ""}}}},
			}},
		},
		"Resources": obj{
			"StackurityRole": obj{
				"Type": "AWS::IAM::Role",
				"Properties": obj{
					"Description":        "Read-only access for Stackurity (external ID required)",
					"MaxSessionDuration": 3600,
					"AssumeRolePolicyDocument": obj{
						"Version": "2012-10-17",
						"Statement": []obj{{
							"Effect":    "Allow",
							"Principal": obj{"AWS": ref("StackurityPrincipal")},
							"Action":    "sts:AssumeRole",
							"Condition": obj{"StringEquals": obj{"sts:ExternalId": ref("ExternalId")}},
						}},
					},
					"Policies": []any{
						obj{"PolicyName": "stackurity-read-only", "PolicyDocument": readOnly},
						obj{"Fn::If": []any{"AgentInstall",
							obj{"PolicyName": "stackurity-agent-install", "PolicyDocument": agentInstall},
							ref("AWS::NoValue")}},
					},
					"Tags": []obj{{"Key": "managed-by", "Value": "stackurity"}},
				},
			},
			"CallbackFunctionRole": obj{
				"Type":      "AWS::IAM::Role",
				"Condition": "Callback",
				"Properties": obj{
					"Description": "Lets the Stackurity callback function write its logs",
					"AssumeRolePolicyDocument": obj{
						"Version": "2012-10-17",
						"Statement": []obj{{
							"Effect":    "Allow",
							"Principal": obj{"Service": "lambda.amazonaws.com"},
							"Action":    "sts:AssumeRole",
						}},
					},
					"ManagedPolicyArns": []any{obj{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"}},
				},
			},
			"CallbackFunction": obj{
				"Type":      "AWS::Lambda::Function",
				"Condition": "Callback",
				"Properties": obj{
					"Description": "Reports the Stackurity role ARN to Stackurity once, when the stack is created",
					"Runtime":     "python3.13",
					"Handler":     "index.handler",
					"Timeout":     60,
					"MemorySize":  128,
					"Role":        obj{"Fn::GetAtt": []string{"CallbackFunctionRole", "Arn"}},
					"Code":        obj{"ZipFile": callbackFunction},
				},
			},
			"Callback": obj{
				"Type":      "Custom::StackurityCallback",
				"Condition": "Callback",
				"Properties": obj{
					"ServiceToken": obj{"Fn::GetAtt": []string{"CallbackFunction", "Arn"}},
					"RoleArn":      obj{"Fn::GetAtt": []string{"StackurityRole", "Arn"}},
					"ExternalId":   ref("ExternalId"),
					"Url":          ref("CallbackUrl"),
					"Token":        ref("CallbackToken"),
				},
			},
		},
		"Outputs": obj{
			"RoleArn": obj{
				"Description": "Paste this into Stackurity if it did not pick the role up by itself",
				"Value":       obj{"Fn::GetAtt": []string{"StackurityRole", "Arn"}},
			},
			"ExternalId": obj{"Description": "The connection's external ID", "Value": ref("ExternalId")},
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(t); err != nil {
		panic(err) // a fixed structure of strings and maps
	}
	return buf.Bytes()
}
