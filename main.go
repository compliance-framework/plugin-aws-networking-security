package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-networking-security/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"iter"
	"os"
	"slices"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		l.logger.Error("unable to load SDK config", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	client := ec2.NewFromConfig(cfg)

	// Run policy checks
	for group, err := range getSecurityGroups(ctx, client) {
		if err != nil {
			l.logger.Error("unable to get instance", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			break
		}

		labels := map[string]string{
			"provider": "aws",
			"type":     "security-group",
			"group-id": aws.ToString(group.GroupId),
			"_vpc-id":  aws.ToString(group.VpcId),
		}

		activities := make([]*proto.Activity, 0)
		evidences := make([]*proto.Evidence, 0)

		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework"),
					},
				},
			},
			{
				Title: "Continuous Compliance Framework - Local SSH Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-local-ssh",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework' Local SSH Plugin"),
					},
				},
			},
		}
		components := []*proto.Component{
			{
				Identifier:  "common-components/amazon-security-group",
				Type:        "service",
				Title:       "Amazon Security Groups",
				Description: "Amazon Security Groups act as virtual firewalls for AWS resources such as EC2 instances and RDS databases. They control inbound and outbound traffic at the instance level using rule-based configurations tied to ports, protocols, and CIDR ranges. Security Groups are stateful and can reference other groups to enforce dynamic trust boundaries within a VPC.",
				Purpose:     "To enforce network segmentation and access control policies at the resource level, providing a configurable and auditable security boundary for cloud-based assets in support of least privilege and Zero Trust architectures.",
			},
		}
		inventory := []*proto.InventoryItem{
			{
				Identifier: fmt.Sprintf("aws-security-group/%s", aws.ToString(group.GroupId)),
				Type:       "firewall",
				Title:      fmt.Sprintf("Amazon Security Group [%s]", aws.ToString(group.GroupId)),
				Props: []*proto.Property{
					{
						Name:  "group-id",
						Value: aws.ToString(group.GroupId),
					},
					{
						Name:  "group-name",
						Value: aws.ToString(group.GroupName),
					},
					{
						Name:  "vpc-id",
						Value: aws.ToString(group.VpcId),
					},
				},
				ImplementedComponents: []*proto.InventoryItemImplementedComponent{
					{
						Identifier: "common-components/amazon-security-group",
					},
				},
			},
		}
		subjects := []*proto.Subject{
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Identifier: "common-components/amazon-security-group",
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: fmt.Sprintf("aws-security-group/%s", aws.ToString(group.GroupId)),
			},
		}

		for _, policyPath := range request.GetPolicyPaths() {
			// Explicitly reset steps to make things readable
			processor := policyManager.NewPolicyProcessor(
				l.logger,
				internal.MergeMaps(
					labels,
					map[string]string{},
				),
				subjects,
				components,
				inventory,
				actors,
				activities,
			)
			evidence, err := processor.GenerateResults(ctx, policyPath, group)
			evidences = slices.Concat(evidences, evidence)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

		if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
			l.logger.Error("Failed to send evidences", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		}
	}

	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
}

func getSecurityGroups(ctx context.Context, client *ec2.Client) iter.Seq2[types.SecurityGroup, error] {
	return func(yield func(types.SecurityGroup, error) bool) {
		result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
		if err != nil {
			yield(types.SecurityGroup{}, err)
			return
		}

		for _, group := range result.SecurityGroups {
			if !yield(group, nil) {
				return
			}
		}
	}
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("Initiating AWS network security plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
