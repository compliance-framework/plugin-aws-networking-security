package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-networking-security/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os"
	"slices"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
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

	svc := ec2.NewFromConfig(cfg)

	// Describe Security Groups
	output, err := svc.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		l.logger.Error("cant list security groups", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	// Run policy checks
	for _, group := range output.SecurityGroups {
		activities := make([]*proto.Activity, 0)
		findings := make([]*proto.Finding, 0)
		observations := make([]*proto.Observation, 0)

		labels := map[string]string{
			"type":        "aws",
			"service":     "security-groups",
			"instance-id": *group.GroupId,
		}
		subjects := []*proto.SubjectReference{
			{
				Type: "aws-security-group",
				Attributes: map[string]string{
					"type":          "aws",
					"service":       "security-group",
					"instance-id":   *group.GroupId,
					"instance-name": *group.GroupName,
					"vpc-id":        *group.VpcId,
				},
				Title: internal.StringAddressed("AWS Security Group"),
				Props: []*proto.Property{
					{
						Name:  "security-group-id",
						Value: *group.GroupId,
					},
					{
						Name:  "security-group-name",
						Value: *group.GroupName,
					},
				},
			},
			{
				Type: "aws-vpc",
				Attributes: map[string]string{
					"type":    "aws",
					"service": "vpc",
					"vpc-id":  fmt.Sprintf("%v", *group.VpcId),
				},
				Title: internal.StringAddressed("AWS VPC"),
				Props: []*proto.Property{
					{
						Name:  "vpc-id",
						Value: fmt.Sprintf("%v", *group.VpcId),
					},
				},
			},
		}
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
		components := []*proto.ComponentReference{
			{
				Identifier: "common-components/aws-security-group",
			},
		}

		for _, policyPath := range request.GetPolicyPaths() {
			// Explicitly reset steps to make things readable
			processor := policyManager.NewPolicyProcessor(
				l.logger,
				internal.MergeMaps(
					labels,
					map[string]string{
						"_policy_path": policyPath,
					},
				),
				subjects,
				components,
				actors,
				activities,
			)
			obs, finds, err := processor.GenerateResults(ctx, policyPath, group)
			observations = slices.Concat(observations, obs)
			findings = slices.Concat(findings, finds)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

		if err = apiHelper.CreateObservations(ctx, observations); err != nil {
			l.logger.Error("Failed to send observations", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		}

		if err = apiHelper.CreateFindings(ctx, findings); err != nil {
			l.logger.Error("Failed to send findings", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		}
	}

	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
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
