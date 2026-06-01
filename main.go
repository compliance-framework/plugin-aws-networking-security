package main

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-networking-security/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger     hclog.Logger
	config     map[string]string
	policyData map[string]interface{}
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	if req.GetPolicyData() != nil {
		l.policyData = req.GetPolicyData().AsMap()
	} else {
		l.policyData = nil
	}
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, buildSubjectTemplates())
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

	// Resolve regions from config or environment
	regions := internal.ResolveRegions(l.config)

	// Common actors for all evidence
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
			Title: "Continuous Compliance Framework - AWS Networking Security Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-aws-networking-security",
					Rel:  internal.StringAddressed("reference"),
					Text: internal.StringAddressed("The Continuous Compliance Framework AWS Networking Security Plugin"),
				},
			},
		},
	}

	defaultBehaviorMapping := map[string][]string{
		"aws-vpc-sg-policies":     {"sg"},
		"aws-vpc-policies":        {"vpc"},
		"aws-vpc-subnet-policies": {"subnet"},
		"aws-vpc-nacl-policies":   {"acl"},
		"aws-vpc-rt-policies":     {"rt"},
	}
	policyEval := request.WithDefaultPolicyBehavior(defaultBehaviorMapping)
	policyPathsByBehavior := buildPolicyPathsByBehavior(policyEval)
	requiredDatasets := buildRequiredDatasets(policyPathsByBehavior)
	deps := internal.EvaluationDependencies{
		Context:    ctx,
		Logger:     l.logger,
		ApiHelper:  apiHelper,
		Actors:     actors,
		PolicyData: l.policyData,
	}

	// Iterate over each configured region
	for _, region := range regions {
		l.logger.Info("Collecting resources in region", "region", region)

		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			l.logger.Error("unable to load SDK config for region", "region", region, "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		client := ec2.NewFromConfig(cfg)
		logsClient := cloudwatchlogs.NewFromConfig(cfg)

		datasets, err := internal.CollectRegionDatasets(ctx, l.logger, client, logsClient, requiredDatasets)
		if err != nil {
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		if vpcPolicyPaths := policyPathsByBehavior["vpc"]; len(vpcPolicyPaths) > 0 {
			result := internal.EvaluateVpcPolicies(deps, vpcPolicyPaths, datasets.Vpcs, region, datasets)
			if fatal := applyResourceEvaluationErrors(result, &evalStatus, &accumulatedErrors, false); fatal != nil {
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fatal
			}
		}

		if subnetPolicyPaths := policyPathsByBehavior["subnet"]; len(subnetPolicyPaths) > 0 {
			result := internal.EvaluateSubnetPolicies(deps, subnetPolicyPaths, datasets.Subnets, region, datasets)
			if fatal := applyResourceEvaluationErrors(result, &evalStatus, &accumulatedErrors, false); fatal != nil {
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fatal
			}
		}

		if sgPolicyPaths := policyPathsByBehavior["sg"]; len(sgPolicyPaths) > 0 {
			result := internal.EvaluateSecurityGroupPolicies(deps, sgPolicyPaths, datasets.SecurityGroups, region, datasets)
			if fatal := applyResourceEvaluationErrors(result, &evalStatus, &accumulatedErrors, true); fatal != nil {
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fatal
			}
		}

		if aclPolicyPaths := policyPathsByBehavior["acl"]; len(aclPolicyPaths) > 0 {
			result := internal.EvaluateNetworkAclPolicies(deps, aclPolicyPaths, datasets.NetworkAcls, region, datasets)
			if fatal := applyResourceEvaluationErrors(result, &evalStatus, &accumulatedErrors, false); fatal != nil {
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fatal
			}
		}

		if routeTablePolicyPaths := policyPathsByBehavior["rt"]; len(routeTablePolicyPaths) > 0 {
			result := internal.EvaluateRouteTablePolicies(deps, routeTablePolicyPaths, datasets.RouteTables, region, datasets)
			if fatal := applyResourceEvaluationErrors(result, &evalStatus, &accumulatedErrors, false); fatal != nil {
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fatal
			}
		}

	}

	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
}

func applyResourceEvaluationErrors(result internal.ResourceEvaluationErrors, evalStatus *proto.ExecutionStatus, accumulatedErrors *error, failOnInputBuild bool) error {
	if result.NonFatal != nil {
		*accumulatedErrors = errors.Join(*accumulatedErrors, result.NonFatal)
	}
	if failOnInputBuild && result.InputBuildFailure {
		*evalStatus = proto.ExecutionStatus_FAILURE
	}
	return result.Fatal
}

func supportedPolicyBehaviors() []string {
	return []string{
		"vpc",
		"subnet",
		"sg",
		"acl",
		"rt",
	}
}

func buildPolicyPathsByBehavior(request *proto.EvalRequest) map[string][]string {
	policyPathsByBehavior := make(map[string][]string)
	for _, behavior := range supportedPolicyBehaviors() {
		policyPaths := request.PolicyPathsForBehavior(behavior)
		if len(policyPaths) > 0 {
			policyPathsByBehavior[behavior] = policyPaths
		}
	}
	return policyPathsByBehavior
}

func buildRequiredDatasets(policyPathsByBehavior map[string][]string) map[string]bool {
	requiredDatasets := make(map[string]bool)
	for behavior, policyPaths := range policyPathsByBehavior {
		if len(policyPaths) == 0 {
			continue
		}

		switch behavior {
		case "vpc":
			markRequiredDatasets(requiredDatasets, "vpcs", "vpc_attributes", "dhcp_options", "subnets", "route_tables", "internet_gateways", "vpc_endpoints", "flow_logs", "log_groups", "transit_gateway_attachments")
		case "subnet":
			markRequiredDatasets(requiredDatasets, "vpcs", "subnets", "route_tables", "network_acls", "internet_gateways", "flow_logs", "log_groups")
		case "sg":
			markRequiredDatasets(requiredDatasets, "vpcs", "subnets", "security_groups", "network_interfaces", "network_acls", "route_tables", "internet_gateways", "vpc_endpoints", "flow_logs", "log_groups", "transit_gateway_attachments")
		case "acl":
			markRequiredDatasets(requiredDatasets, "vpcs", "subnets", "network_acls", "route_tables", "internet_gateways", "flow_logs", "log_groups", "network_interfaces")
		case "rt":
			markRequiredDatasets(requiredDatasets, "vpcs", "subnets", "route_tables", "internet_gateways", "vpc_endpoints", "transit_gateway_attachments")
		default:
			continue
		}
	}
	return requiredDatasets
}

func markRequiredDatasets(requiredDatasets map[string]bool, datasetNames ...string) {
	for _, datasetName := range datasetNames {
		requiredDatasets[datasetName] = true
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
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
