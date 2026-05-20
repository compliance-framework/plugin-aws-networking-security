package main

import (
	"context"
	"errors"
	"slices"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-networking-security/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	return &proto.InitResponse{}, nil
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

		// Collect and evaluate VPCs
		for vpc, err := range internal.PaginatedDescribeVpcs(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get VPC", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			vpcCtx := internal.BuildVpcEvidenceContext(vpc, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						vpcCtx.Labels,
						map[string]string{},
					),
					vpcCtx.Subjects,
					vpcCtx.Components,
					vpcCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, vpc)
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

		// Collect and evaluate Subnets
		for subnet, err := range internal.PaginatedDescribeSubnets(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get Subnet", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			subnetCtx := internal.BuildSubnetEvidenceContext(subnet, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						subnetCtx.Labels,
						map[string]string{},
					),
					subnetCtx.Subjects,
					subnetCtx.Components,
					subnetCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, subnet)
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

		// Collect and evaluate Security Groups
		for group, err := range internal.PaginatedDescribeSecurityGroups(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get Security Group", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			sgCtx := internal.BuildSecurityGroupEvidenceContext(group, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						sgCtx.Labels,
						map[string]string{},
					),
					sgCtx.Subjects,
					sgCtx.Components,
					sgCtx.Inventory,
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

		// Collect and evaluate Network ACLs
		for acl, err := range internal.PaginatedDescribeNetworkAcls(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get Network ACL", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			aclCtx := internal.BuildNetworkAclEvidenceContext(acl, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						aclCtx.Labels,
						map[string]string{},
					),
					aclCtx.Subjects,
					aclCtx.Components,
					aclCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, acl)
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

		// Collect and evaluate Route Tables
		for rt, err := range internal.PaginatedDescribeRouteTables(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get Route Table", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			rtCtx := internal.BuildRouteTableEvidenceContext(rt, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						rtCtx.Labels,
						map[string]string{},
					),
					rtCtx.Subjects,
					rtCtx.Components,
					rtCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, rt)
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

		// Collect and evaluate Internet Gateways
		for igw, err := range internal.PaginatedDescribeInternetGateways(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get Internet Gateway", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			igwCtx := internal.BuildInternetGatewayEvidenceContext(igw, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						igwCtx.Labels,
						map[string]string{},
					),
					igwCtx.Subjects,
					igwCtx.Components,
					igwCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, igw)
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

		// Collect and evaluate VPC Endpoints
		for endpoint, err := range internal.PaginatedDescribeVpcEndpoints(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get VPC Endpoint", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			endpointCtx := internal.BuildVpcEndpointEvidenceContext(endpoint, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						endpointCtx.Labels,
						map[string]string{},
					),
					endpointCtx.Subjects,
					endpointCtx.Components,
					endpointCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, endpoint)
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

		// Collect and evaluate Flow Logs
		for flowLog, err := range internal.PaginatedDescribeFlowLogs(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get Flow Log", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			flowLogCtx := internal.BuildFlowLogEvidenceContext(flowLog, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						flowLogCtx.Labels,
						map[string]string{},
					),
					flowLogCtx.Subjects,
					flowLogCtx.Components,
					flowLogCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, flowLog)
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

		// Collect and evaluate Log Groups
		for logGroup, err := range internal.PaginatedDescribeLogGroups(ctx, logsClient) {
			if err != nil {
				l.logger.Error("unable to get Log Group", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			logGroupCtx := internal.BuildLogGroupEvidenceContext(logGroup, region)
			activities := make([]*proto.Activity, 0)
			evidences := make([]*proto.Evidence, 0)

			for _, policyPath := range request.GetPolicyPaths() {
				processor := policyManager.NewPolicyProcessor(
					l.logger,
					internal.MergeMaps(
						logGroupCtx.Labels,
						map[string]string{},
					),
					logGroupCtx.Subjects,
					logGroupCtx.Components,
					logGroupCtx.Inventory,
					actors,
					activities,
				)
				evidence, err := processor.GenerateResults(ctx, policyPath, logGroup)
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
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
