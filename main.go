package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	protolang "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	startTime := time.Now()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var errAcc error

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		l.logger.Error("unable to load SDK config", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		errAcc = errors.Join(errAcc, err)
	}

	// security groups

	svc := ec2.NewFromConfig(cfg)

	// Describe Security Groups
	output, err := svc.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		l.logger.Error("cant list security groups", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		errAcc = errors.Join(errAcc, err)
	}

	var securityGroups []map[string]interface{}
	for _, group := range output.SecurityGroups {
		l.logger.Debug("SG ID: ", group.GroupId)
		securityGroups = append(securityGroups, map[string]interface{}{
			"SecurityGroupID": aws.ToString(group.GroupId),
			"IpPermissions":   group.IpPermissions,
		})
	}

	l.logger.Debug("evaluating data", securityGroups)

	// Run policy checks
	for _, instance := range securityGroups {
		for _, policyPath := range request.GetPolicyPaths() {
			results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "compliance_plugin", instance)
			if err != nil {
				l.logger.Error("policy evaluation failed", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				errAcc = errors.Join(errAcc, err)
				continue
			}

			// Build and send results (this is also from your existing logic)
			assessmentResult := runner.NewCallableAssessmentResult()
			assessmentResult.Title = "Security Group checks - AWS plugin"

			for _, result := range results {

				// There are no violations reported from the policies.
				// We'll send the observation back to the agent
				if len(result.Violations) == 0 {
					title := "The plugin succeeded. No compliance issues to report."
					assessmentResult.AddObservation(&proto.Observation{
						Uuid:        uuid.New().String(),
						Title:       &title,
						Description: "The plugin policies did not return any violations. The configuration is in compliance with policies.",
						Collected:   timestamppb.New(time.Now()),
						Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
						RelevantEvidence: []*proto.RelevantEvidence{
							{
								Description: fmt.Sprintf("Policy %v was evaluated, and no violations were found on machineId: %s", result.Policy.Package.PurePackage(), "ARN:12345"),
							},
						},
						Labels: map[string]string{
							"package":           string(result.Policy.Package),
							"type":              "aws-cloud--network-security",
							"security_group_id": fmt.Sprintf("%v", instance["SecurityGroupID"]),
						},
					})

					status := runner.FindingTargetStatusSatisfied
					assessmentResult.AddFinding(&proto.Finding{
						Title:       fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage()),
						Description: fmt.Sprintf("No violations found on the %s policy within the Template Compliance Plugin.", result.Policy.Package.PurePackage()),
						Target: &proto.FindingTarget{
							Status: &proto.ObjectiveStatus{
								State: status,
							},
						},
						Labels: map[string]string{
							"package":           string(result.Policy.Package),
							"type":              "aws-cloud--network-security",
							"security_group_id": fmt.Sprintf("%v", instance["SecurityGroupID"]),
						},
					})
				}

				// There are violations in the policy checks.
				// We'll send these observations back to the agent
				if len(result.Violations) > 0 {
					title := fmt.Sprintf("The plugin found violations for policy %s on machineId: %s", result.Policy.Package.PurePackage(), "ARN:12345")
					observationUuid := uuid.New().String()
					assessmentResult.AddObservation(&proto.Observation{
						Uuid:        observationUuid,
						Title:       &title,
						Description: fmt.Sprintf("Observed %d violation(s) for policy %s", len(result.Violations), result.Policy.Package.PurePackage()),
						Collected:   timestamppb.New(time.Now()),
						Expires:     timestamppb.New(time.Now().AddDate(0, 1, 0)), // Add one month for the expiration
						RelevantEvidence: []*proto.RelevantEvidence{
							{
								Description: fmt.Sprintf("Policy %v was evaluated, and %d violations were found", result.Policy.Package.PurePackage(), len(result.Violations)),
							},
						},
						Labels: map[string]string{
							"package":           string(result.Policy.Package),
							"type":              "aws-cloud--network-security",
							"security_group_id": fmt.Sprintf("%v", instance["SecurityGroupID"]),
						},
					})

					for _, violation := range result.Violations {
						status := runner.FindingTargetStatusNotSatisfied
						assessmentResult.AddFinding(&proto.Finding{
							Title:       violation.Title,
							Description: violation.Description,
							Remarks:     &violation.Remarks,
							RelatedObservations: []*proto.RelatedObservation{
								{
									ObservationUuid: observationUuid,
								},
							},
							Target: &proto.FindingTarget{
								Status: &proto.ObjectiveStatus{
									State: status,
								},
							},
							Labels: map[string]string{
								"package":           string(result.Policy.Package),
								"type":              "aws-cloud--network-security",
								"security_group_id": fmt.Sprintf("%v", instance["SecurityGroupID"]),
							},
						})
					}
				}

				for _, risk := range result.Risks {
					links := []*proto.Link{}
					for _, link := range risk.Links {
						links = append(links, &proto.Link{
							Href: link.URL,
							Text: &link.Text,
						})
					}

					assessmentResult.AddRiskEntry(&proto.Risk{
						Title:       risk.Title,
						Description: risk.Description,
						Statement:   risk.Statement,
						Props:       []*proto.Property{},
						Links:       links,
					})
				}
			}

			assessmentResult.Start = timestamppb.New(startTime)

			var endTime = time.Now()
			assessmentResult.End = timestamppb.New(endTime)

			streamId, err := sdk.SeededUUID(map[string]string{
				"type":    "aws-cloud--network-security",
				"_policy": policyPath,
			})
			if err != nil {
				l.logger.Error("Failed to seedUUID", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				errAcc = errors.Join(errAcc, err)
				continue
			}

			assessmentResult.AddLogEntry(&proto.AssessmentLog_Entry{
				Title:       protolang.String("Template check"),
				Description: protolang.String("Template plugin checks completed successfully"),
				Start:       timestamppb.New(startTime),
				End:         timestamppb.New(endTime),
			})

			err = apiHelper.CreateResult(
				streamId.String(),
				map[string]string{
					"type":    "aws-cloud--network-security",
					"_policy": policyPath,
				},
				policyPath,
				assessmentResult.Result())
			if err != nil {
				l.logger.Error("Failed to add assessment result", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				errAcc = errors.Join(errAcc, err)
			}
		}
	}

	return &proto.EvalResponse{
		Status: evalStatus,
	}, errAcc
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
