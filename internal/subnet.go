package internal

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func EvaluateSubnetPolicies(deps EvaluationDependencies, policyPaths []string, subnets []types.Subnet, region string, datasets RegionDatasets) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		subnets,
		func(subnet types.Subnet) ResourceEvidenceContext {
			subnetCtx := BuildSubnetEvidenceContext(subnet, region)
			return newResourceEvidenceContext(subnetCtx.Labels, subnetCtx.Subjects, subnetCtx.Components, subnetCtx.Inventory)
		},
		func(subnet types.Subnet) (interface{}, error) {
			return BuildSubnetPolicyInput(subnet, region, datasets)
		},
		func(subnet types.Subnet, err error) {
			deps.Logger.Error("unable to build Subnet policy input", "subnet_id", aws.ToString(subnet.SubnetId), "region", region, "error", err)
		},
		func(evidences []*proto.Evidence, subnet types.Subnet) {
			PrefixEvidenceTitles(evidences, SubnetDisplayName(subnet))
		},
	)
}

func SubnetDisplayName(subnet types.Subnet) string {
	for _, tag := range subnet.Tags {
		if aws.ToString(tag.Key) == "Name" && aws.ToString(tag.Value) != "" {
			return aws.ToString(tag.Value)
		}
	}
	return aws.ToString(subnet.SubnetId)
}
