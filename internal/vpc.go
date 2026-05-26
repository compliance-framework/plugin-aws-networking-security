package internal

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func EvaluateVpcPolicies(deps EvaluationDependencies, policyPaths []string, vpcs []types.Vpc, region string, datasets RegionDatasets) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		vpcs,
		func(vpc types.Vpc) ResourceEvidenceContext {
			vpcCtx := BuildVpcEvidenceContext(vpc, region)
			return newResourceEvidenceContext(vpcCtx.Labels, vpcCtx.Subjects, vpcCtx.Components, vpcCtx.Inventory)
		},
		func(vpc types.Vpc) (interface{}, error) {
			return BuildVpcPolicyInput(vpc, region, datasets)
		},
		func(vpc types.Vpc, err error) {
			deps.Logger.Error("unable to build VPC policy input", "vpc_id", aws.ToString(vpc.VpcId), "region", region, "error", err)
		},
		func(evidences []*proto.Evidence, vpc types.Vpc) {
			PrefixVpcEvidenceTitles(evidences, VpcDisplayName(vpc))
		},
	)
}

func VpcDisplayName(vpc types.Vpc) string {
	for _, tag := range vpc.Tags {
		if aws.ToString(tag.Key) == "Name" && aws.ToString(tag.Value) != "" {
			return aws.ToString(tag.Value)
		}
	}
	return aws.ToString(vpc.VpcId)
}
