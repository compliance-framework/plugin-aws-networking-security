package internal

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

func EvaluateVpcPolicies(deps EvaluationDependencies, policyPaths []string, vpcs []types.Vpc, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		vpcs,
		func(vpc types.Vpc) ResourceEvidenceContext {
			vpcCtx := BuildVpcEvidenceContext(vpc, region)
			return newResourceEvidenceContext(vpcCtx.Labels, vpcCtx.Subjects, vpcCtx.Components, vpcCtx.Inventory)
		},
		buildRawResourceInput[types.Vpc],
		nil,
		nil,
	)
}
