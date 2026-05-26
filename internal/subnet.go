package internal

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

func EvaluateSubnetPolicies(deps EvaluationDependencies, policyPaths []string, subnets []types.Subnet, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		subnets,
		func(subnet types.Subnet) ResourceEvidenceContext {
			subnetCtx := BuildSubnetEvidenceContext(subnet, region)
			return newResourceEvidenceContext(subnetCtx.Labels, subnetCtx.Subjects, subnetCtx.Components, subnetCtx.Inventory)
		},
		buildRawResourceInput[types.Subnet],
		nil,
		nil,
	)
}
