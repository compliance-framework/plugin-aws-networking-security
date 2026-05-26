package internal

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

func EvaluateVpcEndpointPolicies(deps EvaluationDependencies, policyPaths []string, vpcEndpoints []types.VpcEndpoint, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		vpcEndpoints,
		func(vpcEndpoint types.VpcEndpoint) ResourceEvidenceContext {
			vpcEndpointCtx := BuildVpcEndpointEvidenceContext(vpcEndpoint, region)
			return newResourceEvidenceContext(vpcEndpointCtx.Labels, vpcEndpointCtx.Subjects, vpcEndpointCtx.Components, vpcEndpointCtx.Inventory)
		},
		buildRawResourceInput[types.VpcEndpoint],
		nil,
		nil,
	)
}
