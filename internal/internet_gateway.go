package internal

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

func EvaluateInternetGatewayPolicies(deps EvaluationDependencies, policyPaths []string, internetGateways []types.InternetGateway, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		internetGateways,
		func(internetGateway types.InternetGateway) ResourceEvidenceContext {
			internetGatewayCtx := BuildInternetGatewayEvidenceContext(internetGateway, region)
			return newResourceEvidenceContext(internetGatewayCtx.Labels, internetGatewayCtx.Subjects, internetGatewayCtx.Components, internetGatewayCtx.Inventory)
		},
		buildRawResourceInput[types.InternetGateway],
		nil,
		nil,
	)
}
