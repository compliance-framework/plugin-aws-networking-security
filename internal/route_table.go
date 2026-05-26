package internal

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

func EvaluateRouteTablePolicies(deps EvaluationDependencies, policyPaths []string, routeTables []types.RouteTable, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		routeTables,
		func(routeTable types.RouteTable) ResourceEvidenceContext {
			routeTableCtx := BuildRouteTableEvidenceContext(routeTable, region)
			return newResourceEvidenceContext(routeTableCtx.Labels, routeTableCtx.Subjects, routeTableCtx.Components, routeTableCtx.Inventory)
		},
		buildRawResourceInput[types.RouteTable],
		nil,
		nil,
	)
}
