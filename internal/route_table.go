package internal

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func EvaluateRouteTablePolicies(deps EvaluationDependencies, policyPaths []string, routeTables []types.RouteTable, region string, datasets RegionDatasets) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		routeTables,
		func(routeTable types.RouteTable) ResourceEvidenceContext {
			routeTableCtx := BuildRouteTableEvidenceContext(routeTable, region)
			return newResourceEvidenceContext(routeTableCtx.Labels, routeTableCtx.Subjects, routeTableCtx.Components, routeTableCtx.Inventory)
		},
		func(routeTable types.RouteTable) (interface{}, error) {
			return BuildRouteTablePolicyInput(routeTable, region, datasets)
		},
		func(routeTable types.RouteTable, err error) {
			deps.Logger.Error("unable to build Route Table policy input", "route_table_id", aws.ToString(routeTable.RouteTableId), "region", region, "error", err)
		},
		func(evidences []*proto.Evidence, routeTable types.RouteTable) {
			PrefixEvidenceTitles(evidences, RouteTableDisplayName(routeTable))
		},
	)
}

func RouteTableDisplayName(routeTable types.RouteTable) string {
	for _, tag := range routeTable.Tags {
		if aws.ToString(tag.Key) == "Name" && aws.ToString(tag.Value) != "" {
			return aws.ToString(tag.Value)
		}
	}
	return aws.ToString(routeTable.RouteTableId)
}
