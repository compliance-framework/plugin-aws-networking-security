package internal

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

func EvaluateFlowLogPolicies(deps EvaluationDependencies, policyPaths []string, flowLogs []types.FlowLog, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		flowLogs,
		func(flowLog types.FlowLog) ResourceEvidenceContext {
			flowLogCtx := BuildFlowLogEvidenceContext(flowLog, region)
			return newResourceEvidenceContext(flowLogCtx.Labels, flowLogCtx.Subjects, flowLogCtx.Components, flowLogCtx.Inventory)
		},
		buildRawResourceInput[types.FlowLog],
		nil,
		nil,
	)
}
