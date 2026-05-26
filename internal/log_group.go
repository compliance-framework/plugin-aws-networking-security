package internal

import cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

func EvaluateLogGroupPolicies(deps EvaluationDependencies, policyPaths []string, logGroups []cloudwatchlogstypes.LogGroup, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		logGroups,
		func(logGroup cloudwatchlogstypes.LogGroup) ResourceEvidenceContext {
			logGroupCtx := BuildLogGroupEvidenceContext(logGroup, region)
			return newResourceEvidenceContext(logGroupCtx.Labels, logGroupCtx.Subjects, logGroupCtx.Components, logGroupCtx.Inventory)
		},
		buildRawResourceInput[cloudwatchlogstypes.LogGroup],
		nil,
		nil,
	)
}
