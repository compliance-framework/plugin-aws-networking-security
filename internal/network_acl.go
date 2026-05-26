package internal

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

func EvaluateNetworkAclPolicies(deps EvaluationDependencies, policyPaths []string, networkAcls []types.NetworkAcl, region string) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		networkAcls,
		func(acl types.NetworkAcl) ResourceEvidenceContext {
			aclCtx := BuildNetworkAclEvidenceContext(acl, region)
			return newResourceEvidenceContext(aclCtx.Labels, aclCtx.Subjects, aclCtx.Components, aclCtx.Inventory)
		},
		buildRawResourceInput[types.NetworkAcl],
		nil,
		nil,
	)
}
