package internal

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func EvaluateNetworkAclPolicies(deps EvaluationDependencies, policyPaths []string, networkAcls []types.NetworkAcl, region string, datasets RegionDatasets) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		networkAcls,
		func(acl types.NetworkAcl) ResourceEvidenceContext {
			aclCtx := BuildNetworkAclEvidenceContext(acl, region)
			return newResourceEvidenceContext(aclCtx.Labels, aclCtx.Subjects, aclCtx.Components, aclCtx.Inventory)
		},
		func(acl types.NetworkAcl) (interface{}, error) {
			return BuildNetworkAclPolicyInput(acl, region, datasets)
		},
		func(acl types.NetworkAcl, err error) {
			deps.Logger.Error("unable to build Network ACL policy input", "network_acl_id", aws.ToString(acl.NetworkAclId), "region", region, "error", err)
		},
		func(evidences []*proto.Evidence, acl types.NetworkAcl) {
			PrefixNetworkAclEvidenceTitles(evidences, NetworkAclDisplayName(acl))
		},
	)
}

func NetworkAclDisplayName(acl types.NetworkAcl) string {
	for _, tag := range acl.Tags {
		if aws.ToString(tag.Key) == "Name" && aws.ToString(tag.Value) != "" {
			return aws.ToString(tag.Value)
		}
	}
	return aws.ToString(acl.NetworkAclId)
}
