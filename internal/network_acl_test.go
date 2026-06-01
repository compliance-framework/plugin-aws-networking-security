package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func TestNetworkAclDisplayNameUsesNameTag(t *testing.T) {
	acl := types.NetworkAcl{
		NetworkAclId: aws.String("acl-123"),
		Tags: []types.Tag{
			{Key: aws.String("Name"), Value: aws.String("prod-public-nacl")},
		},
	}

	if got := NetworkAclDisplayName(acl); got != "prod-public-nacl" {
		t.Fatalf("NetworkAclDisplayName() = %q, want prod-public-nacl", got)
	}
}

func TestNetworkAclDisplayNameFallsBackToID(t *testing.T) {
	acl := types.NetworkAcl{NetworkAclId: aws.String("acl-123")}

	if got := NetworkAclDisplayName(acl); got != "acl-123" {
		t.Fatalf("NetworkAclDisplayName() = %q, want acl-123", got)
	}
}

func TestPrefixNetworkAclEvidenceTitles(t *testing.T) {
	evidences := []*proto.Evidence{
		{Title: "Network ACL should set required tags"},
		{Title: ""},
		nil,
	}

	PrefixEvidenceTitles(evidences, "acl-123")

	if got := evidences[0].GetTitle(); got != "acl-123 | Network ACL should set required tags" {
		t.Fatalf("prefixed title = %q", got)
	}
	if got := evidences[1].GetTitle(); got != "acl-123" {
		t.Fatalf("empty title fallback = %q", got)
	}
}
