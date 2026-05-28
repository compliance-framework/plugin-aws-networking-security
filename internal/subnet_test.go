package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func TestSubnetDisplayNameUsesNameTag(t *testing.T) {
	subnet := types.Subnet{
		SubnetId: aws.String("subnet-123"),
		Tags: []types.Tag{
			{Key: aws.String("Name"), Value: aws.String("prod-private-a")},
		},
	}

	if got := SubnetDisplayName(subnet); got != "prod-private-a" {
		t.Fatalf("SubnetDisplayName() = %q, want prod-private-a", got)
	}
}

func TestSubnetDisplayNameFallsBackToID(t *testing.T) {
	subnet := types.Subnet{SubnetId: aws.String("subnet-123")}

	if got := SubnetDisplayName(subnet); got != "subnet-123" {
		t.Fatalf("SubnetDisplayName() = %q, want subnet-123", got)
	}
}

func TestPrefixSubnetEvidenceTitles(t *testing.T) {
	evidences := []*proto.Evidence{
		{Title: "Subnet should set required tags"},
		{Title: ""},
		nil,
	}

	PrefixEvidenceTitles(evidences, "subnet-123")

	if got := evidences[0].Title; got != "subnet-123 | Subnet should set required tags" {
		t.Fatalf("prefixed title = %q", got)
	}
	if got := evidences[1].Title; got != "subnet-123" {
		t.Fatalf("empty title fallback = %q", got)
	}
}
