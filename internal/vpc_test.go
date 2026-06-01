package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestVpcDisplayNameUsesNameTag(t *testing.T) {
	vpc := types.Vpc{
		VpcId: aws.String("vpc-123"),
		Tags: []types.Tag{
			{Key: aws.String("Name"), Value: aws.String("production-vpc")},
		},
	}

	if got := VpcDisplayName(vpc); got != "production-vpc" {
		t.Fatalf("VpcDisplayName() = %q, want production-vpc", got)
	}
}

func TestVpcDisplayNameFallsBackToID(t *testing.T) {
	vpc := types.Vpc{
		VpcId: aws.String("vpc-123"),
		Tags: []types.Tag{
			{Key: aws.String("Environment"), Value: aws.String("prod")},
		},
	}

	if got := VpcDisplayName(vpc); got != "vpc-123" {
		t.Fatalf("VpcDisplayName() = %q, want vpc-123", got)
	}
}
