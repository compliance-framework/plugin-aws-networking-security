package internal

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/hashicorp/go-hclog"
)

func TestCollectRegionDatasetsRequiresEC2ClientForEC2Datasets(t *testing.T) {
	_, err := CollectRegionDatasets(context.Background(), hclog.NewNullLogger(), nil, nil, map[string]bool{
		"vpcs": true,
	})
	if err == nil || !strings.Contains(err.Error(), "ec2 client is required") {
		t.Fatalf("CollectRegionDatasets error = %v, want EC2 client required error", err)
	}
}

func TestCollectRegionDatasetsRequiresLogsClientForLogGroups(t *testing.T) {
	_, err := CollectRegionDatasets(context.Background(), hclog.NewNullLogger(), ec2.New(ec2.Options{}), nil, map[string]bool{
		"log_groups": true,
	})
	if err == nil || !strings.Contains(err.Error(), "cloudwatch logs client is required") {
		t.Fatalf("CollectRegionDatasets error = %v, want CloudWatch Logs client required error", err)
	}
}

func TestCollectRegionDatasetsAllowsNilClientsWhenNoDatasetsRequired(t *testing.T) {
	if _, err := CollectRegionDatasets(context.Background(), hclog.NewNullLogger(), nil, nil, nil); err != nil {
		t.Fatalf("CollectRegionDatasets returned error with no required datasets: %v", err)
	}
}

func TestVpcAttributesRequireVpcCollection(t *testing.T) {
	if !requiresVpcCollection(map[string]bool{"vpc_attributes": true}) {
		t.Fatal("vpc_attributes should require VPC collection")
	}
}
