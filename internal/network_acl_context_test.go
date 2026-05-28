package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestBuildNetworkAclPolicyInputIncludesNaclContext(t *testing.T) {
	networkAcl := types.NetworkAcl{
		NetworkAclId: aws.String("acl-123"),
		VpcId:        aws.String("vpc-123"),
		IsDefault:    aws.Bool(false),
		Tags:         []types.Tag{{Key: aws.String("Owner"), Value: aws.String("platform")}},
		Associations: []types.NetworkAclAssociation{
			{NetworkAclAssociationId: aws.String("aclassoc-123"), NetworkAclId: aws.String("acl-123"), SubnetId: aws.String("subnet-123")},
		},
		Entries: []types.NetworkAclEntry{
			{RuleNumber: aws.Int32(100), RuleAction: types.RuleActionAllow, CidrBlock: aws.String("10.0.0.0/16")},
		},
	}

	input, err := BuildNetworkAclPolicyInput(networkAcl, "eu-west-2", RegionDatasets{
		Vpcs: []types.Vpc{
			{VpcId: aws.String("vpc-123")},
			{VpcId: aws.String("vpc-other")},
		},
		Subnets: []types.Subnet{
			{SubnetId: aws.String("subnet-123"), VpcId: aws.String("vpc-123")},
			{SubnetId: aws.String("subnet-other"), VpcId: aws.String("vpc-other")},
		},
		RouteTables: []types.RouteTable{
			{RouteTableId: aws.String("rtb-123"), VpcId: aws.String("vpc-123"), Associations: []types.RouteTableAssociation{{SubnetId: aws.String("subnet-123")}}},
			{RouteTableId: aws.String("rtb-other"), VpcId: aws.String("vpc-other"), Associations: []types.RouteTableAssociation{{SubnetId: aws.String("subnet-other")}}},
		},
		InternetGateways: []types.InternetGateway{
			{InternetGatewayId: aws.String("igw-123"), Attachments: []types.InternetGatewayAttachment{{VpcId: aws.String("vpc-123")}}},
			{InternetGatewayId: aws.String("igw-other"), Attachments: []types.InternetGatewayAttachment{{VpcId: aws.String("vpc-other")}}},
		},
		FlowLogs: []types.FlowLog{
			{FlowLogId: aws.String("fl-vpc"), ResourceId: aws.String("vpc-123"), LogGroupName: aws.String("/aws/vpc/flow")},
			{FlowLogId: aws.String("fl-subnet"), ResourceId: aws.String("subnet-123"), LogGroupName: aws.String("/aws/vpc/subnet")},
			{FlowLogId: aws.String("fl-other"), ResourceId: aws.String("vpc-other"), LogGroupName: aws.String("/aws/vpc/other")},
		},
		LogGroups: []cloudwatchlogstypes.LogGroup{
			{LogGroupName: aws.String("/aws/vpc/flow")},
			{LogGroupName: aws.String("/aws/vpc/subnet")},
			{LogGroupName: aws.String("/aws/vpc/other")},
		},
		NetworkInterfaces: []types.NetworkInterface{
			{NetworkInterfaceId: aws.String("eni-123"), SubnetId: aws.String("subnet-123")},
			{NetworkInterfaceId: aws.String("eni-other"), SubnetId: aws.String("subnet-other")},
		},
	})
	if err != nil {
		t.Fatalf("BuildNetworkAclPolicyInput returned error: %v", err)
	}

	networkAclMap, ok := input["network_acl"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[network_acl] should contain the raw Network ACL map")
	}
	if networkAclMap["IsDefault"] != false {
		t.Fatalf("network_acl.IsDefault = %v, want false", networkAclMap["IsDefault"])
	}

	contextMap, ok := input["nacl_context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[nacl_context] should be a map")
	}

	current := contextMap["current"].(map[string]interface{})
	if current["network_acl_id"] != "acl-123" {
		t.Fatalf("current.network_acl_id = %v, want acl-123", current["network_acl_id"])
	}
	if current["region"] != "eu-west-2" {
		t.Fatalf("current.region = %v, want eu-west-2", current["region"])
	}
	if current["association_count"] != float64(1) {
		t.Fatalf("current.association_count = %v, want 1", current["association_count"])
	}
	if current["entry_count"] != float64(1) {
		t.Fatalf("current.entry_count = %v, want 1", current["entry_count"])
	}
	if current["is_default"] != false {
		t.Fatalf("current.is_default = %v, want false", current["is_default"])
	}

	assertOneItem(t, contextMap, "associated_subnets")
	assertOneItem(t, contextMap, "route_tables_in_vpc")
	assertOneItem(t, contextMap, "route_tables_for_associated_subnets")
	assertOneItem(t, contextMap, "internet_gateways_for_vpc")
	assertOneItem(t, contextMap, "network_interfaces_in_associated_subnets")

	assertItemCount(t, contextMap, "flow_logs_for_vpc", 1)
	assertItemCount(t, contextMap, "flow_logs_for_associated_subnets", 1)
	assertItemCount(t, contextMap, "log_groups_for_related_flow_logs", 2)

	vpc := contextMap["vpc"].(map[string]interface{})
	if vpc["VpcId"] != "vpc-123" {
		t.Fatalf("vpc.VpcId = %v, want vpc-123", vpc["VpcId"])
	}
}

func assertItemCount(t *testing.T, values map[string]interface{}, key string, want int) {
	t.Helper()
	items, ok := values[key].([]interface{})
	if !ok {
		t.Fatalf("%s should be a list", key)
	}
	if len(items) != want {
		t.Fatalf("len(%s) = %d, want %d", key, len(items), want)
	}
}
