package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestBuildSubnetPolicyInputIncludesSubnetContext(t *testing.T) {
	subnet := types.Subnet{
		SubnetId:                aws.String("subnet-123"),
		VpcId:                   aws.String("vpc-123"),
		CidrBlock:               aws.String("10.0.1.0/24"),
		AvailabilityZone:        aws.String("eu-west-2a"),
		AvailabilityZoneId:      aws.String("euw2-az1"),
		MapPublicIpOnLaunch:     aws.Bool(false),
		AvailableIpAddressCount: aws.Int32(120),
		Tags:                    []types.Tag{{Key: aws.String("Owner"), Value: aws.String("platform")}},
	}

	input, err := BuildSubnetPolicyInput(subnet, "eu-west-2", RegionDatasets{
		Vpcs: []types.Vpc{
			{VpcId: aws.String("vpc-123")},
			{VpcId: aws.String("vpc-other")},
		},
		RouteTables: []types.RouteTable{
			{RouteTableId: aws.String("rtb-main"), VpcId: aws.String("vpc-123"), Associations: []types.RouteTableAssociation{{Main: aws.Bool(true)}}},
			{RouteTableId: aws.String("rtb-explicit"), VpcId: aws.String("vpc-123"), Associations: []types.RouteTableAssociation{{SubnetId: aws.String("subnet-123")}}},
			{RouteTableId: aws.String("rtb-other"), VpcId: aws.String("vpc-other"), Associations: []types.RouteTableAssociation{{SubnetId: aws.String("subnet-other")}}},
		},
		NetworkAcls: []types.NetworkAcl{
			{NetworkAclId: aws.String("acl-123"), VpcId: aws.String("vpc-123"), Associations: []types.NetworkAclAssociation{{SubnetId: aws.String("subnet-123")}}},
			{NetworkAclId: aws.String("acl-other"), VpcId: aws.String("vpc-other"), Associations: []types.NetworkAclAssociation{{SubnetId: aws.String("subnet-other")}}},
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
	})
	if err != nil {
		t.Fatalf("BuildSubnetPolicyInput returned error: %v", err)
	}

	subnetMap, ok := input["subnet"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[subnet] should contain the raw Subnet map")
	}
	if subnetMap["SubnetId"] != "subnet-123" {
		t.Fatalf("subnet.SubnetId = %v, want subnet-123", subnetMap["SubnetId"])
	}

	contextMap, ok := input["subnet_context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[subnet_context] should be a map")
	}

	current := contextMap["current"].(map[string]interface{})
	if current["subnet_id"] != "subnet-123" {
		t.Fatalf("current.subnet_id = %v, want subnet-123", current["subnet_id"])
	}
	if current["region"] != "eu-west-2" {
		t.Fatalf("current.region = %v, want eu-west-2", current["region"])
	}
	if current["map_public_ip_on_launch"] != false {
		t.Fatalf("current.map_public_ip_on_launch = %v, want false", current["map_public_ip_on_launch"])
	}
	if current["available_ip_address_count"] != float64(120) {
		t.Fatalf("current.available_ip_address_count = %v, want 120", current["available_ip_address_count"])
	}

	if contextMap["explicit_route_table_association"] != true {
		t.Fatalf("explicit_route_table_association = %v, want true", contextMap["explicit_route_table_association"])
	}

	routeTable := contextMap["route_table_for_subnet"].(map[string]interface{})
	if routeTable["RouteTableId"] != "rtb-explicit" {
		t.Fatalf("route_table_for_subnet.RouteTableId = %v, want rtb-explicit", routeTable["RouteTableId"])
	}

	assertOneItem(t, contextMap, "network_acls_for_subnet")
	assertOneItem(t, contextMap, "internet_gateways_for_vpc")
	assertItemCount(t, contextMap, "route_tables_in_vpc", 2)
	assertItemCount(t, contextMap, "flow_logs_for_vpc", 1)
	assertItemCount(t, contextMap, "flow_logs_for_subnet", 1)
	assertItemCount(t, contextMap, "log_groups_for_related_flow_logs", 2)

	vpc := contextMap["vpc"].(map[string]interface{})
	if vpc["VpcId"] != "vpc-123" {
		t.Fatalf("vpc.VpcId = %v, want vpc-123", vpc["VpcId"])
	}
}

func TestBuildSubnetPolicyInputFallsBackToMainRouteTable(t *testing.T) {
	subnet := types.Subnet{SubnetId: aws.String("subnet-123"), VpcId: aws.String("vpc-123")}

	input, err := BuildSubnetPolicyInput(subnet, "eu-west-2", RegionDatasets{
		RouteTables: []types.RouteTable{
			{RouteTableId: aws.String("rtb-main"), VpcId: aws.String("vpc-123"), Associations: []types.RouteTableAssociation{{Main: aws.Bool(true)}}},
		},
	})
	if err != nil {
		t.Fatalf("BuildSubnetPolicyInput returned error: %v", err)
	}

	contextMap := input["subnet_context"].(map[string]interface{})
	if contextMap["explicit_route_table_association"] != false {
		t.Fatalf("explicit_route_table_association = %v, want false", contextMap["explicit_route_table_association"])
	}
	routeTable := contextMap["route_table_for_subnet"].(map[string]interface{})
	if routeTable["RouteTableId"] != "rtb-main" {
		t.Fatalf("route_table_for_subnet.RouteTableId = %v, want rtb-main", routeTable["RouteTableId"])
	}
}
