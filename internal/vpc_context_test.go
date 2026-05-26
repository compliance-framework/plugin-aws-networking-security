package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestBuildVpcPolicyInputIncludesVpcContext(t *testing.T) {
	enableDnsSupport := true
	enableDnsHostnames := false
	enableNetworkAddressUsageMetrics := true

	vpc := types.Vpc{
		VpcId:         aws.String("vpc-123"),
		CidrBlock:     aws.String("10.0.0.0/16"),
		DhcpOptionsId: aws.String("dopt-123"),
		IsDefault:     aws.Bool(false),
		State:         types.VpcStateAvailable,
		Tags:          []types.Tag{{Key: aws.String("Owner"), Value: aws.String("platform")}},
	}

	input, err := BuildVpcPolicyInput(vpc, "eu-west-2", RegionDatasets{
		VpcAttributes: map[string]VpcAttributeValues{
			"vpc-123": {
				EnableDnsSupport:                 &enableDnsSupport,
				EnableDnsHostnames:               &enableDnsHostnames,
				EnableNetworkAddressUsageMetrics: &enableNetworkAddressUsageMetrics,
			},
		},
		DhcpOptions: []types.DhcpOptions{
			{DhcpOptionsId: aws.String("dopt-123")},
			{DhcpOptionsId: aws.String("dopt-other")},
		},
		Subnets: []types.Subnet{
			{SubnetId: aws.String("subnet-123"), VpcId: aws.String("vpc-123")},
			{SubnetId: aws.String("subnet-other"), VpcId: aws.String("vpc-other")},
		},
		RouteTables: []types.RouteTable{
			{RouteTableId: aws.String("rtb-123"), VpcId: aws.String("vpc-123")},
			{RouteTableId: aws.String("rtb-other"), VpcId: aws.String("vpc-other")},
		},
		InternetGateways: []types.InternetGateway{
			{InternetGatewayId: aws.String("igw-123"), Attachments: []types.InternetGatewayAttachment{{VpcId: aws.String("vpc-123")}}},
			{InternetGatewayId: aws.String("igw-other"), Attachments: []types.InternetGatewayAttachment{{VpcId: aws.String("vpc-other")}}},
		},
		VpcEndpoints: []types.VpcEndpoint{
			{VpcEndpointId: aws.String("vpce-123"), VpcId: aws.String("vpc-123")},
			{VpcEndpointId: aws.String("vpce-other"), VpcId: aws.String("vpc-other")},
		},
		FlowLogs: []types.FlowLog{
			{FlowLogId: aws.String("fl-123"), ResourceId: aws.String("vpc-123"), LogGroupName: aws.String("/aws/vpc/flow")},
			{FlowLogId: aws.String("fl-other"), ResourceId: aws.String("vpc-other"), LogGroupName: aws.String("/aws/vpc/other")},
		},
		LogGroups: []cloudwatchlogstypes.LogGroup{
			{LogGroupName: aws.String("/aws/vpc/flow")},
			{LogGroupName: aws.String("/aws/vpc/other")},
		},
		TransitGatewayAttachments: []types.TransitGatewayAttachment{
			{TransitGatewayAttachmentId: aws.String("tgw-attach-123"), ResourceId: aws.String("vpc-123")},
			{TransitGatewayAttachmentId: aws.String("tgw-attach-other"), ResourceId: aws.String("vpc-other")},
		},
	})
	if err != nil {
		t.Fatalf("BuildVpcPolicyInput returned error: %v", err)
	}

	if _, ok := input["vpc"].(map[string]interface{}); !ok {
		t.Fatalf("input[vpc] should contain the raw VPC map")
	}

	contextMap, ok := input["vpc_context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[vpc_context] should be a map")
	}

	current := contextMap["current"].(map[string]interface{})
	if current["vpc_id"] != "vpc-123" {
		t.Fatalf("current.vpc_id = %v, want vpc-123", current["vpc_id"])
	}
	if current["region"] != "eu-west-2" {
		t.Fatalf("current.region = %v, want eu-west-2", current["region"])
	}

	attributes := contextMap["attributes"].(map[string]interface{})
	if attributes["enable_dns_support"] != true {
		t.Fatalf("attributes.enable_dns_support = %v, want true", attributes["enable_dns_support"])
	}
	if attributes["enable_dns_hostnames"] != false {
		t.Fatalf("attributes.enable_dns_hostnames = %v, want false", attributes["enable_dns_hostnames"])
	}
	if attributes["enable_network_address_usage_metrics"] != true {
		t.Fatalf("attributes.enable_network_address_usage_metrics = %v, want true", attributes["enable_network_address_usage_metrics"])
	}

	assertOneItem(t, contextMap, "subnets_in_vpc")
	assertOneItem(t, contextMap, "route_tables_in_vpc")
	assertOneItem(t, contextMap, "internet_gateways_for_vpc")
	assertOneItem(t, contextMap, "vpc_endpoints_for_vpc")
	assertOneItem(t, contextMap, "flow_logs_for_vpc")
	assertOneItem(t, contextMap, "log_groups_for_vpc_flow_logs")
	assertOneItem(t, contextMap, "transit_gateway_attachments_for_vpc")

	dhcpOptions := contextMap["dhcp_options"].(map[string]interface{})
	if dhcpOptions["DhcpOptionsId"] != "dopt-123" {
		t.Fatalf("dhcp_options.DhcpOptionsId = %v, want dopt-123", dhcpOptions["DhcpOptionsId"])
	}
}

func assertOneItem(t *testing.T, values map[string]interface{}, key string) {
	t.Helper()
	items, ok := values[key].([]interface{})
	if !ok {
		t.Fatalf("%s should be a list", key)
	}
	if len(items) != 1 {
		t.Fatalf("len(%s) = %d, want 1", key, len(items))
	}
}
