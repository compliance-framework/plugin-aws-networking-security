package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestBuildRouteTablePolicyInputIncludesRouteTableContext(t *testing.T) {
	routeTable := types.RouteTable{
		RouteTableId: aws.String("rtb-public"),
		VpcId:        aws.String("vpc-123"),
		OwnerId:      aws.String("123456789012"),
		Associations: []types.RouteTableAssociation{
			{SubnetId: aws.String("subnet-public")},
		},
		Routes: []types.Route{
			{DestinationCidrBlock: aws.String("10.0.0.0/16"), GatewayId: aws.String("local"), State: types.RouteStateActive, Origin: types.RouteOriginCreateRouteTable},
			{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-123"), State: types.RouteStateActive, Origin: types.RouteOriginCreateRoute},
			{DestinationCidrBlock: aws.String("10.20.0.0/16"), TransitGatewayId: aws.String("tgw-123"), State: types.RouteStateBlackhole, Origin: types.RouteOriginCreateRoute},
		},
		Tags: []types.Tag{{Key: aws.String("Name"), Value: aws.String("public-rt")}},
	}

	input, err := BuildRouteTablePolicyInput(routeTable, "eu-west-2", RegionDatasets{
		Vpcs: []types.Vpc{
			{VpcId: aws.String("vpc-123")},
			{VpcId: aws.String("vpc-other")},
		},
		Subnets: []types.Subnet{
			{SubnetId: aws.String("subnet-public"), VpcId: aws.String("vpc-123")},
			{SubnetId: aws.String("subnet-private"), VpcId: aws.String("vpc-123")},
			{SubnetId: aws.String("subnet-other"), VpcId: aws.String("vpc-other")},
		},
		InternetGateways: []types.InternetGateway{
			{InternetGatewayId: aws.String("igw-123"), Attachments: []types.InternetGatewayAttachment{{VpcId: aws.String("vpc-123")}}},
			{InternetGatewayId: aws.String("igw-other"), Attachments: []types.InternetGatewayAttachment{{VpcId: aws.String("vpc-other")}}},
		},
		VpcEndpoints: []types.VpcEndpoint{
			{VpcEndpointId: aws.String("vpce-123"), VpcId: aws.String("vpc-123"), RouteTableIds: []string{"rtb-public"}},
			{VpcEndpointId: aws.String("vpce-other"), VpcId: aws.String("vpc-other"), RouteTableIds: []string{"rtb-public"}},
		},
		TransitGatewayAttachments: []types.TransitGatewayAttachment{
			{TransitGatewayAttachmentId: aws.String("tgw-attach-123"), ResourceId: aws.String("vpc-123")},
			{TransitGatewayAttachmentId: aws.String("tgw-attach-other"), ResourceId: aws.String("vpc-other")},
		},
	})
	if err != nil {
		t.Fatalf("BuildRouteTablePolicyInput returned error: %v", err)
	}

	routeTableMap, ok := input["route_table"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[route_table] should contain the raw RouteTable map")
	}
	if routeTableMap["RouteTableId"] != "rtb-public" {
		t.Fatalf("route_table.RouteTableId = %v, want rtb-public", routeTableMap["RouteTableId"])
	}

	contextMap, ok := input["route_table_context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input[route_table_context] should be a map")
	}

	current := contextMap["current"].(map[string]interface{})
	if current["route_table_id"] != "rtb-public" {
		t.Fatalf("current.route_table_id = %v, want rtb-public", current["route_table_id"])
	}
	if current["region"] != "eu-west-2" {
		t.Fatalf("current.region = %v, want eu-west-2", current["region"])
	}
	if current["is_main"] != false {
		t.Fatalf("current.is_main = %v, want false", current["is_main"])
	}
	if current["explicit_subnet_association_count"] != float64(1) {
		t.Fatalf("current.explicit_subnet_association_count = %v, want 1", current["explicit_subnet_association_count"])
	}
	if current["effective_subnet_association_count"] != float64(1) {
		t.Fatalf("current.effective_subnet_association_count = %v, want 1", current["effective_subnet_association_count"])
	}
	if current["has_default_route_to_internet_gateway"] != true {
		t.Fatalf("current.has_default_route_to_internet_gateway = %v, want true", current["has_default_route_to_internet_gateway"])
	}
	if current["has_blackhole_routes"] != true {
		t.Fatalf("current.has_blackhole_routes = %v, want true", current["has_blackhole_routes"])
	}
	if current["blackhole_route_count"] != float64(1) {
		t.Fatalf("current.blackhole_route_count = %v, want 1", current["blackhole_route_count"])
	}
	if current["has_gateway_endpoint_routes"] != true {
		t.Fatalf("current.has_gateway_endpoint_routes = %v, want true", current["has_gateway_endpoint_routes"])
	}

	assertOneItem(t, contextMap, "explicitly_associated_subnets")
	assertOneItem(t, contextMap, "effectively_associated_subnets")
	assertOneItem(t, contextMap, "internet_gateways_for_vpc")
	assertOneItem(t, contextMap, "vpc_endpoints_for_route_table")
	assertOneItem(t, contextMap, "transit_gateway_attachments_for_vpc")
	assertItemCount(t, contextMap, "subnets_in_vpc", 2)
	assertItemCount(t, contextMap, "route_summaries", 3)
	assertItemCount(t, contextMap, "blackhole_routes", 1)

	vpc := contextMap["vpc"].(map[string]interface{})
	if vpc["VpcId"] != "vpc-123" {
		t.Fatalf("vpc.VpcId = %v, want vpc-123", vpc["VpcId"])
	}
}

func TestBuildRouteTablePolicyInputIncludesImplicitMainRouteAssociations(t *testing.T) {
	mainRouteTable := types.RouteTable{
		RouteTableId: aws.String("rtb-main"),
		VpcId:        aws.String("vpc-123"),
		Associations: []types.RouteTableAssociation{{Main: aws.Bool(true)}},
	}

	input, err := BuildRouteTablePolicyInput(mainRouteTable, "eu-west-2", RegionDatasets{
		Subnets: []types.Subnet{
			{SubnetId: aws.String("subnet-main-a"), VpcId: aws.String("vpc-123")},
			{SubnetId: aws.String("subnet-explicit"), VpcId: aws.String("vpc-123")},
			{SubnetId: aws.String("subnet-other"), VpcId: aws.String("vpc-other")},
		},
		RouteTables: []types.RouteTable{
			mainRouteTable,
			{RouteTableId: aws.String("rtb-explicit"), VpcId: aws.String("vpc-123"), Associations: []types.RouteTableAssociation{{SubnetId: aws.String("subnet-explicit")}}},
		},
	})
	if err != nil {
		t.Fatalf("BuildRouteTablePolicyInput returned error: %v", err)
	}

	contextMap := input["route_table_context"].(map[string]interface{})
	current := contextMap["current"].(map[string]interface{})
	if current["is_main"] != true {
		t.Fatalf("current.is_main = %v, want true", current["is_main"])
	}
	if current["implicit_subnet_association_count"] != float64(1) {
		t.Fatalf("current.implicit_subnet_association_count = %v, want 1", current["implicit_subnet_association_count"])
	}
	if current["effective_subnet_association_count"] != float64(1) {
		t.Fatalf("current.effective_subnet_association_count = %v, want 1", current["effective_subnet_association_count"])
	}

	implicitSubnetIDs := current["implicitly_associated_subnet_ids"].([]interface{})
	if len(implicitSubnetIDs) != 1 || implicitSubnetIDs[0] != "subnet-main-a" {
		t.Fatalf("implicitly_associated_subnet_ids = %v, want [subnet-main-a]", implicitSubnetIDs)
	}
	assertOneItem(t, contextMap, "implicitly_associated_subnets")
	assertOneItem(t, contextMap, "effectively_associated_subnets")
}
