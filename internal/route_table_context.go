package internal

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func BuildRouteTablePolicyInput(routeTable types.RouteTable, region string, datasets RegionDatasets) (map[string]interface{}, error) {
	routeTableValue, err := toInterfaceMap(routeTable)
	if err != nil {
		return nil, err
	}

	contextValue, err := toInterfaceMap(buildRouteTableSupplementaryContext(routeTable, region, datasets))
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"route_table":         routeTableValue,
		"route_table_context": contextValue,
	}, nil
}

func buildRouteTableSupplementaryContext(routeTable types.RouteTable, region string, datasets RegionDatasets) map[string]interface{} {
	routeTableID := aws.ToString(routeTable.RouteTableId)
	vpcID := aws.ToString(routeTable.VpcId)
	explicitSubnetIDs := routeTableExplicitSubnetIDs(routeTable)
	implicitSubnetIDs := routeTableImplicitSubnetIDs(routeTable, datasets.RouteTables, datasets.Subnets, vpcID)
	effectiveSubnetIDs := combineIDSets(explicitSubnetIDs, implicitSubnetIDs)
	gatewayAssociationIDs := routeTableGatewayAssociationIDs(routeTable)
	routeSummaries := summarizeRoutes(routeTable.Routes)
	blackholeRoutes := filterRouteSummariesByState(routeSummaries, "blackhole")

	return map[string]interface{}{
		"current": map[string]interface{}{
			"route_table_id":                                routeTableID,
			"vpc_id":                                        vpcID,
			"owner_id":                                      aws.ToString(routeTable.OwnerId),
			"region":                                        region,
			"is_main":                                       routeTableIsMain(routeTable),
			"association_count":                             len(routeTable.Associations),
			"explicit_subnet_association_count":             len(explicitSubnetIDs),
			"implicit_subnet_association_count":             len(implicitSubnetIDs),
			"effective_subnet_association_count":            len(effectiveSubnetIDs),
			"gateway_association_count":                     len(gatewayAssociationIDs),
			"route_count":                                   len(routeTable.Routes),
			"blackhole_route_count":                         len(blackholeRoutes),
			"explicitly_associated_subnet_ids":              sortedIDSetValues(explicitSubnetIDs),
			"implicitly_associated_subnet_ids":              sortedIDSetValues(implicitSubnetIDs),
			"effectively_associated_subnet_ids":             sortedIDSetValues(effectiveSubnetIDs),
			"gateway_association_ids":                       sortedIDSetValues(gatewayAssociationIDs),
			"has_blackhole_routes":                          len(blackholeRoutes) > 0,
			"has_ipv4_default_route_to_internet_gateway":    hasIPv4DefaultRouteToInternetGateway(routeTable.Routes),
			"has_ipv6_default_route_to_internet_gateway":    hasIPv6DefaultRouteToInternetGateway(routeTable.Routes),
			"has_default_route_to_internet_gateway":         hasDefaultRouteToInternetGateway(routeTable.Routes),
			"has_ipv6_default_route_to_egress_only_gateway": hasIPv6DefaultRouteToEgressOnlyInternetGateway(routeTable.Routes),
			"has_default_route_to_nat_gateway":              hasDefaultRouteToNatGateway(routeTable.Routes),
			"has_default_route_to_transit_gateway":          hasDefaultRouteToTransitGateway(routeTable.Routes),
			"has_default_route_to_vpc_peering_connection":   hasDefaultRouteToVpcPeeringConnection(routeTable.Routes),
			"has_gateway_endpoint_routes":                   len(filterVpcEndpointsByRouteTable(datasets.VpcEndpoints, vpcID, routeTableID)) > 0,
			"propagating_vgw_count":                         len(routeTable.PropagatingVgws),
			"tags_present":                                  len(routeTable.Tags) > 0,
		},
		"vpc":                                 findVpcByID(datasets.Vpcs, vpcID),
		"subnets_in_vpc":                      filterSubnetsByVpc(datasets.Subnets, vpcID),
		"explicitly_associated_subnets":       filterSubnetsByIDs(datasets.Subnets, explicitSubnetIDs),
		"implicitly_associated_subnets":       filterSubnetsByIDs(datasets.Subnets, implicitSubnetIDs),
		"effectively_associated_subnets":      filterSubnetsByIDs(datasets.Subnets, effectiveSubnetIDs),
		"internet_gateways_for_vpc":           filterInternetGatewaysByVpc(datasets.InternetGateways, vpcID),
		"vpc_endpoints_for_vpc":               filterVpcEndpointsByVpc(datasets.VpcEndpoints, vpcID),
		"vpc_endpoints_for_route_table":       filterVpcEndpointsByRouteTable(datasets.VpcEndpoints, vpcID, routeTableID),
		"transit_gateway_attachments_for_vpc": filterTransitGatewayAttachmentsByResourceID(datasets.TransitGatewayAttachments, vpcID),
		"route_summaries":                     routeSummaries,
		"blackhole_routes":                    blackholeRoutes,
	}
}

func routeTableIsMain(routeTable types.RouteTable) bool {
	for _, association := range routeTable.Associations {
		if aws.ToBool(association.Main) {
			return true
		}
	}
	return false
}

func routeTableExplicitSubnetIDs(routeTable types.RouteTable) map[string]bool {
	subnetIDs := make(map[string]bool)
	for _, association := range routeTable.Associations {
		subnetID := aws.ToString(association.SubnetId)
		if subnetID != "" {
			subnetIDs[subnetID] = true
		}
	}
	return subnetIDs
}

func routeTableImplicitSubnetIDs(routeTable types.RouteTable, routeTables []types.RouteTable, subnets []types.Subnet, vpcID string) map[string]bool {
	if !routeTableIsMain(routeTable) {
		return map[string]bool{}
	}

	explicitSubnetIDsInVpc := make(map[string]bool)
	for _, candidate := range routeTables {
		if aws.ToString(candidate.VpcId) != vpcID {
			continue
		}
		for subnetID := range routeTableExplicitSubnetIDs(candidate) {
			explicitSubnetIDsInVpc[subnetID] = true
		}
	}

	implicitSubnetIDs := make(map[string]bool)
	for _, subnet := range subnets {
		if aws.ToString(subnet.VpcId) != vpcID {
			continue
		}
		subnetID := aws.ToString(subnet.SubnetId)
		if subnetID != "" && !explicitSubnetIDsInVpc[subnetID] {
			implicitSubnetIDs[subnetID] = true
		}
	}
	return implicitSubnetIDs
}

func routeTableGatewayAssociationIDs(routeTable types.RouteTable) map[string]bool {
	gatewayIDs := make(map[string]bool)
	for _, association := range routeTable.Associations {
		gatewayID := aws.ToString(association.GatewayId)
		if gatewayID != "" {
			gatewayIDs[gatewayID] = true
		}
	}
	return gatewayIDs
}

func summarizeRoutes(routes []types.Route) []map[string]interface{} {
	summaries := make([]map[string]interface{}, 0, len(routes))
	for _, route := range routes {
		targetType, targetID := routeTarget(route)
		summaries = append(summaries, map[string]interface{}{
			"destination":      routeDestination(route),
			"destination_type": routeDestinationType(route),
			"target_type":      targetType,
			"target_id":        targetID,
			"state":            string(route.State),
			"origin":           string(route.Origin),
		})
	}
	return summaries
}

func filterRouteSummariesByState(routeSummaries []map[string]interface{}, state string) []map[string]interface{} {
	filtered := make([]map[string]interface{}, 0)
	for _, routeSummary := range routeSummaries {
		if routeSummary["state"] == state {
			filtered = append(filtered, routeSummary)
		}
	}
	return filtered
}

func routeDestination(route types.Route) string {
	switch {
	case aws.ToString(route.DestinationCidrBlock) != "":
		return aws.ToString(route.DestinationCidrBlock)
	case aws.ToString(route.DestinationIpv6CidrBlock) != "":
		return aws.ToString(route.DestinationIpv6CidrBlock)
	case aws.ToString(route.DestinationPrefixListId) != "":
		return aws.ToString(route.DestinationPrefixListId)
	default:
		return ""
	}
}

func routeDestinationType(route types.Route) string {
	switch {
	case aws.ToString(route.DestinationCidrBlock) != "":
		return "ipv4_cidr"
	case aws.ToString(route.DestinationIpv6CidrBlock) != "":
		return "ipv6_cidr"
	case aws.ToString(route.DestinationPrefixListId) != "":
		return "prefix_list"
	default:
		return "unknown"
	}
}

func routeTarget(route types.Route) (string, string) {
	targets := []struct {
		targetType string
		targetID   string
	}{
		{"carrier_gateway", aws.ToString(route.CarrierGatewayId)},
		{"core_network", aws.ToString(route.CoreNetworkArn)},
		{"egress_only_internet_gateway", aws.ToString(route.EgressOnlyInternetGatewayId)},
		{"gateway", aws.ToString(route.GatewayId)},
		{"instance", aws.ToString(route.InstanceId)},
		{"local_gateway", aws.ToString(route.LocalGatewayId)},
		{"nat_gateway", aws.ToString(route.NatGatewayId)},
		{"network_interface", aws.ToString(route.NetworkInterfaceId)},
		{"transit_gateway", aws.ToString(route.TransitGatewayId)},
		{"vpc_peering_connection", aws.ToString(route.VpcPeeringConnectionId)},
	}
	for _, target := range targets {
		if target.targetID != "" {
			return target.targetType, target.targetID
		}
	}
	return "unknown", ""
}

func hasIPv4DefaultRouteToInternetGateway(routes []types.Route) bool {
	for _, route := range routes {
		if aws.ToString(route.DestinationCidrBlock) == "0.0.0.0/0" && strings.HasPrefix(aws.ToString(route.GatewayId), "igw-") {
			return true
		}
	}
	return false
}

func hasIPv6DefaultRouteToInternetGateway(routes []types.Route) bool {
	for _, route := range routes {
		if aws.ToString(route.DestinationIpv6CidrBlock) == "::/0" && strings.HasPrefix(aws.ToString(route.GatewayId), "igw-") {
			return true
		}
	}
	return false
}

func hasDefaultRouteToInternetGateway(routes []types.Route) bool {
	return hasIPv4DefaultRouteToInternetGateway(routes) || hasIPv6DefaultRouteToInternetGateway(routes)
}

func hasIPv6DefaultRouteToEgressOnlyInternetGateway(routes []types.Route) bool {
	for _, route := range routes {
		if aws.ToString(route.DestinationIpv6CidrBlock) == "::/0" && aws.ToString(route.EgressOnlyInternetGatewayId) != "" {
			return true
		}
	}
	return false
}

func hasDefaultRouteToNatGateway(routes []types.Route) bool {
	for _, route := range routes {
		if isDefaultRoute(route) && aws.ToString(route.NatGatewayId) != "" {
			return true
		}
	}
	return false
}

func hasDefaultRouteToTransitGateway(routes []types.Route) bool {
	for _, route := range routes {
		if isDefaultRoute(route) && aws.ToString(route.TransitGatewayId) != "" {
			return true
		}
	}
	return false
}

func hasDefaultRouteToVpcPeeringConnection(routes []types.Route) bool {
	for _, route := range routes {
		if isDefaultRoute(route) && aws.ToString(route.VpcPeeringConnectionId) != "" {
			return true
		}
	}
	return false
}

func isDefaultRoute(route types.Route) bool {
	return aws.ToString(route.DestinationCidrBlock) == "0.0.0.0/0" || aws.ToString(route.DestinationIpv6CidrBlock) == "::/0"
}

func filterVpcEndpointsByRouteTable(vpcEndpoints []types.VpcEndpoint, vpcID string, routeTableID string) []types.VpcEndpoint {
	filtered := make([]types.VpcEndpoint, 0)
	for _, endpoint := range vpcEndpoints {
		if aws.ToString(endpoint.VpcId) != vpcID {
			continue
		}
		for _, endpointRouteTableID := range endpoint.RouteTableIds {
			if endpointRouteTableID == routeTableID {
				filtered = append(filtered, endpoint)
				break
			}
		}
	}
	return filtered
}
