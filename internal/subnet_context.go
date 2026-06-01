package internal

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func BuildSubnetPolicyInput(subnet types.Subnet, region string, datasets RegionDatasets) (map[string]interface{}, error) {
	subnetValue, err := toInterfaceMap(subnet)
	if err != nil {
		return nil, err
	}

	contextValue, err := toInterfaceMap(buildSubnetSupplementaryContext(subnet, region, datasets))
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"subnet":         subnetValue,
		"subnet_context": contextValue,
	}, nil
}

func buildSubnetSupplementaryContext(subnet types.Subnet, region string, datasets RegionDatasets) map[string]interface{} {
	subnetID := aws.ToString(subnet.SubnetId)
	vpcID := aws.ToString(subnet.VpcId)
	subnetIDs := singletonIDSet(subnetID)
	relatedResourceIDs := combineIDSets(singletonIDSet(vpcID), subnetIDs)
	flowLogsForVpc := filterFlowLogsByResourceIDs(datasets.FlowLogs, singletonIDSet(vpcID))
	flowLogsForSubnet := filterFlowLogsByResourceIDs(datasets.FlowLogs, subnetIDs)

	return map[string]interface{}{
		"current": map[string]interface{}{
			"subnet_id":                  subnetID,
			"vpc_id":                     vpcID,
			"region":                     region,
			"availability_zone":          aws.ToString(subnet.AvailabilityZone),
			"availability_zone_id":       aws.ToString(subnet.AvailabilityZoneId),
			"cidr_block":                 aws.ToString(subnet.CidrBlock),
			"ipv6_cidr_block_count":      len(subnet.Ipv6CidrBlockAssociationSet),
			"state":                      string(subnet.State),
			"map_public_ip_on_launch":    aws.ToBool(subnet.MapPublicIpOnLaunch),
			"available_ip_address_count": aws.ToInt32(subnet.AvailableIpAddressCount),
			"tags_present":               len(subnet.Tags) > 0,
		},
		"vpc":                              findVpcByID(datasets.Vpcs, vpcID),
		"route_tables_in_vpc":              filterRouteTablesByVpc(datasets.RouteTables, vpcID),
		"route_table_for_subnet":           findRouteTableForSubnet(datasets.RouteTables, vpcID, subnetID),
		"explicit_route_table_association": hasExplicitRouteTableAssociation(datasets.RouteTables, subnetID),
		"network_acls_for_subnet":          filterNetworkAclsForSubnetIDs(datasets.NetworkAcls, subnetIDs),
		"internet_gateways_for_vpc":        filterInternetGatewaysByVpc(datasets.InternetGateways, vpcID),
		"flow_logs_for_vpc":                flowLogsForVpc,
		"flow_logs_for_subnet":             flowLogsForSubnet,
		"log_groups_for_related_flow_logs": filterLogGroupsForFlowLogs(datasets.LogGroups, append(flowLogsForVpc, flowLogsForSubnet...), relatedResourceIDs),
	}
}

func findRouteTableForSubnet(routeTables []types.RouteTable, vpcID string, subnetID string) *types.RouteTable {
	for _, routeTable := range routeTables {
		if aws.ToString(routeTable.VpcId) != vpcID {
			continue
		}
		for _, association := range routeTable.Associations {
			if aws.ToString(association.SubnetId) == subnetID {
				routeTableCopy := routeTable
				return &routeTableCopy
			}
		}
	}

	for _, routeTable := range routeTables {
		if aws.ToString(routeTable.VpcId) != vpcID {
			continue
		}
		for _, association := range routeTable.Associations {
			if aws.ToBool(association.Main) {
				routeTableCopy := routeTable
				return &routeTableCopy
			}
		}
	}

	return nil
}

func hasExplicitRouteTableAssociation(routeTables []types.RouteTable, subnetID string) bool {
	for _, routeTable := range routeTables {
		for _, association := range routeTable.Associations {
			if aws.ToString(association.SubnetId) == subnetID {
				return true
			}
		}
	}
	return false
}
