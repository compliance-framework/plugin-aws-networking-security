package internal

import (
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func BuildNetworkAclPolicyInput(networkAcl types.NetworkAcl, region string, datasets RegionDatasets) (map[string]interface{}, error) {
	networkAclValue, err := toInterfaceMap(networkAcl)
	if err != nil {
		return nil, err
	}

	contextValue, err := toInterfaceMap(buildNetworkAclSupplementaryContext(networkAcl, region, datasets))
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"network_acl":  networkAclValue,
		"nacl_context": contextValue,
	}, nil
}

func buildNetworkAclSupplementaryContext(networkAcl types.NetworkAcl, region string, datasets RegionDatasets) map[string]interface{} {
	networkAclID := aws.ToString(networkAcl.NetworkAclId)
	vpcID := aws.ToString(networkAcl.VpcId)
	associatedSubnetIDs := networkAclAssociatedSubnetIDs(networkAcl)
	relatedResourceIDs := combineIDSets(singletonIDSet(vpcID), associatedSubnetIDs)
	flowLogsForVpc := filterFlowLogsByResourceIDs(datasets.FlowLogs, singletonIDSet(vpcID))
	flowLogsForAssociatedSubnets := filterFlowLogsByResourceIDs(datasets.FlowLogs, associatedSubnetIDs)

	return map[string]interface{}{
		"current": map[string]interface{}{
			"network_acl_id":          networkAclID,
			"vpc_id":                  vpcID,
			"region":                  region,
			"is_default":              aws.ToBool(networkAcl.IsDefault),
			"association_count":       len(networkAcl.Associations),
			"entry_count":             len(networkAcl.Entries),
			"associated_subnet_ids":   sortedIDSetValues(associatedSubnetIDs),
			"has_subnet_associations": len(networkAcl.Associations) > 0,
			"tags_present":            len(networkAcl.Tags) > 0,
		},
		"vpc":                                      findVpcByID(datasets.Vpcs, vpcID),
		"associated_subnets":                       filterSubnetsByIDs(datasets.Subnets, associatedSubnetIDs),
		"route_tables_in_vpc":                      filterRouteTablesByVpc(datasets.RouteTables, vpcID),
		"route_tables_for_associated_subnets":      filterRouteTablesForSubnetIDs(datasets.RouteTables, vpcID, associatedSubnetIDs),
		"internet_gateways_for_vpc":                filterInternetGatewaysByVpc(datasets.InternetGateways, vpcID),
		"flow_logs_for_vpc":                        flowLogsForVpc,
		"flow_logs_for_associated_subnets":         flowLogsForAssociatedSubnets,
		"log_groups_for_related_flow_logs":         filterLogGroupsForFlowLogs(datasets.LogGroups, append(flowLogsForVpc, flowLogsForAssociatedSubnets...), relatedResourceIDs),
		"network_interfaces_in_associated_subnets": filterNetworkInterfacesBySubnetIDs(datasets.NetworkInterfaces, associatedSubnetIDs),
	}
}

func networkAclAssociatedSubnetIDs(networkAcl types.NetworkAcl) map[string]bool {
	subnetIDs := make(map[string]bool)
	for _, association := range networkAcl.Associations {
		subnetID := aws.ToString(association.SubnetId)
		if subnetID != "" {
			subnetIDs[subnetID] = true
		}
	}
	return subnetIDs
}

func filterNetworkInterfacesBySubnetIDs(networkInterfaces []types.NetworkInterface, subnetIDs map[string]bool) []types.NetworkInterface {
	filtered := make([]types.NetworkInterface, 0)
	for _, networkInterface := range networkInterfaces {
		if subnetIDs[aws.ToString(networkInterface.SubnetId)] {
			filtered = append(filtered, networkInterface)
		}
	}
	return filtered
}

func sortedIDSetValues(values map[string]bool) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
