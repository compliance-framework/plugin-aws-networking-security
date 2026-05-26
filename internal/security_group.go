package internal

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func EvaluateSecurityGroupPolicies(deps EvaluationDependencies, policyPaths []string, securityGroups []types.SecurityGroup, region string, datasets RegionDatasets) ResourceEvaluationErrors {
	return evaluateResources(
		deps,
		policyPaths,
		securityGroups,
		func(group types.SecurityGroup) ResourceEvidenceContext {
			sgCtx := BuildSecurityGroupEvidenceContext(group, region)
			return newResourceEvidenceContext(sgCtx.Labels, sgCtx.Subjects, sgCtx.Components, sgCtx.Inventory)
		},
		func(group types.SecurityGroup) (interface{}, error) {
			return BuildSecurityGroupPolicyInput(group, region, datasets)
		},
		func(group types.SecurityGroup, err error) {
			deps.Logger.Error("unable to build security group policy input", "group_id", aws.ToString(group.GroupId), "region", region, "error", err)
		},
		func(evidences []*proto.Evidence, group types.SecurityGroup) {
			PrefixSecurityGroupEvidenceTitles(evidences, aws.ToString(group.GroupName))
		},
	)
}

func BuildSecurityGroupPolicyInput(group types.SecurityGroup, region string, datasets RegionDatasets) (map[string]interface{}, error) {
	securityGroupValue, err := toInterfaceMap(group)
	if err != nil {
		return nil, err
	}

	contextValue, err := toInterfaceMap(buildSecurityGroupSupplementaryContext(group, region, datasets))
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"security_group": securityGroupValue,
		"sg_context":     contextValue,
	}, nil
}

func buildSecurityGroupSupplementaryContext(group types.SecurityGroup, region string, datasets RegionDatasets) map[string]interface{} {
	groupID := aws.ToString(group.GroupId)
	vpcID := aws.ToString(group.VpcId)
	attachedNetworkInterfaces := filterNetworkInterfacesBySecurityGroup(datasets.NetworkInterfaces, groupID)
	attachedSubnetIDs := subnetIDsFromNetworkInterfaces(attachedNetworkInterfaces)
	attachedNetworkInterfaceIDs := networkInterfaceIDs(attachedNetworkInterfaces)

	return map[string]interface{}{
		"current": map[string]interface{}{
			"group_id":     groupID,
			"group_name":   aws.ToString(group.GroupName),
			"vpc_id":       vpcID,
			"region":       region,
			"is_default":   aws.ToString(group.GroupName) == "default",
			"tags_present": len(group.Tags) > 0,
		},
		"vpc":                                 findVpcByID(datasets.Vpcs, vpcID),
		"security_groups_in_vpc":              filterSecurityGroupsByVpc(datasets.SecurityGroups, vpcID),
		"attached_network_interfaces":         attachedNetworkInterfaces,
		"attached_subnets":                    filterSubnetsByIDs(datasets.Subnets, attachedSubnetIDs),
		"route_tables_in_vpc":                 filterRouteTablesByVpc(datasets.RouteTables, vpcID),
		"route_tables_for_attached_subnets":   filterRouteTablesForSubnetIDs(datasets.RouteTables, vpcID, attachedSubnetIDs),
		"network_acls_in_vpc":                 filterNetworkAclsByVpc(datasets.NetworkAcls, vpcID),
		"network_acls_for_attached_subnets":   filterNetworkAclsForSubnetIDs(datasets.NetworkAcls, attachedSubnetIDs),
		"internet_gateways_for_vpc":           filterInternetGatewaysByVpc(datasets.InternetGateways, vpcID),
		"vpc_endpoints_for_vpc":               filterVpcEndpointsByVpc(datasets.VpcEndpoints, vpcID),
		"flow_logs_for_related_resources":     filterFlowLogsByResourceIDs(datasets.FlowLogs, combineIDSets(singletonIDSet(vpcID), attachedSubnetIDs, attachedNetworkInterfaceIDs)),
		"log_groups_for_related_flow_logs":    filterLogGroupsForFlowLogs(datasets.LogGroups, datasets.FlowLogs, combineIDSets(singletonIDSet(vpcID), attachedSubnetIDs, attachedNetworkInterfaceIDs)),
		"transit_gateway_attachments_for_vpc": filterTransitGatewayAttachmentsByResourceID(datasets.TransitGatewayAttachments, vpcID),
	}
}

func toInterfaceMap(value interface{}) (map[string]interface{}, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	if err := json.Unmarshal(content, &result); err != nil {
		return nil, err
	}

	return result, nil
}

func singletonIDSet(id string) map[string]bool {
	ids := make(map[string]bool)
	if id != "" {
		ids[id] = true
	}
	return ids
}

func combineIDSets(sets ...map[string]bool) map[string]bool {
	combined := make(map[string]bool)
	for _, set := range sets {
		for id := range set {
			combined[id] = true
		}
	}
	return combined
}

func filterNetworkInterfacesBySecurityGroup(networkInterfaces []types.NetworkInterface, groupID string) []types.NetworkInterface {
	filtered := make([]types.NetworkInterface, 0)
	for _, networkInterface := range networkInterfaces {
		for _, group := range networkInterface.Groups {
			if aws.ToString(group.GroupId) == groupID {
				filtered = append(filtered, networkInterface)
				break
			}
		}
	}
	return filtered
}

func subnetIDsFromNetworkInterfaces(networkInterfaces []types.NetworkInterface) map[string]bool {
	ids := make(map[string]bool)
	for _, networkInterface := range networkInterfaces {
		subnetID := aws.ToString(networkInterface.SubnetId)
		if subnetID != "" {
			ids[subnetID] = true
		}
	}
	return ids
}

func networkInterfaceIDs(networkInterfaces []types.NetworkInterface) map[string]bool {
	ids := make(map[string]bool)
	for _, networkInterface := range networkInterfaces {
		networkInterfaceID := aws.ToString(networkInterface.NetworkInterfaceId)
		if networkInterfaceID != "" {
			ids[networkInterfaceID] = true
		}
	}
	return ids
}

func findVpcByID(vpcs []types.Vpc, vpcID string) *types.Vpc {
	for _, vpc := range vpcs {
		if aws.ToString(vpc.VpcId) == vpcID {
			vpcCopy := vpc
			return &vpcCopy
		}
	}
	return nil
}

func filterSecurityGroupsByVpc(securityGroups []types.SecurityGroup, vpcID string) []types.SecurityGroup {
	filtered := make([]types.SecurityGroup, 0)
	for _, securityGroup := range securityGroups {
		if aws.ToString(securityGroup.VpcId) == vpcID {
			filtered = append(filtered, securityGroup)
		}
	}
	return filtered
}

func filterSubnetsByIDs(subnets []types.Subnet, subnetIDs map[string]bool) []types.Subnet {
	filtered := make([]types.Subnet, 0)
	for _, subnet := range subnets {
		if subnetIDs[aws.ToString(subnet.SubnetId)] {
			filtered = append(filtered, subnet)
		}
	}
	return filtered
}

func filterRouteTablesByVpc(routeTables []types.RouteTable, vpcID string) []types.RouteTable {
	filtered := make([]types.RouteTable, 0)
	for _, routeTable := range routeTables {
		if aws.ToString(routeTable.VpcId) == vpcID {
			filtered = append(filtered, routeTable)
		}
	}
	return filtered
}

func filterRouteTablesForSubnetIDs(routeTables []types.RouteTable, vpcID string, subnetIDs map[string]bool) []types.RouteTable {
	filtered := make([]types.RouteTable, 0)
	for _, routeTable := range routeTables {
		if aws.ToString(routeTable.VpcId) != vpcID {
			continue
		}

		include := false
		for _, association := range routeTable.Associations {
			if subnetIDs[aws.ToString(association.SubnetId)] || aws.ToBool(association.Main) {
				include = true
				break
			}
		}
		if include {
			filtered = append(filtered, routeTable)
		}
	}
	return filtered
}

func filterNetworkAclsByVpc(networkAcls []types.NetworkAcl, vpcID string) []types.NetworkAcl {
	filtered := make([]types.NetworkAcl, 0)
	for _, networkAcl := range networkAcls {
		if aws.ToString(networkAcl.VpcId) == vpcID {
			filtered = append(filtered, networkAcl)
		}
	}
	return filtered
}

func filterNetworkAclsForSubnetIDs(networkAcls []types.NetworkAcl, subnetIDs map[string]bool) []types.NetworkAcl {
	filtered := make([]types.NetworkAcl, 0)
	for _, networkAcl := range networkAcls {
		include := false
		for _, association := range networkAcl.Associations {
			if subnetIDs[aws.ToString(association.SubnetId)] {
				include = true
				break
			}
		}
		if include {
			filtered = append(filtered, networkAcl)
		}
	}
	return filtered
}

func filterInternetGatewaysByVpc(internetGateways []types.InternetGateway, vpcID string) []types.InternetGateway {
	filtered := make([]types.InternetGateway, 0)
	for _, internetGateway := range internetGateways {
		for _, attachment := range internetGateway.Attachments {
			if aws.ToString(attachment.VpcId) == vpcID {
				filtered = append(filtered, internetGateway)
				break
			}
		}
	}
	return filtered
}

func filterVpcEndpointsByVpc(vpcEndpoints []types.VpcEndpoint, vpcID string) []types.VpcEndpoint {
	filtered := make([]types.VpcEndpoint, 0)
	for _, vpcEndpoint := range vpcEndpoints {
		if aws.ToString(vpcEndpoint.VpcId) == vpcID {
			filtered = append(filtered, vpcEndpoint)
		}
	}
	return filtered
}

func filterFlowLogsByResourceIDs(flowLogs []types.FlowLog, resourceIDs map[string]bool) []types.FlowLog {
	filtered := make([]types.FlowLog, 0)
	for _, flowLog := range flowLogs {
		if resourceIDs[aws.ToString(flowLog.ResourceId)] {
			filtered = append(filtered, flowLog)
		}
	}
	return filtered
}

func filterLogGroupsForFlowLogs(logGroups []cloudwatchlogstypes.LogGroup, flowLogs []types.FlowLog, resourceIDs map[string]bool) []cloudwatchlogstypes.LogGroup {
	logGroupNames := make(map[string]bool)
	for _, flowLog := range flowLogs {
		if !resourceIDs[aws.ToString(flowLog.ResourceId)] {
			continue
		}
		logGroupName := aws.ToString(flowLog.LogGroupName)
		if logGroupName != "" {
			logGroupNames[logGroupName] = true
		}
	}

	filtered := make([]cloudwatchlogstypes.LogGroup, 0)
	for _, logGroup := range logGroups {
		if logGroupNames[aws.ToString(logGroup.LogGroupName)] {
			filtered = append(filtered, logGroup)
		}
	}
	return filtered
}

func filterTransitGatewayAttachmentsByResourceID(attachments []types.TransitGatewayAttachment, resourceID string) []types.TransitGatewayAttachment {
	filtered := make([]types.TransitGatewayAttachment, 0)
	for _, attachment := range attachments {
		if aws.ToString(attachment.ResourceId) == resourceID {
			filtered = append(filtered, attachment)
		}
	}
	return filtered
}
