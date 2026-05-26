package internal

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type VpcAttributeValues struct {
	EnableDnsSupport                 *bool `json:"enable_dns_support,omitempty"`
	EnableDnsHostnames               *bool `json:"enable_dns_hostnames,omitempty"`
	EnableNetworkAddressUsageMetrics *bool `json:"enable_network_address_usage_metrics,omitempty"`
}

func CollectVpcAttributes(ctx context.Context, client *ec2.Client, vpcs []types.Vpc) (map[string]VpcAttributeValues, error) {
	attributesByVpcID := make(map[string]VpcAttributeValues)
	for _, vpc := range vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		if vpcID == "" {
			continue
		}

		attributes, err := describeVpcAttributes(ctx, client, vpcID)
		if err != nil {
			return nil, err
		}
		attributesByVpcID[vpcID] = attributes
	}
	return attributesByVpcID, nil
}

func describeVpcAttributes(ctx context.Context, client *ec2.Client, vpcID string) (VpcAttributeValues, error) {
	var attributes VpcAttributeValues

	dnsSupport, err := describeVpcAttribute(ctx, client, vpcID, types.VpcAttributeNameEnableDnsSupport)
	if err != nil {
		return VpcAttributeValues{}, err
	}
	attributes.EnableDnsSupport = attributeBooleanValue(dnsSupport.EnableDnsSupport)

	dnsHostnames, err := describeVpcAttribute(ctx, client, vpcID, types.VpcAttributeNameEnableDnsHostnames)
	if err != nil {
		return VpcAttributeValues{}, err
	}
	attributes.EnableDnsHostnames = attributeBooleanValue(dnsHostnames.EnableDnsHostnames)

	networkAddressUsageMetrics, err := describeVpcAttribute(ctx, client, vpcID, types.VpcAttributeNameEnableNetworkAddressUsageMetrics)
	if err != nil {
		return VpcAttributeValues{}, err
	}
	attributes.EnableNetworkAddressUsageMetrics = attributeBooleanValue(networkAddressUsageMetrics.EnableNetworkAddressUsageMetrics)

	return attributes, nil
}

func describeVpcAttribute(ctx context.Context, client *ec2.Client, vpcID string, attribute types.VpcAttributeName) (*ec2.DescribeVpcAttributeOutput, error) {
	return client.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		VpcId:     aws.String(vpcID),
		Attribute: attribute,
	})
}

func BuildVpcPolicyInput(vpc types.Vpc, region string, datasets RegionDatasets) (map[string]interface{}, error) {
	vpcValue, err := toInterfaceMap(vpc)
	if err != nil {
		return nil, err
	}

	contextValue, err := toInterfaceMap(buildVpcSupplementaryContext(vpc, region, datasets))
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"vpc":         vpcValue,
		"vpc_context": contextValue,
	}, nil
}

func buildVpcSupplementaryContext(vpc types.Vpc, region string, datasets RegionDatasets) map[string]interface{} {
	vpcID := aws.ToString(vpc.VpcId)
	flowLogs := filterFlowLogsByResourceIDs(datasets.FlowLogs, singletonIDSet(vpcID))

	return map[string]interface{}{
		"current": map[string]interface{}{
			"vpc_id":          vpcID,
			"region":          region,
			"cidr_block":      aws.ToString(vpc.CidrBlock),
			"dhcp_options_id": aws.ToString(vpc.DhcpOptionsId),
			"is_default":      aws.ToBool(vpc.IsDefault),
			"state":           string(vpc.State),
			"tags_present":    len(vpc.Tags) > 0,
		},
		"attributes":                          datasets.VpcAttributes[vpcID],
		"dhcp_options":                        findDhcpOptionsByID(datasets.DhcpOptions, aws.ToString(vpc.DhcpOptionsId)),
		"subnets_in_vpc":                      filterSubnetsByVpc(datasets.Subnets, vpcID),
		"route_tables_in_vpc":                 filterRouteTablesByVpc(datasets.RouteTables, vpcID),
		"internet_gateways_for_vpc":           filterInternetGatewaysByVpc(datasets.InternetGateways, vpcID),
		"vpc_endpoints_for_vpc":               filterVpcEndpointsByVpc(datasets.VpcEndpoints, vpcID),
		"flow_logs_for_vpc":                   flowLogs,
		"log_groups_for_vpc_flow_logs":        filterLogGroupsForFlowLogs(datasets.LogGroups, flowLogs, singletonIDSet(vpcID)),
		"transit_gateway_attachments_for_vpc": filterTransitGatewayAttachmentsByResourceID(datasets.TransitGatewayAttachments, vpcID),
	}
}

func filterSubnetsByVpc(subnets []types.Subnet, vpcID string) []types.Subnet {
	filtered := make([]types.Subnet, 0)
	for _, subnet := range subnets {
		if aws.ToString(subnet.VpcId) == vpcID {
			filtered = append(filtered, subnet)
		}
	}
	return filtered
}

func findDhcpOptionsByID(dhcpOptions []types.DhcpOptions, dhcpOptionsID string) *types.DhcpOptions {
	for _, options := range dhcpOptions {
		if aws.ToString(options.DhcpOptionsId) == dhcpOptionsID {
			optionsCopy := options
			return &optionsCopy
		}
	}
	return nil
}

func attributeBooleanValue(value *types.AttributeBooleanValue) *bool {
	if value == nil {
		return nil
	}
	return value.Value
}
