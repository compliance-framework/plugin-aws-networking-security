package internal

import (
	"context"
	"errors"
	"iter"

	cloudwatchlogs "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/hashicorp/go-hclog"
)

type RegionDatasets struct {
	Vpcs                      []types.Vpc
	VpcAttributes             map[string]VpcAttributeValues
	DhcpOptions               []types.DhcpOptions
	Subnets                   []types.Subnet
	SecurityGroups            []types.SecurityGroup
	NetworkInterfaces         []types.NetworkInterface
	NetworkAcls               []types.NetworkAcl
	RouteTables               []types.RouteTable
	InternetGateways          []types.InternetGateway
	VpcEndpoints              []types.VpcEndpoint
	FlowLogs                  []types.FlowLog
	LogGroups                 []cloudwatchlogstypes.LogGroup
	TransitGatewayAttachments []types.TransitGatewayAttachment
}

func CollectRegionDatasets(ctx context.Context, logger hclog.Logger, client *ec2.Client, logsClient *cloudwatchlogs.Client, requiredDatasets map[string]bool) (RegionDatasets, error) {
	var (
		datasets RegionDatasets
		err      error
	)

	if requiresEC2Client(requiredDatasets) && client == nil {
		return RegionDatasets{}, errors.New("ec2 client is required for requested region datasets")
	}
	if requiredDatasets["log_groups"] && logsClient == nil {
		return RegionDatasets{}, errors.New("cloudwatch logs client is required for requested region datasets")
	}

	if requiresVpcCollection(requiredDatasets) {
		datasets.Vpcs, err = collectSequence(PaginatedDescribeVpcs(ctx, client))
		if err != nil {
			logger.Error("unable to get VPC", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["vpc_attributes"] {
		datasets.VpcAttributes, err = CollectVpcAttributes(ctx, client, datasets.Vpcs)
		if err != nil {
			logger.Error("unable to get VPC attributes", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["dhcp_options"] {
		datasets.DhcpOptions, err = collectSequence(PaginatedDescribeDhcpOptions(ctx, client))
		if err != nil {
			logger.Error("unable to get DHCP Options", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["subnets"] {
		datasets.Subnets, err = collectSequence(PaginatedDescribeSubnets(ctx, client))
		if err != nil {
			logger.Error("unable to get Subnet", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["security_groups"] {
		datasets.SecurityGroups, err = collectSequence(PaginatedDescribeSecurityGroups(ctx, client))
		if err != nil {
			logger.Error("unable to get Security Group", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["network_interfaces"] {
		datasets.NetworkInterfaces, err = collectSequence(PaginatedDescribeNetworkInterfaces(ctx, client))
		if err != nil {
			logger.Error("unable to get Network Interface", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["network_acls"] {
		datasets.NetworkAcls, err = collectSequence(PaginatedDescribeNetworkAcls(ctx, client))
		if err != nil {
			logger.Error("unable to get Network ACL", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["route_tables"] {
		datasets.RouteTables, err = collectSequence(PaginatedDescribeRouteTables(ctx, client))
		if err != nil {
			logger.Error("unable to get Route Table", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["internet_gateways"] {
		datasets.InternetGateways, err = collectSequence(PaginatedDescribeInternetGateways(ctx, client))
		if err != nil {
			logger.Error("unable to get Internet Gateway", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["vpc_endpoints"] {
		datasets.VpcEndpoints, err = collectSequence(PaginatedDescribeVpcEndpoints(ctx, client))
		if err != nil {
			logger.Error("unable to get VPC Endpoint", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["flow_logs"] {
		datasets.FlowLogs, err = collectSequence(PaginatedDescribeFlowLogs(ctx, client))
		if err != nil {
			logger.Error("unable to get Flow Log", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["log_groups"] {
		datasets.LogGroups, err = collectSequence(PaginatedDescribeLogGroups(ctx, logsClient))
		if err != nil {
			logger.Error("unable to get Log Group", "error", err)
			return RegionDatasets{}, err
		}
	}

	if requiredDatasets["transit_gateway_attachments"] {
		datasets.TransitGatewayAttachments, err = collectSequence(PaginatedDescribeTransitGatewayAttachments(ctx, client))
		if err != nil {
			logger.Error("unable to get Transit Gateway Attachment", "error", err)
			return RegionDatasets{}, err
		}
	}

	return datasets, nil
}

func collectSequence[T any](seq iter.Seq2[T, error]) ([]T, error) {
	items := make([]T, 0)
	for item, err := range seq {
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func requiresVpcCollection(requiredDatasets map[string]bool) bool {
	return requiredDatasets["vpcs"] || requiredDatasets["vpc_attributes"]
}

func requiresEC2Client(requiredDatasets map[string]bool) bool {
	for _, datasetName := range []string{
		"vpcs",
		"vpc_attributes",
		"dhcp_options",
		"subnets",
		"security_groups",
		"network_interfaces",
		"network_acls",
		"route_tables",
		"internet_gateways",
		"vpc_endpoints",
		"flow_logs",
		"transit_gateway_attachments",
	} {
		if requiredDatasets[datasetName] {
			return true
		}
	}
	return false
}
