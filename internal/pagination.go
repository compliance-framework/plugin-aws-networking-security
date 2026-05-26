package internal

import (
	"context"
	"iter"

	cloudwatchlogs "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// PaginatedDescribeVpcs returns an iterator over all VPCs in the account/region
func PaginatedDescribeVpcs(ctx context.Context, client *ec2.Client) iter.Seq2[types.Vpc, error] {
	return func(yield func(types.Vpc, error) bool) {
		paginator := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.Vpc{}, err)
				return
			}
			for _, vpc := range page.Vpcs {
				if !yield(vpc, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeSubnets returns an iterator over all subnets in the account/region
func PaginatedDescribeSubnets(ctx context.Context, client *ec2.Client) iter.Seq2[types.Subnet, error] {
	return func(yield func(types.Subnet, error) bool) {
		paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.Subnet{}, err)
				return
			}
			for _, subnet := range page.Subnets {
				if !yield(subnet, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeSecurityGroups returns an iterator over all security groups in the account/region
func PaginatedDescribeSecurityGroups(ctx context.Context, client *ec2.Client) iter.Seq2[types.SecurityGroup, error] {
	return func(yield func(types.SecurityGroup, error) bool) {
		paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.SecurityGroup{}, err)
				return
			}
			for _, sg := range page.SecurityGroups {
				if !yield(sg, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeNetworkInterfaces returns an iterator over all network interfaces in the account/region
func PaginatedDescribeNetworkInterfaces(ctx context.Context, client *ec2.Client) iter.Seq2[types.NetworkInterface, error] {
	return func(yield func(types.NetworkInterface, error) bool) {
		paginator := ec2.NewDescribeNetworkInterfacesPaginator(client, &ec2.DescribeNetworkInterfacesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.NetworkInterface{}, err)
				return
			}
			for _, networkInterface := range page.NetworkInterfaces {
				if !yield(networkInterface, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeNetworkAcls returns an iterator over all network ACLs in the account/region
func PaginatedDescribeNetworkAcls(ctx context.Context, client *ec2.Client) iter.Seq2[types.NetworkAcl, error] {
	return func(yield func(types.NetworkAcl, error) bool) {
		paginator := ec2.NewDescribeNetworkAclsPaginator(client, &ec2.DescribeNetworkAclsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.NetworkAcl{}, err)
				return
			}
			for _, acl := range page.NetworkAcls {
				if !yield(acl, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeRouteTables returns an iterator over all route tables in the account/region
func PaginatedDescribeRouteTables(ctx context.Context, client *ec2.Client) iter.Seq2[types.RouteTable, error] {
	return func(yield func(types.RouteTable, error) bool) {
		paginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.RouteTable{}, err)
				return
			}
			for _, rt := range page.RouteTables {
				if !yield(rt, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeInternetGateways returns an iterator over all internet gateways in the account/region
func PaginatedDescribeInternetGateways(ctx context.Context, client *ec2.Client) iter.Seq2[types.InternetGateway, error] {
	return func(yield func(types.InternetGateway, error) bool) {
		paginator := ec2.NewDescribeInternetGatewaysPaginator(client, &ec2.DescribeInternetGatewaysInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.InternetGateway{}, err)
				return
			}
			for _, igw := range page.InternetGateways {
				if !yield(igw, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeFlowLogs returns an iterator over all flow logs in the account/region
func PaginatedDescribeFlowLogs(ctx context.Context, client *ec2.Client) iter.Seq2[types.FlowLog, error] {
	return func(yield func(types.FlowLog, error) bool) {
		paginator := ec2.NewDescribeFlowLogsPaginator(client, &ec2.DescribeFlowLogsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.FlowLog{}, err)
				return
			}
			for _, fl := range page.FlowLogs {
				if !yield(fl, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeVpcEndpoints returns an iterator over all VPC endpoints in the account/region
func PaginatedDescribeVpcEndpoints(ctx context.Context, client *ec2.Client) iter.Seq2[types.VpcEndpoint, error] {
	return func(yield func(types.VpcEndpoint, error) bool) {
		paginator := ec2.NewDescribeVpcEndpointsPaginator(client, &ec2.DescribeVpcEndpointsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.VpcEndpoint{}, err)
				return
			}
			for _, endpoint := range page.VpcEndpoints {
				if !yield(endpoint, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeTransitGatewayAttachments returns an iterator over all transit gateway attachments in the account/region
func PaginatedDescribeTransitGatewayAttachments(ctx context.Context, client *ec2.Client) iter.Seq2[types.TransitGatewayAttachment, error] {
	return func(yield func(types.TransitGatewayAttachment, error) bool) {
		paginator := ec2.NewDescribeTransitGatewayAttachmentsPaginator(client, &ec2.DescribeTransitGatewayAttachmentsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.TransitGatewayAttachment{}, err)
				return
			}
			for _, attachment := range page.TransitGatewayAttachments {
				if !yield(attachment, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeLogGroups returns an iterator over all CloudWatch Logs log groups
func PaginatedDescribeLogGroups(ctx context.Context, client *cloudwatchlogs.Client) iter.Seq2[cloudwatchlogstypes.LogGroup, error] {
	return func(yield func(cloudwatchlogstypes.LogGroup, error) bool) {
		paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, &cloudwatchlogs.DescribeLogGroupsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(cloudwatchlogstypes.LogGroup{}, err)
				return
			}
			for _, lg := range page.LogGroups {
				if !yield(lg, nil) {
					return
				}
			}
		}
	}
}

// PaginatedDescribeDhcpOptions returns an iterator over all DHCP option sets in the account/region
func PaginatedDescribeDhcpOptions(ctx context.Context, client *ec2.Client) iter.Seq2[types.DhcpOptions, error] {
	return func(yield func(types.DhcpOptions, error) bool) {
		paginator := ec2.NewDescribeDhcpOptionsPaginator(client, &ec2.DescribeDhcpOptionsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield(types.DhcpOptions{}, err)
				return
			}
			for _, options := range page.DhcpOptions {
				if !yield(options, nil) {
					return
				}
			}
		}
	}
}
