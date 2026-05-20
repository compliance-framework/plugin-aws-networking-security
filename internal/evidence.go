package internal

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

// VpcEvidenceContext contains the evidence context for a VPC
type VpcEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// SubnetEvidenceContext contains the evidence context for a Subnet
type SubnetEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// SecurityGroupEvidenceContext contains the evidence context for a Security Group
type SecurityGroupEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// NetworkAclEvidenceContext contains the evidence context for a Network ACL
type NetworkAclEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// RouteTableEvidenceContext contains the evidence context for a Route Table
type RouteTableEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// InternetGatewayEvidenceContext contains the evidence context for an Internet Gateway
type InternetGatewayEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// VpcEndpointEvidenceContext contains the evidence context for a VPC Endpoint
type VpcEndpointEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// FlowLogEvidenceContext contains the evidence context for a Flow Log
type FlowLogEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// LogGroupEvidenceContext contains the evidence context for a Log Group
type LogGroupEvidenceContext struct {
	Labels     map[string]string
	Components []*proto.Component
	Inventory  []*proto.InventoryItem
	Subjects   []*proto.Subject
}

// BuildVpcEvidenceContext builds evidence context for a VPC
func BuildVpcEvidenceContext(vpc types.Vpc, region string) VpcEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeVPC)
	vpcId := aws.ToString(vpc.VpcId)

	labels := map[string]string{
		"provider": "aws",
		"type":     string(ResourceTypeVPC),
		"vpc-id":   vpcId,
		"cidr":     aws.ToString(vpc.CidrBlock),
		"region":   region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, vpcId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, vpcId),
			Props: []*proto.Property{
				{
					Name:  "vpc-id",
					Value: vpcId,
				},
				{
					Name:  "cidr-block",
					Value: aws.ToString(vpc.CidrBlock),
				},
				{
					Name:  "state",
					Value: string(vpc.State),
				},
				{
					Name:  "is-default",
					Value: fmt.Sprintf("%v", vpc.IsDefault),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, vpcId),
		},
	}

	return VpcEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildSubnetEvidenceContext builds evidence context for a Subnet
func BuildSubnetEvidenceContext(subnet types.Subnet, region string) SubnetEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeSubnet)
	subnetId := aws.ToString(subnet.SubnetId)
	vpcId := aws.ToString(subnet.VpcId)

	labels := map[string]string{
		"provider":  "aws",
		"type":      string(ResourceTypeSubnet),
		"subnet-id": subnetId,
		"vpc-id":    vpcId,
		"cidr":      aws.ToString(subnet.CidrBlock),
		"az":        aws.ToString(subnet.AvailabilityZone),
		"region":    region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, subnetId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, subnetId),
			Props: []*proto.Property{
				{
					Name:  "subnet-id",
					Value: subnetId,
				},
				{
					Name:  "vpc-id",
					Value: vpcId,
				},
				{
					Name:  "cidr-block",
					Value: aws.ToString(subnet.CidrBlock),
				},
				{
					Name:  "availability-zone",
					Value: aws.ToString(subnet.AvailabilityZone),
				},
				{
					Name:  "state",
					Value: string(subnet.State),
				},
				{
					Name:  "map-public-ip-on-launch",
					Value: fmt.Sprintf("%v", subnet.MapPublicIpOnLaunch),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, subnetId),
		},
	}

	return SubnetEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildSecurityGroupEvidenceContext builds evidence context for a Security Group
func BuildSecurityGroupEvidenceContext(group types.SecurityGroup, region string) SecurityGroupEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeSecurityGroup)
	groupId := aws.ToString(group.GroupId)
	vpcId := aws.ToString(group.VpcId)

	labels := map[string]string{
		"provider": "aws",
		"type":     string(ResourceTypeSecurityGroup),
		"group-id": groupId,
		"_vpc-id":  vpcId,
		"region":   region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, groupId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, groupId),
			Props: []*proto.Property{
				{
					Name:  "group-id",
					Value: groupId,
				},
				{
					Name:  "group-name",
					Value: aws.ToString(group.GroupName),
				},
				{
					Name:  "vpc-id",
					Value: vpcId,
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, groupId),
		},
	}

	return SecurityGroupEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildNetworkAclEvidenceContext builds evidence context for a Network ACL
func BuildNetworkAclEvidenceContext(acl types.NetworkAcl, region string) NetworkAclEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeNetworkAcl)
	aclId := aws.ToString(acl.NetworkAclId)
	vpcId := aws.ToString(acl.VpcId)

	labels := map[string]string{
		"provider":   "aws",
		"type":       string(ResourceTypeNetworkAcl),
		"acl-id":     aclId,
		"vpc-id":     vpcId,
		"is-default": fmt.Sprintf("%v", acl.IsDefault),
		"region":     region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, aclId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, aclId),
			Props: []*proto.Property{
				{
					Name:  "acl-id",
					Value: aclId,
				},
				{
					Name:  "vpc-id",
					Value: vpcId,
				},
				{
					Name:  "is-default",
					Value: fmt.Sprintf("%v", acl.IsDefault),
				},
				{
					Name:  "owner-id",
					Value: aws.ToString(acl.OwnerId),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, aclId),
		},
	}

	return NetworkAclEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildRouteTableEvidenceContext builds evidence context for a Route Table
func BuildRouteTableEvidenceContext(routeTable types.RouteTable, region string) RouteTableEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeRouteTable)
	rtId := aws.ToString(routeTable.RouteTableId)
	vpcId := aws.ToString(routeTable.VpcId)

	labels := map[string]string{
		"provider":       "aws",
		"type":           string(ResourceTypeRouteTable),
		"route-table-id": rtId,
		"vpc-id":         vpcId,
		"region":         region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, rtId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, rtId),
			Props: []*proto.Property{
				{
					Name:  "route-table-id",
					Value: rtId,
				},
				{
					Name:  "vpc-id",
					Value: vpcId,
				},
				{
					Name:  "owner-id",
					Value: aws.ToString(routeTable.OwnerId),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, rtId),
		},
	}

	return RouteTableEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildInternetGatewayEvidenceContext builds evidence context for an Internet Gateway
func BuildInternetGatewayEvidenceContext(igw types.InternetGateway, region string) InternetGatewayEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeInternetGateway)
	igwId := aws.ToString(igw.InternetGatewayId)

	// Get VPC ID if attached
	var vpcId string
	if len(igw.Attachments) > 0 {
		vpcId = aws.ToString(igw.Attachments[0].VpcId)
	}

	labels := map[string]string{
		"provider": "aws",
		"type":     string(ResourceTypeInternetGateway),
		"igw-id":   igwId,
		"vpc-id":   vpcId,
		"region":   region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, igwId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, igwId),
			Props: []*proto.Property{
				{
					Name:  "igw-id",
					Value: igwId,
				},
				{
					Name:  "vpc-id",
					Value: vpcId,
				},
				{
					Name:  "owner-id",
					Value: aws.ToString(igw.OwnerId),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, igwId),
		},
	}

	return InternetGatewayEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildVpcEndpointEvidenceContext builds evidence context for a VPC Endpoint
func BuildVpcEndpointEvidenceContext(endpoint types.VpcEndpoint, region string) VpcEndpointEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeVpcEndpoint)
	endpointId := aws.ToString(endpoint.VpcEndpointId)
	vpcId := aws.ToString(endpoint.VpcId)

	labels := map[string]string{
		"provider":     "aws",
		"type":         string(ResourceTypeVpcEndpoint),
		"endpoint-id":  endpointId,
		"vpc-id":       vpcId,
		"service-name": aws.ToString(endpoint.ServiceName),
		"state":        string(endpoint.State),
		"region":       region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, endpointId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, endpointId),
			Props: []*proto.Property{
				{
					Name:  "endpoint-id",
					Value: endpointId,
				},
				{
					Name:  "vpc-id",
					Value: vpcId,
				},
				{
					Name:  "service-name",
					Value: aws.ToString(endpoint.ServiceName),
				},
				{
					Name:  "state",
					Value: string(endpoint.State),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, endpointId),
		},
	}

	return VpcEndpointEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildFlowLogEvidenceContext builds evidence context for a Flow Log
func BuildFlowLogEvidenceContext(flowLog types.FlowLog, region string) FlowLogEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeFlowLog)
	flowLogId := aws.ToString(flowLog.FlowLogId)

	labels := map[string]string{
		"provider":        "aws",
		"type":            string(ResourceTypeFlowLog),
		"flow-log-id":     flowLogId,
		"resource-id":     aws.ToString(flowLog.ResourceId),
		"traffic-type":    string(flowLog.TrafficType),
		"flow-log-status": aws.ToString(flowLog.FlowLogStatus),
		"region":          region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, flowLogId),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, flowLogId),
			Props: []*proto.Property{
				{
					Name:  "flow-log-id",
					Value: flowLogId,
				},
				{
					Name:  "resource-id",
					Value: aws.ToString(flowLog.ResourceId),
				},
				{
					Name:  "traffic-type",
					Value: string(flowLog.TrafficType),
				},
				{
					Name:  "flow-log-status",
					Value: aws.ToString(flowLog.FlowLogStatus),
				},
				{
					Name:  "log-group-name",
					Value: aws.ToString(flowLog.LogGroupName),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, flowLogId),
		},
	}

	return FlowLogEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}

// BuildLogGroupEvidenceContext builds evidence context for a Log Group
func BuildLogGroupEvidenceContext(logGroup cloudwatchlogstypes.LogGroup, region string) LogGroupEvidenceContext {
	metadata := GetResourceMetadata(ResourceTypeLogGroup)
	logGroupName := aws.ToString(logGroup.LogGroupName)

	labels := map[string]string{
		"provider":       "aws",
		"type":           string(ResourceTypeLogGroup),
		"log-group-name": logGroupName,
		"region":         region,
	}

	components := []*proto.Component{
		{
			Identifier:  metadata.ComponentID,
			Type:        metadata.ComponentType,
			Title:       metadata.ComponentTitle,
			Description: metadata.ComponentDesc,
			Purpose:     metadata.ComponentPurpose,
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, logGroupName),
			Type:       metadata.InventoryType,
			Title:      fmt.Sprintf("%s [%s]", metadata.ComponentTitle, logGroupName),
			Props: []*proto.Property{
				{
					Name:  "log-group-name",
					Value: logGroupName,
				},
				{
					Name:  "retention-in-days",
					Value: fmt.Sprintf("%d", aws.ToInt32(logGroup.RetentionInDays)),
				},
				{
					Name:  "stored-bytes",
					Value: fmt.Sprintf("%d", aws.ToInt64(logGroup.StoredBytes)),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: metadata.ComponentID,
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: metadata.ComponentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("%s/%s", metadata.LabelPrefix, logGroupName),
		},
	}

	return LogGroupEvidenceContext{
		Labels:     labels,
		Components: components,
		Inventory:  inventory,
		Subjects:   subjects,
	}
}
