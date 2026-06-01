package internal

// ResourceType represents the type of AWS VPC-related resource
type ResourceType string

const (
	ResourceTypeVPC              ResourceType = "vpc"
	ResourceTypeSubnet           ResourceType = "subnet"
	ResourceTypeSecurityGroup    ResourceType = "security-group"
	ResourceTypeNetworkAcl       ResourceType = "nacl"
	ResourceTypeRouteTable       ResourceType = "route-table"
	ResourceTypeFlowLog          ResourceType = "flow-log"
	ResourceTypeVpcEndpoint      ResourceType = "vpc-endpoint"
	ResourceTypeInternetGateway  ResourceType = "internet-gateway"
	ResourceTypeTransitGateway   ResourceType = "transit-gateway"
	ResourceTypeLogGroup         ResourceType = "log-group"
)

// ResourceMetadata contains metadata for building evidence context for a resource type
type ResourceMetadata struct {
	Type              ResourceType
	ComponentID       string
	ComponentTitle    string
	ComponentType     string
	ComponentDesc     string
	ComponentPurpose  string
	InventoryType     string
	LabelPrefix       string
}

// GetResourceMetadata returns metadata for a given resource type
func GetResourceMetadata(resourceType ResourceType) ResourceMetadata {
	switch resourceType {
	case ResourceTypeVPC:
		return ResourceMetadata{
			Type:              ResourceTypeVPC,
			ComponentID:       "common-components/amazon-vpc",
			ComponentTitle:    "Amazon VPC",
			ComponentType:     "service",
			ComponentDesc:     "Amazon Virtual Private Cloud (VPC) provides a logically isolated section of the AWS Cloud where you can launch AWS resources in a virtual network that you define. VPCs enable network segmentation, control over IP address ranges, subnet configuration, and network gateways.",
			ComponentPurpose:  "To provide network isolation and segmentation for AWS resources, enabling secure network architecture design with control over IP addressing, subnets, routing, and network gateways.",
			InventoryType:     "network",
			LabelPrefix:       "aws-vpc",
		}
	case ResourceTypeSubnet:
		return ResourceMetadata{
			Type:              ResourceTypeSubnet,
			ComponentID:       "common-components/amazon-subnet",
			ComponentTitle:    "Amazon Subnet",
			ComponentType:     "service",
			ComponentDesc:     "Amazon VPC Subnets are segments of a VPC's IP address range where you can launch AWS resources. Subnets can be public or private, with public subnets having a route to an internet gateway and private subnets lacking direct internet access.",
			ComponentPurpose:  "To provide network segmentation within a VPC, allowing isolation of resources and control over network accessibility through public/private subnet design.",
			InventoryType:     "network-segment",
			LabelPrefix:       "aws-subnet",
		}
	case ResourceTypeSecurityGroup:
		return ResourceMetadata{
			Type:              ResourceTypeSecurityGroup,
			ComponentID:       "common-components/amazon-security-group",
			ComponentTitle:    "Amazon Security Groups",
			ComponentType:     "service",
			ComponentDesc:     "Amazon Security Groups act as virtual firewalls for AWS resources such as EC2 instances and RDS databases. They control inbound and outbound traffic at the instance level using rule-based configurations tied to ports, protocols, and CIDR ranges. Security Groups are stateful and can reference other groups to enforce dynamic trust boundaries within a VPC.",
			ComponentPurpose:  "To enforce network segmentation and access control policies at the resource level, providing a configurable and auditable security boundary for cloud-based assets in support of least privilege and Zero Trust architectures.",
			InventoryType:     "firewall",
			LabelPrefix:       "aws-security-group",
		}
	case ResourceTypeNetworkAcl:
		return ResourceMetadata{
			Type:              ResourceTypeNetworkAcl,
			ComponentID:       "common-components/amazon-network-acl",
			ComponentTitle:    "Amazon Network ACL",
			ComponentType:     "service",
			ComponentDesc:     "Amazon Network Access Control Lists (NACLs) act as stateless firewalls for controlling inbound and outbound traffic at the subnet level. NACLs use numbered rules to allow or deny traffic based on protocol, port, and source/destination CIDR ranges.",
			ComponentPurpose:  "To provide subnet-level network traffic control as an additional layer of defense alongside security groups, enabling network segmentation and access control at the subnet boundary.",
			InventoryType:     "network-control",
			LabelPrefix:       "aws-nacl",
		}
	case ResourceTypeRouteTable:
		return ResourceMetadata{
			Type:              ResourceTypeRouteTable,
			ComponentID:       "common-components/amazon-route-table",
			ComponentTitle:    "Amazon Route Table",
			ComponentType:     "service",
			ComponentDesc:     "Amazon Route Tables contain a set of rules (routes) that determine where network traffic is directed within a VPC. Each subnet in a VPC must be associated with a route table, which controls the routing for that subnet.",
			ComponentPurpose:  "To control network traffic routing within a VPC, enabling communication between subnets, to internet gateways, to VPC endpoints, and to other network resources.",
			InventoryType:     "network-routing",
			LabelPrefix:       "aws-route-table",
		}
	case ResourceTypeFlowLog:
		return ResourceMetadata{
			Type:              ResourceTypeFlowLog,
			ComponentID:       "common-components/amazon-flow-log",
			ComponentTitle:    "Amazon VPC Flow Logs",
			ComponentType:     "service",
			ComponentDesc:     "Amazon VPC Flow Logs capture information about the IP traffic going to and from network interfaces in a VPC. Flow log data can be published to CloudWatch Logs or S3 for analysis, auditing, and network monitoring.",
			ComponentPurpose:  "To provide visibility into network traffic patterns for security monitoring, compliance auditing, and network troubleshooting, supporting detection of unauthorized access and network anomalies.",
			InventoryType:     "network-monitoring",
			LabelPrefix:       "aws-flow-log",
		}
	case ResourceTypeVpcEndpoint:
		return ResourceMetadata{
			Type:              ResourceTypeVpcEndpoint,
			ComponentID:       "common-components/amazon-vpc-endpoint",
			ComponentTitle:    "Amazon VPC Endpoint",
			ComponentType:     "service",
			ComponentDesc:     "Amazon VPC Endpoints enable private connections between your VPC and supported AWS services without requiring an internet gateway, NAT device, VPN connection, or AWS Direct Connect connection. Endpoints are horizontally scalable and highly available.",
			ComponentPurpose:  "To enable private communication between VPC resources and AWS services, keeping traffic within the AWS network for improved security, reduced latency, and lower data transfer costs.",
			InventoryType:     "network-endpoint",
			LabelPrefix:       "aws-vpc-endpoint",
		}
	case ResourceTypeInternetGateway:
		return ResourceMetadata{
			Type:              ResourceTypeInternetGateway,
			ComponentID:       "common-components/amazon-internet-gateway",
			ComponentTitle:    "Amazon Internet Gateway",
			ComponentType:     "service",
			ComponentDesc:     "Amazon Internet Gateways enable communication between resources in your VPC and the internet. An internet gateway supports IPv4 and IPv6 traffic and does not cause availability risks or bandwidth constraints.",
			ComponentPurpose:  "To provide internet access for resources in public subnets, enabling outbound internet traffic and inbound access from the internet to publicly accessible resources.",
			InventoryType:     "network-gateway",
			LabelPrefix:       "aws-internet-gateway",
		}
	case ResourceTypeTransitGateway:
		return ResourceMetadata{
			Type:              ResourceTypeTransitGateway,
			ComponentID:       "common-components/amazon-transit-gateway",
			ComponentTitle:    "Amazon Transit Gateway",
			ComponentType:     "service",
			ComponentDesc:     "Amazon Transit Gateway acts as a regional cloud router that simplifies network topology by connecting VPCs and on-premises networks through a central hub. Transit Gateway scales with your network growth and provides inter-Region connectivity.",
			ComponentPurpose:  "To provide centralized network connectivity across multiple VPCs and on-premises networks, simplifying network architecture and reducing operational complexity for large-scale cloud deployments.",
			InventoryType:     "network-gateway",
			LabelPrefix:       "aws-transit-gateway",
		}
	case ResourceTypeLogGroup:
		return ResourceMetadata{
			Type:              ResourceTypeLogGroup,
			ComponentID:       "common-components/amazon-log-group",
			ComponentTitle:    "Amazon CloudWatch Logs",
			ComponentType:     "service",
			ComponentDesc:     "Amazon CloudWatch Logs enables you to centralize logs from all your systems, applications, and AWS services. Log groups organize log streams and can be used for monitoring, troubleshooting, and auditing.",
			ComponentPurpose:  "To provide centralized log management and analysis capabilities, enabling operational monitoring, security auditing, and compliance verification across AWS resources.",
			InventoryType:     "logging",
			LabelPrefix:       "aws-log-group",
		}
	default:
		return ResourceMetadata{}
	}
}
