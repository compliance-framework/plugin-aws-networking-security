package internal

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/compliance-framework/agent/runner/proto"
)

func TestEvidenceLabelKeysUseUnderscoreNotation(t *testing.T) {
	contexts := []struct {
		name   string
		labels map[string]string
	}{
		{
			name: "vpc",
			labels: BuildVpcEvidenceContext(types.Vpc{
				VpcId:     aws.String("vpc-123"),
				CidrBlock: aws.String("10.0.0.0/16"),
			}, "eu-west-2").Labels,
		},
		{
			name: "subnet",
			labels: BuildSubnetEvidenceContext(types.Subnet{
				SubnetId:         aws.String("subnet-123"),
				VpcId:            aws.String("vpc-123"),
				CidrBlock:        aws.String("10.0.1.0/24"),
				AvailabilityZone: aws.String("eu-west-2a"),
			}, "eu-west-2").Labels,
		},
		{
			name: "security-group",
			labels: BuildSecurityGroupEvidenceContext(types.SecurityGroup{
				GroupId: aws.String("sg-123"),
				VpcId:   aws.String("vpc-123"),
			}, "eu-west-2").Labels,
		},
		{
			name: "network-acl",
			labels: BuildNetworkAclEvidenceContext(types.NetworkAcl{
				NetworkAclId: aws.String("acl-123"),
				VpcId:        aws.String("vpc-123"),
			}, "eu-west-2").Labels,
		},
		{
			name: "route-table",
			labels: BuildRouteTableEvidenceContext(types.RouteTable{
				RouteTableId: aws.String("rtb-123"),
				VpcId:        aws.String("vpc-123"),
			}, "eu-west-2").Labels,
		},
		{
			name: "internet-gateway",
			labels: BuildInternetGatewayEvidenceContext(types.InternetGateway{
				InternetGatewayId: aws.String("igw-123"),
				Attachments: []types.InternetGatewayAttachment{
					{VpcId: aws.String("vpc-123")},
				},
			}, "eu-west-2").Labels,
		},
		{
			name: "vpc-endpoint",
			labels: BuildVpcEndpointEvidenceContext(types.VpcEndpoint{
				VpcEndpointId: aws.String("vpce-123"),
				VpcId:         aws.String("vpc-123"),
				ServiceName:   aws.String("com.amazonaws.eu-west-2.s3"),
			}, "eu-west-2").Labels,
		},
		{
			name: "flow-log",
			labels: BuildFlowLogEvidenceContext(types.FlowLog{
				FlowLogId:     aws.String("fl-123"),
				ResourceId:    aws.String("vpc-123"),
				TrafficType:   types.TrafficTypeAll,
				FlowLogStatus: aws.String("ACTIVE"),
			}, "eu-west-2").Labels,
		},
		{
			name: "log-group",
			labels: BuildLogGroupEvidenceContext(cloudwatchlogstypes.LogGroup{
				LogGroupName: aws.String("/aws/vpc/flowlogs"),
			}, "eu-west-2").Labels,
		},
	}

	for _, context := range contexts {
		for key := range context.labels {
			if strings.Contains(key, "-") {
				t.Fatalf("%s evidence label key %q must use underscore notation", context.name, key)
			}
		}
	}
}

func TestEvidenceBoolPointerPropertiesRenderAsBoolStrings(t *testing.T) {
	vpcCtx := BuildVpcEvidenceContext(types.Vpc{
		VpcId:     aws.String("vpc-123"),
		IsDefault: aws.Bool(true),
	}, "eu-west-2")
	assertInventoryProperty(t, vpcCtx.Inventory[0].Props, "is-default", "true")

	subnetCtx := BuildSubnetEvidenceContext(types.Subnet{
		SubnetId:            aws.String("subnet-123"),
		VpcId:               aws.String("vpc-123"),
		MapPublicIpOnLaunch: aws.Bool(false),
	}, "eu-west-2")
	assertInventoryProperty(t, subnetCtx.Inventory[0].Props, "map-public-ip-on-launch", "false")

	aclCtx := BuildNetworkAclEvidenceContext(types.NetworkAcl{
		NetworkAclId: aws.String("acl-123"),
		VpcId:        aws.String("vpc-123"),
		IsDefault:    aws.Bool(true),
	}, "eu-west-2")
	assertInventoryProperty(t, aclCtx.Inventory[0].Props, "is-default", "true")
}

func assertInventoryProperty(t *testing.T, props []*proto.Property, name string, expected string) {
	t.Helper()

	for _, prop := range props {
		if prop.Name == name {
			if prop.Value != expected {
				t.Fatalf("property %s = %q, want %q", name, prop.Value, expected)
			}
			return
		}
	}

	t.Fatalf("property %s not found", name)
}
