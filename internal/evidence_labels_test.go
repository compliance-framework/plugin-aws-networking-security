package internal

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
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
