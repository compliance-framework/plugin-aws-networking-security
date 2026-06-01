package main

import "github.com/compliance-framework/agent/runner/proto"

func buildSubjectTemplates() []*proto.SubjectTemplate {
	return []*proto.SubjectTemplate{
		{
			Name:                "aws-vpc",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       `AWS VPC {{ .vpc_id }} in {{ .region }}`,
			DescriptionTemplate: `Amazon VPC {{ .vpc_id }} with CIDR {{ .cidr }} in AWS region {{ .region }}.`,
			PurposeTemplate:     "Represents an AWS VPC evaluated for networking compliance posture.",
			IdentityLabelKeys:   []string{"provider", "region", "vpc_id"},
			SelectorLabels:      selectorLabelsForType("vpc"),
			LabelSchema: labelSchema(
				label("provider", "Cloud provider for the evaluated resource"),
				label("type", "VPC plugin resource type"),
				label("vpc_id", "AWS VPC identifier"),
				label("cidr", "Primary IPv4 CIDR block associated with the VPC"),
				label("region", "AWS region containing the VPC"),
			),
		},
		{
			Name:                "aws-vpc-subnet",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       `AWS subnet {{ .subnet_id }} in {{ .region }}`,
			DescriptionTemplate: `Amazon VPC subnet {{ .subnet_id }} in VPC {{ .vpc_id }} with CIDR {{ .cidr }}.`,
			PurposeTemplate:     "Represents an AWS VPC subnet evaluated for network segmentation and routing posture.",
			IdentityLabelKeys:   []string{"provider", "region", "subnet_id"},
			SelectorLabels:      selectorLabelsForType("subnet"),
			LabelSchema: labelSchema(
				label("provider", "Cloud provider for the evaluated resource"),
				label("type", "VPC plugin resource type"),
				label("subnet_id", "AWS subnet identifier"),
				label("vpc_id", "AWS VPC identifier containing the subnet"),
				label("cidr", "IPv4 CIDR block associated with the subnet"),
				label("az", "AWS availability zone containing the subnet"),
				label("region", "AWS region containing the subnet"),
			),
		},
		{
			Name:                "aws-vpc-security-group",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       `AWS security group {{ .group_id }} in {{ .region }}`,
			DescriptionTemplate: `Amazon VPC security group {{ .group_id }} in VPC {{ .vpc_id }}.`,
			PurposeTemplate:     "Represents an AWS security group evaluated for network access-control posture.",
			IdentityLabelKeys:   []string{"provider", "region", "group_id"},
			SelectorLabels:      selectorLabelsForType("security-group"),
			LabelSchema: labelSchema(
				label("provider", "Cloud provider for the evaluated resource"),
				label("type", "VPC plugin resource type"),
				label("group_id", "AWS security group identifier"),
				label("vpc_id", "AWS VPC identifier containing the security group"),
				label("region", "AWS region containing the security group"),
			),
		},
		{
			Name:                "aws-vpc-network-acl",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       `AWS network ACL {{ .acl_id }} in {{ .region }}`,
			DescriptionTemplate: `Amazon VPC network ACL {{ .acl_id }} in VPC {{ .vpc_id }}.`,
			PurposeTemplate:     "Represents an AWS network ACL evaluated for subnet-level network control posture.",
			IdentityLabelKeys:   []string{"provider", "region", "acl_id"},
			SelectorLabels:      selectorLabelsForType("nacl"),
			LabelSchema: labelSchema(
				label("provider", "Cloud provider for the evaluated resource"),
				label("type", "VPC plugin resource type"),
				label("acl_id", "AWS network ACL identifier"),
				label("vpc_id", "AWS VPC identifier containing the network ACL"),
				label("region", "AWS region containing the network ACL"),
			),
		},
		{
			Name:                "aws-vpc-route-table",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       `AWS route table {{ .route_table_id }} in {{ .region }}`,
			DescriptionTemplate: `Amazon VPC route table {{ .route_table_id }} in VPC {{ .vpc_id }}.`,
			PurposeTemplate:     "Represents an AWS route table evaluated for network routing and reachability posture.",
			IdentityLabelKeys:   []string{"provider", "region", "route_table_id"},
			SelectorLabels:      selectorLabelsForType("route-table"),
			LabelSchema: labelSchema(
				label("provider", "Cloud provider for the evaluated resource"),
				label("type", "VPC plugin resource type"),
				label("route_table_id", "AWS route table identifier"),
				label("vpc_id", "AWS VPC identifier containing the route table"),
				label("region", "AWS region containing the route table"),
			),
		},
	}
}

func selectorLabelsForType(resourceType string) []*proto.SubjectLabelSelector {
	return []*proto.SubjectLabelSelector{
		{
			Key:   "type",
			Value: resourceType,
		},
	}
}

func label(key string, description string) *proto.SubjectLabelSchema {
	return &proto.SubjectLabelSchema{
		Key:         key,
		Description: description,
	}
}

func labelSchema(labels ...*proto.SubjectLabelSchema) []*proto.SubjectLabelSchema {
	return labels
}
