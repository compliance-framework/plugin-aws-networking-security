package main

import "testing"

func TestBuildRequiredDatasetsForAclPolicies(t *testing.T) {
	required := buildRequiredDatasets(map[string][]string{
		"acl": {"/tmp/policies"},
	})

	for _, dataset := range []string{"vpcs", "subnets", "network_acls", "route_tables", "internet_gateways", "flow_logs", "log_groups", "network_interfaces"} {
		if !required[dataset] {
			t.Fatalf("expected %s to be required for acl policies", dataset)
		}
	}
}

func TestBuildRequiredDatasetsForSubnetPolicies(t *testing.T) {
	required := buildRequiredDatasets(map[string][]string{
		"subnet": {"/tmp/policies"},
	})

	for _, dataset := range []string{"vpcs", "subnets", "route_tables", "network_acls", "internet_gateways", "flow_logs", "log_groups"} {
		if !required[dataset] {
			t.Fatalf("expected %s to be required for subnet policies", dataset)
		}
	}
}

func TestBuildRequiredDatasetsForRouteTablePolicies(t *testing.T) {
	required := buildRequiredDatasets(map[string][]string{
		"rt": {"/tmp/policies"},
	})

	for _, dataset := range []string{"vpcs", "subnets", "route_tables", "internet_gateways", "vpc_endpoints", "transit_gateway_attachments"} {
		if !required[dataset] {
			t.Fatalf("expected %s to be required for route table policies", dataset)
		}
	}
}
