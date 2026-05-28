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
