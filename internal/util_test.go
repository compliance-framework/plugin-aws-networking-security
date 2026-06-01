package internal

import "testing"

func TestResolveRegionsIgnoresWhitespaceOnlyRegionConfig(t *testing.T) {
	t.Setenv("AWS_REGION", "eu-west-2")

	regions := ResolveRegions(map[string]string{"region": "   \t  "})
	if len(regions) != 1 || regions[0] != "eu-west-2" {
		t.Fatalf("ResolveRegions() = %v, want [eu-west-2]", regions)
	}
}
