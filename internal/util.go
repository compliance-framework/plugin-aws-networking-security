package internal

import (
	"os"
	"strings"
)

func MergeMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, imap := range maps {
		for k, v := range imap {
			result[k] = v
		}
	}
	return result
}

func StringAddressed(str string) *string {
	return &str
}

// ResolveRegions resolves the list of AWS regions from config or environment
// Priority: config["regions"] > config["region"] > AWS_REGION env var
func ResolveRegions(config map[string]string) []string {
	// Check for comma-separated regions list
	if regionsStr, ok := config["regions"]; ok && regionsStr != "" {
		regionParts := strings.Split(regionsStr, ",")
		regions := make([]string, 0, len(regionParts))
		seen := make(map[string]bool)
		for _, r := range regionParts {
			r = strings.TrimSpace(r)
			if r != "" && !seen[r] {
				seen[r] = true
				regions = append(regions, r)
			}
		}
		if len(regions) > 0 {
			return regions
		}
	}

	// Check for single region
	if regionStr, ok := config["region"]; ok && regionStr != "" {
		return []string{strings.TrimSpace(regionStr)}
	}

	// Fall back to environment variable
	if regionEnv := os.Getenv("AWS_REGION"); regionEnv != "" {
		return []string{regionEnv}
	}

	// Default to us-east-1 if nothing is configured
	return []string{"us-east-1"}
}
