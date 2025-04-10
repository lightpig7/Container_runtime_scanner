package audit

import (
	"Container_runtime_scanner/internal/docker"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// CVE structure matching your JSON data
type CVE struct {
	CVEId            string   `json:"cveId"`
	Technology       string   `json:"technology"`
	AffectedVersions []string `json:"affectedVersions"`
	CVSSScore        float64  `json:"cvssScore"`
	Severity         string   `json:"severity"`
}

// MatchResult stores matching results
type MatchResult struct {
	Component   string
	Version     string
	MatchedCVEs []CVE
}

// VersionMatch checks if installed components are vulnerable
func VersionMatch(logger *log.Logger) []MatchResult {
	// Get Docker information
	versionInfo := docker.GetInfo()

	// Store all matching results
	var results []MatchResult

	// Print version information first
	logger.Printf("Docker version: %s\n", versionInfo.DockerVersion)
	logger.Printf("API version: %s\n", versionInfo.APIVersion)
	logger.Printf("Go version: %s\n", versionInfo.GoVersion)
	logger.Printf("Git commit: %s\n", versionInfo.GitVersion)
	logger.Printf("OS: %s\n", versionInfo.OSVersion)
	logger.Printf("runc version: %s\n", versionInfo.RuncVersion)
	logger.Printf("Kernel version: %s\n", versionInfo.KernelVersion)
	logger.Printf("containerd version: %s\n", versionInfo.ContainerVersion)

	// Check Docker version
	dockerMatches := checkComponentVersion("docker", versionInfo.DockerVersion)
	// Remove duplicates from matches
	dockerMatches = removeDuplicateCVEs(dockerMatches)
	if len(dockerMatches) > 0 {
		results = append(results, MatchResult{
			Component:   "docker",
			Version:     versionInfo.DockerVersion,
			MatchedCVEs: dockerMatches,
		})
	}

	// Check containerd version
	if versionInfo.ContainerVersion != "" {
		containerdMatches := checkComponentVersion("containerd", versionInfo.ContainerVersion)
		// Remove duplicates from matches
		containerdMatches = removeDuplicateCVEs(containerdMatches)
		if len(containerdMatches) > 0 {
			results = append(results, MatchResult{
				Component:   "containerd",
				Version:     versionInfo.ContainerVersion,
				MatchedCVEs: containerdMatches,
			})
		}
	}

	// Check runc version
	if versionInfo.RuncVersion != "" {
		runcMatches := checkComponentVersion("runc", versionInfo.RuncVersion)
		// Remove duplicates from matches
		runcMatches = removeDuplicateCVEs(runcMatches)
		if len(runcMatches) > 0 {
			results = append(results, MatchResult{
				Component:   "runc",
				Version:     versionInfo.RuncVersion,
				MatchedCVEs: runcMatches,
			})
		}
	}

	// Print match results summary
	logger.Println("\nVulnerability Matches:")
	for _, result := range results {
		logger.Printf("%s %s has %d matching CVEs\n",
			result.Component, result.Version, len(result.MatchedCVEs))

		for _, cve := range result.MatchedCVEs {
			logger.Printf("  - %s (CVSS: %.1f, %s)\n",
				cve.CVEId, cve.CVSSScore, cve.Severity)
		}
	}

	return results
}

// Check if a specific component version has vulnerabilities
func checkComponentVersion(component, version string) []CVE {
	// Clean version number
	version = cleanVersion(version)

	// Build file path
	filename := fmt.Sprintf("internal/data/nvd-data/vulnerabilities/%s-vulnerabilities.json", component)

	// Try using the combined file if component-specific file doesn't exist
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		filename = "internal/data/nvd-data/vulnerabilities/all-container-vulnerabilities.json"
	}

	// Read file
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Warning: Cannot open file %s: %v", filename, err)
		return nil
	}

	var cves []CVE
	err = json.Unmarshal(content, &cves)
	if err != nil {
		log.Printf("Warning: JSON parsing failed: %v", err)
		return nil
	}

	// Filter CVEs for current component
	var componentCVEs []CVE
	for _, cve := range cves {
		if strings.ToLower(cve.Technology) == strings.ToLower(component) {
			// Skip CVEs with empty severity or CVSS score of 0 (likely incomplete data)
			if cve.Severity == "" || cve.CVSSScore == 0 {
				continue
			}
			componentCVEs = append(componentCVEs, cve)
		}
	}

	// Match version number
	var matches []CVE
	for _, cve := range componentCVEs {
		if isVersionAffected(version, cve) {
			matches = append(matches, cve)
		}
	}

	return matches
}

// removeDuplicateCVEs removes duplicate CVEs from the list
func removeDuplicateCVEs(cves []CVE) []CVE {
	if len(cves) == 0 {
		return cves
	}

	// Use a map to track unique CVE IDs
	seen := make(map[string]bool)
	var result []CVE

	for _, cve := range cves {
		if !seen[cve.CVEId] {
			seen[cve.CVEId] = true
			result = append(result, cve)
		}
	}

	return result
}

// isVersionAffected checks if the given version is affected by the CVE
func isVersionAffected(version string, cve CVE) bool {
	// Skip if no affected versions are listed
	if len(cve.AffectedVersions) == 0 {
		return false
	}

	cleanedVersion := cleanVersion(version)

	// Check each affected version
	for _, affectedVersion := range cve.AffectedVersions {
		// Handle special cases
		if affectedVersion == "-" || affectedVersion == "*" {
			// Be conservative, don't automatically match all versions
			continue
		}

		// Handle exact match
		cleanedAffectedVersion := cleanVersion(affectedVersion)
		if cleanedAffectedVersion == cleanedVersion {
			return true
		}

		// For Docker and other components, we need to be more specific with version matching
		// Only match if the version parts are exactly the same - don't match partial versions
		versionParts := strings.Split(cleanedVersion, ".")
		affectedParts := strings.Split(cleanedAffectedVersion, ".")

		// Skip if the affected version has more specific version parts than the installed version
		// For example, if installed is 24.0 and affected is 24.0.2, don't match
		if len(affectedParts) > len(versionParts) {
			continue
		}

		// Match only if affected version is a complete prefix of the installed version
		// For example, if installed is 24.0.2 and affected is 24.0, consider it a match
		// But if installed is 24.1.0 and affected is 24.0, don't match
		isPrefix := true
		for i := 0; i < len(affectedParts); i++ {
			if i >= len(versionParts) || versionParts[i] != affectedParts[i] {
				isPrefix = false
				break
			}
		}

		if isPrefix {
			// If we're matching based on prefix, ensure the version is actually vulnerable
			// For example, if the affected version is 1.2, it should match 1.2.0 but not 1.20.0
			if len(versionParts) > len(affectedParts) {
				// Only match if the next version part is a minor/patch version (e.g., 1.2 matches 1.2.3 but not 1.20)
				if len(versionParts) > len(affectedParts) && len(versionParts[len(affectedParts)]) > 1 {
					// If the next part is more than one digit, it's likely a different version
					// (e.g., 1.2 vs 1.20) so don't match
					continue
				}
			}
			return true
		}
	}

	return false
}

// compareVersions compares two version strings
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Clean version numbers
	v1 = cleanVersion(v1)
	v2 = cleanVersion(v2)

	// Split versions into parts
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// Compare each part
	maxLength := len(parts1)
	if len(parts2) > maxLength {
		maxLength = len(parts2)
	}

	// Ensure both version arrays have the same length, pad with zeros
	for i := len(parts1); i < maxLength; i++ {
		parts1 = append(parts1, "0")
	}
	for i := len(parts2); i < maxLength; i++ {
		parts2 = append(parts2, "0")
	}

	// Compare each part
	for i := 0; i < maxLength; i++ {
		num1, err1 := strconv.Atoi(parts1[i])
		num2, err2 := strconv.Atoi(parts2[i])

		// Handle parsing errors by defaulting to 0
		if err1 != nil {
			num1 = 0
		}
		if err2 != nil {
			num2 = 0
		}

		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}

	return 0 // Versions are identical
}

// cleanVersion removes prefixes and extracts semantic version
func cleanVersion(version string) string {
	// Remove prefixes like "v" or "version"
	version = regexp.MustCompile(`^[vV]`).ReplaceAllString(version, "")

	// Extract semantic version (x.y.z)
	re := regexp.MustCompile(`(\d+(?:\.\d+){0,2})`)
	matches := re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1]
	}

	return version
}
