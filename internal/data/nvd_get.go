package data

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// NVD feeds base URL
	nvdFeedsBaseURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"

	// Data storage directory
	dataDir = "./internal/data/nvd-data"

	// User agent
	userAgent = "Mozilla/5.0 NVD Data Fetcher"
)

// ExtractContainerVulnerabilities fetches and processes NVD data for container technologies
func ExtractContainerVulnerabilities() {
	// Create data directory
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	log.Println("Downloading NVD data for container-related vulnerabilities...")
	vulnerabilities := fetchContainerVulnerabilitiesFromNVD()

	// Save extracted vulnerability information
	saveVulnerabilityData(vulnerabilities)
}

// Fetch container vulnerabilities from NVD feeds
func fetchContainerVulnerabilitiesFromNVD() []ContainerVulnerability {
	// Get current year
	currentYear := time.Now().Year()

	// Store all extracted vulnerabilities
	var allVulnerabilities []ContainerVulnerability

	// Process last 5 years of CVE data
	for year := currentYear; year >= currentYear-5; year-- {
		yearStr := fmt.Sprintf("%d", year)
		feedURL := fmt.Sprintf(nvdFeedsBaseURL, yearStr)
		outputFile := filepath.Join(dataDir, fmt.Sprintf("nvdcve-%s.json", yearStr))
		gzOutputFile := outputFile + ".gz"

		log.Printf("Processing CVE data for year %d...\n", year)

		// Download gzip file if it doesn't exist
		if _, err := os.Stat(gzOutputFile); os.IsNotExist(err) {
			log.Printf("Downloading CVE data for year %d...\n", year)
			if err := downloadFile(feedURL, gzOutputFile); err != nil {
				log.Printf("Error downloading CVE data: %v", err)
				continue
			}
			log.Printf("Successfully downloaded CVE data for year %d\n", year)
		} else {
			log.Printf("File %s already exists, skipping download\n", gzOutputFile)
		}

		// Decompress gzip file
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			if err := decompressGzFile(gzOutputFile, outputFile); err != nil {
				log.Printf("Error decompressing file: %v", err)
				continue
			}
			log.Printf("Successfully decompressed CVE data for year %d\n", year)
		} else {
			log.Printf("File %s already exists, skipping decompression\n", outputFile)
		}

		// Read and parse JSON file
		cveData, err := parseCVEFile(outputFile)
		if err != nil {
			log.Printf("Error parsing CVE data: %v", err)
			continue
		}

		// Extract container vulnerabilities
		log.Printf("Extracting container vulnerabilities from %d data...\n", year)
		yearVulnerabilities := extractContainerVulnerabilities(cveData)
		allVulnerabilities = append(allVulnerabilities, yearVulnerabilities...)
		log.Printf("Extracted %d container vulnerabilities from %d data\n",
			len(yearVulnerabilities), year)

		// Clean up extracted JSON file to save space
		if err := os.Remove(outputFile); err != nil {
			log.Printf("Error removing file: %v", err)
		}
	}

	log.Printf("Total container vulnerabilities extracted: %d\n", len(allVulnerabilities))
	return allVulnerabilities
}

// Download a file from URL
func downloadFile(url, outputPath string) error {
	// Create HTTP client
	client := &http.Client{
		Timeout: 180 * time.Second,
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("User-Agent", userAgent)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	// Create output file
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	// Copy data
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save file: %v", err)
	}

	return nil
}

// Decompress gzip file
func decompressGzFile(gzFilePath, outputFilePath string) error {
	// Open gzip file
	gzFile, err := os.Open(gzFilePath)
	if err != nil {
		return fmt.Errorf("failed to open gzip file: %v", err)
	}
	defer gzFile.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()

	// Create output file
	outFile, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	// Copy decompressed data
	_, err = io.Copy(outFile, gzReader)
	if err != nil {
		return fmt.Errorf("decompression failed: %v", err)
	}

	return nil
}

// Parse CVE JSON file
func parseCVEFile(filePath string) (*CVE, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// Parse JSON
	var cveData CVE
	if err := json.Unmarshal(data, &cveData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return &cveData, nil
}

// Extract container vulnerabilities from CVE data
func extractContainerVulnerabilities(cveData *CVE) []ContainerVulnerability {
	var vulnerabilities []ContainerVulnerability

	// Process each CVE item
	for _, item := range cveData.CVEItems {
		cveID := item.CVE.CVEDataMeta.ID

		// Get description
		var description string
		for _, desc := range item.CVE.Description.DescriptionData {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		// Get CVSS score and severity
		var cvssScore float64
		var severity string
		if item.Impact.BaseMetricV3.CVSSV3.BaseScore > 0 {
			cvssScore = item.Impact.BaseMetricV3.CVSSV3.BaseScore
			severity = item.Impact.BaseMetricV3.CVSSV3.BaseSeverity
		} else if item.Impact.BaseMetricV2.CVSSV2.BaseScore > 0 {
			cvssScore = item.Impact.BaseMetricV2.CVSSV2.BaseScore
			severity = item.Impact.BaseMetricV2.Severity
		}

		// Check if description mentions container technologies
		descriptionVulns := extractVulnerabilitiesFromDescription(
			cveID, description, cvssScore, severity)
		vulnerabilities = append(vulnerabilities, descriptionVulns...)

		// Check CPE data
		cpeVulns := extractVulnerabilitiesFromCPE(
			cveID, item.Configurations.Nodes, description, cvssScore, severity)
		vulnerabilities = append(vulnerabilities, cpeVulns...)
	}

	return vulnerabilities
}

// Extract vulnerabilities from description text
func extractVulnerabilitiesFromDescription(
	cveID, description string, cvssScore float64, severity string) []ContainerVulnerability {

	var vulnerabilities []ContainerVulnerability

	// Check for each container technology
	for tech, aliases := range containerTechnologies {
		// Check if any alias is mentioned in the description
		mentioned := false
		for _, alias := range aliases {
			// Look for word boundaries around the technology name
			pattern := fmt.Sprintf(`(?i)\b%s\b`, regexp.QuoteMeta(alias))
			if regexp.MustCompile(pattern).MatchString(description) {
				mentioned = true
				break
			}
		}

		if mentioned {
			// Extract version information
			versions := extractVersionsFromDescription(description, tech)

			if len(versions) > 0 {
				vulnerability := ContainerVulnerability{
					CVEId:            cveID,
					Technology:       tech,
					AffectedVersions: versions,
					CVSSScore:        cvssScore,
					Severity:         severity,
				}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}

	return vulnerabilities
}

// Extract versions from description based on technology
func extractVersionsFromDescription(description, technology string) []string {
	var versions []string
	versionSet := make(map[string]bool) // To avoid duplicates

	// Technology-specific version patterns
	var patterns []string
	switch technology {
	case "docker":
		patterns = []string{
			`(?i)Docker[\s]+(Engine[\s]+)?v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`,
			`(?i)Docker[\s]+version[\s]+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`,
		}
	case "kubernetes":
		patterns = []string{
			`(?i)Kubernetes[\s]+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`,
			`(?i)k8s[\s]+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`,
		}
	default:
		patterns = []string{
			fmt.Sprintf(`(?i)%s[\s]+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`, technology),
			fmt.Sprintf(`(?i)%s[\s]+version[\s]+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`, technology),
		}
	}

	// Extract explicit versions
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(description, -1)
		for _, match := range matches {
			if len(match) > 1 && isValidVersion(match[1]) {
				versionSet[match[1]] = true
			}
		}
	}

	// Extract version ranges
	rangePatterns := []string{
		`(?i)versions?\s+(?:before|prior to|earlier than)\s+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`,
		`(?i)versions?\s+(?:up to|through)\s+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`,
		`(?i)versions?\s+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)\s+(?:and below|and earlier|or earlier|or below)`,
		`(?i)affects\s+versions?\s+(?:before|prior to)\s+v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)`,
	}

	for _, pattern := range rangePatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(description, -1)
		for _, match := range matches {
			if len(match) > 1 && isValidVersion(match[1]) {
				versionSet[match[1]] = true
			}
		}
	}

	// Convert set to slice
	for version := range versionSet {
		versions = append(versions, version)
	}

	return versions
}

// Check if a string is a valid version
func isValidVersion(version string) bool {
	// Basic version validation
	return regexp.MustCompile(`^\d+\.\d+(\.\d+)?`).MatchString(version)
}

// Extract vulnerabilities from CPE data
func extractVulnerabilitiesFromCPE(
	cveID string, nodes []struct {
		Operator string `json:"operator"`
		CpeMatch []struct {
			Vulnerable bool   `json:"vulnerable"`
			Cpe23Uri   string `json:"cpe23Uri"`
		} `json:"cpe_match,omitempty"`
		Children []struct {
			Operator string `json:"operator"`
			CpeMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				Cpe23Uri   string `json:"cpe23Uri"`
			} `json:"cpe_match,omitempty"`
		} `json:"children,omitempty"`
	}, description string, cvssScore float64, severity string) []ContainerVulnerability {

	var vulnerabilities []ContainerVulnerability

	// Process each node
	for _, node := range nodes {
		// Process direct CPE matches
		for _, match := range node.CpeMatch {
			vuln := processCPEMatch(cveID, match.Cpe23Uri, match.Vulnerable,
				cvssScore, severity)
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, *vuln)
			}
		}

		// Process child nodes
		for _, child := range node.Children {
			for _, match := range child.CpeMatch {
				vuln := processCPEMatch(cveID, match.Cpe23Uri, match.Vulnerable,
					cvssScore, severity)
				if vuln != nil {
					vulnerabilities = append(vulnerabilities, *vuln)
				}
			}
		}
	}

	return vulnerabilities
}

// Process a CPE match
func processCPEMatch(cveID, cpeURI string, vulnerable bool,
	cvssScore float64, severity string) *ContainerVulnerability {

	// Check if CPE is for a container technology
	tech, version, found := matchContainerTechnologyInCPE(cpeURI)
	if !found || version == "" {
		return nil
	}

	// Create vulnerability info
	return &ContainerVulnerability{
		CVEId:            cveID,
		Technology:       tech,
		AffectedVersions: []string{version},
		CVSSScore:        cvssScore,
		Severity:         severity,
	}
}

// Match container technology in CPE URI
func matchContainerTechnologyInCPE(cpeURI string) (string, string, bool) {
	// Parse CPE URI
	// Format: cpe:2.3:part:vendor:product:version:update:edition:language:...
	parts := strings.Split(cpeURI, ":")
	if len(parts) < 5 {
		return "", "", false
	}

	vendor := strings.ToLower(parts[3])
	product := strings.ToLower(parts[4])
	version := ""
	if len(parts) > 5 {
		version = parts[5]
	}

	// Skip wildcard versions
	if version == "*" {
		return "", "", false
	}

	// Check against container technologies
	for tech, aliases := range containerTechnologies {
		for _, alias := range aliases {
			if vendor == alias || product == alias {
				return tech, version, true
			}
		}
	}

	return "", "", false
}

// Save vulnerability data
func saveVulnerabilityData(vulnerabilities []ContainerVulnerability) {
	if len(vulnerabilities) == 0 {
		log.Println("No container vulnerabilities found")
		return
	}

	// Create output directory
	outputDir := filepath.Join(dataDir, "vulnerabilities")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Group vulnerabilities by technology
	techVulns := make(map[string][]ContainerVulnerability)
	for _, vuln := range vulnerabilities {
		techVulns[vuln.Technology] = append(techVulns[vuln.Technology], vuln)
	}

	// Save all vulnerabilities to one file
	allVulnsFile := filepath.Join(outputDir, "all-container-vulnerabilities.json")
	allVulnsJSON, err := json.MarshalIndent(vulnerabilities, "", "  ")
	if err != nil {
		log.Printf("Failed to serialize all vulnerabilities: %v", err)
	} else {
		if err := os.WriteFile(allVulnsFile, allVulnsJSON, 0644); err != nil {
			log.Printf("Failed to save all vulnerabilities: %v", err)
		} else {
			log.Printf("Saved %d container vulnerabilities to %s\n",
				len(vulnerabilities), allVulnsFile)
		}
	}

	// Save vulnerabilities by technology
	for tech, vulns := range techVulns {
		techFile := filepath.Join(outputDir, fmt.Sprintf("%s-vulnerabilities.json", tech))
		techJSON, err := json.MarshalIndent(vulns, "", "  ")
		if err != nil {
			log.Printf("Failed to serialize %s vulnerabilities: %v", tech, err)
			continue
		}

		if err := os.WriteFile(techFile, techJSON, 0644); err != nil {
			log.Printf("Failed to save %s vulnerabilities: %v", tech, err)
		} else {
			log.Printf("Saved %d %s vulnerabilities to %s\n",
				len(vulns), tech, techFile)
		}
	}

	// Generate CSV summary
	generateVulnerabilitySummaryCSV(vulnerabilities,
		filepath.Join(outputDir, "container-vulnerabilities-summary.csv"))
}

// Generate CSV summary of vulnerabilities
func generateVulnerabilitySummaryCSV(vulns []ContainerVulnerability, outputFile string) {
	// Create CSV file
	file, err := os.Create(outputFile)
	if err != nil {
		log.Printf("Failed to create CSV file: %v", err)
		return
	}
	defer file.Close()

	// Write CSV header
	_, err = file.WriteString("Technology,Version,CVE ID,CVSS Score,Severity\n")
	if err != nil {
		log.Printf("Failed to write CSV header: %v", err)
		return
	}

	// Write data rows
	for _, vuln := range vulns {
		for _, version := range vuln.AffectedVersions {
			line := fmt.Sprintf("%s,%s,%s,%.1f,%s\n",
				vuln.Technology, version, vuln.CVEId, vuln.CVSSScore, vuln.Severity)
			if _, err := file.WriteString(line); err != nil {
				log.Printf("Failed to write CSV data: %v", err)
			}
		}
	}

	log.Printf("Generated vulnerability summary CSV: %s\n", outputFile)
}

// Main entry point
func FetchContainerVulnerabilities() {
	log.Println("Starting container vulnerability extraction...")
	ExtractContainerVulnerabilities()
	log.Println("Container vulnerability extraction complete.")
}
