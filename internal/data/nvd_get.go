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
	// NVD feeds 基础 URL
	nvdFeedsBaseURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"

	// 数据存储目录
	dataDir = "internal/data/nvd-data"

	// 用户代理
	userAgent = "Mozilla/5.0 NVD Data Fetcher"
)

// ExtractContainerVulnerabilities 获取并处理容器技术的 NVD 数据
func ExtractContainerVulnerabilities() {
	// 创建数据目录
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	log.Println("Downloading NVD data for container-related vulnerabilities...")
	vulnerabilities := fetchContainerVulnerabilitiesFromNVD(15)

	// 保存提取的漏洞信息
	saveVulnerabilityData(vulnerabilities)
}

// 从 NVD feeds 获取容器漏洞
func fetchContainerVulnerabilitiesFromNVD(num int) []ContainerVulnerability {
	// 获取当前年份
	currentYear := time.Now().Year()

	// 存储所有提取的漏洞
	var allVulnerabilities []ContainerVulnerability

	// 处理最近 5 年的 CVE 数据
	for year := currentYear; year >= currentYear-num; year-- {
		yearStr := fmt.Sprintf("%d", year)
		feedURL := fmt.Sprintf(nvdFeedsBaseURL, yearStr)
		outputFile := filepath.Join(dataDir, fmt.Sprintf("nvdcve-%s.json", yearStr))
		gzOutputFile := outputFile + ".gz"

		log.Printf("Processing CVE data for year %d...\n", year)

		// 如果压缩文件不存在则下载
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

		// 解压 gzip 文件
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			if err := decompressGzFile(gzOutputFile, outputFile); err != nil {
				log.Printf("Error decompressing file: %v", err)
				continue
			}
			log.Printf("Successfully decompressed CVE data for year %d\n", year)
		} else {
			log.Printf("File %s already exists, skipping decompression\n", outputFile)
		}

		// 读取并解析 JSON 文件
		cveData, err := parseCVEFile(outputFile)
		if err != nil {
			log.Printf("Error parsing CVE data: %v", err)
			continue
		}

		// 提取容器漏洞
		log.Printf("Extracting container vulnerabilities from %d data...\n", year)
		yearVulnerabilities := extractContainerVulnerabilities(cveData)
		allVulnerabilities = append(allVulnerabilities, yearVulnerabilities...)
		log.Printf("Extracted %d container vulnerabilities from %d data\n",
			len(yearVulnerabilities), year)

		// 清理提取的 JSON 文件以节省空间
		if err := os.Remove(outputFile); err != nil {
			log.Printf("Error removing file: %v", err)
		}
	}

	log.Printf("Total container vulnerabilities extracted: %d\n", len(allVulnerabilities))
	return allVulnerabilities
}

// 从 URL 下载文件
func downloadFile(url, outputPath string) error {
	// 创建 HTTP 客户端
	client := &http.Client{
		Timeout: 180 * time.Second,
	}

	// 创建请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// 设置请求头
	req.Header.Set("User-Agent", userAgent)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	// 创建输出文件
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	// 复制数据
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save file: %v", err)
	}

	return nil
}

// 解压 gzip 文件
func decompressGzFile(gzFilePath, outputFilePath string) error {
	// 打开 gzip 文件
	gzFile, err := os.Open(gzFilePath)
	if err != nil {
		return fmt.Errorf("failed to open gzip file: %v", err)
	}
	defer gzFile.Close()

	// 创建 gzip 读取器
	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()

	// 创建输出文件
	outFile, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	// 复制解压缩数据
	_, err = io.Copy(outFile, gzReader)
	if err != nil {
		return fmt.Errorf("decompression failed: %v", err)
	}

	return nil
}

// 解析 CVE JSON 文件
func parseCVEFile(filePath string) (*CVE, error) {
	// 读取文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// 解析 JSON
	var cveData CVE
	if err := json.Unmarshal(data, &cveData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return &cveData, nil
}

// 从 CVE 数据中提取容器漏洞
func extractContainerVulnerabilities(cveData *CVE) []ContainerVulnerability {
	var vulnerabilities []ContainerVulnerability

	// 处理每个 CVE 项目
	for _, item := range cveData.CVEItems {
		cveID := item.CVE.CVEDataMeta.ID

		// 获取描述
		var description string
		for _, desc := range item.CVE.Description.DescriptionData {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		// 获取 CVSS 分数和严重性
		var cvssScore float64
		var severity string
		if item.Impact.BaseMetricV3.CVSSV3.BaseScore > 0 {
			cvssScore = item.Impact.BaseMetricV3.CVSSV3.BaseScore
			severity = item.Impact.BaseMetricV3.CVSSV3.BaseSeverity
		} else if item.Impact.BaseMetricV2.CVSSV2.BaseScore > 0 {
			cvssScore = item.Impact.BaseMetricV2.CVSSV2.BaseScore
			severity = item.Impact.BaseMetricV2.Severity
		}

		// 检查描述是否提及容器技术
		descriptionVulns := extractVulnerabilitiesFromDescription(
			cveID, description, cvssScore, severity)
		vulnerabilities = append(vulnerabilities, descriptionVulns...)

		// 检查 CPE 数据
		cpeVulns := extractVulnerabilitiesFromCPE(
			cveID, item.Configurations.Nodes, description, cvssScore, severity)
		vulnerabilities = append(vulnerabilities, cpeVulns...)
	}

	return vulnerabilities
}

// 从描述文本中提取漏洞
func extractVulnerabilitiesFromDescription(
	cveID, description string, cvssScore float64, severity string) []ContainerVulnerability {

	var vulnerabilities []ContainerVulnerability

	// 检查每种容器技术
	for tech, aliases := range containerTechnologies {
		// 检查描述中是否提及任何别名
		mentioned := false
		for _, alias := range aliases {
			// 查找技术名称周围的词边界
			pattern := fmt.Sprintf(`(?i)\b%s\b`, regexp.QuoteMeta(alias))
			if regexp.MustCompile(pattern).MatchString(description) {
				mentioned = true
				break
			}
		}

		if mentioned {
			// 提取版本信息
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

// 根据技术从描述中提取版本
func extractVersionsFromDescription(description, technology string) []string {
	var versions []string
	versionSet := make(map[string]bool) // 避免重复

	// 特定技术的版本模式
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

	// 提取明确的版本
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(description, -1)
		for _, match := range matches {
			if len(match) > 1 && isValidVersion(match[1]) {
				versionSet[match[1]] = true
			}
		}
	}

	// 提取版本范围
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

	// 将集合转换为切片
	for version := range versionSet {
		versions = append(versions, version)
	}

	return versions
}

// 检查字符串是否为有效版本
func isValidVersion(version string) bool {
	// 基本版本验证
	return regexp.MustCompile(`^\d+\.\d+(\.\d+)?`).MatchString(version)
}

// 从 CPE 数据中提取漏洞
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

	// 处理每个节点
	for _, node := range nodes {
		// 处理直接 CPE 匹配
		for _, match := range node.CpeMatch {
			vuln := processCPEMatch(cveID, match.Cpe23Uri, match.Vulnerable,
				cvssScore, severity)
			if vuln != nil {
				vulnerabilities = append(vulnerabilities, *vuln)
			}
		}

		// 处理子节点
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

// 处理 CPE 匹配
func processCPEMatch(cveID, cpeURI string, vulnerable bool,
	cvssScore float64, severity string) *ContainerVulnerability {

	// 检查 CPE 是否属于容器技术
	tech, version, found := matchContainerTechnologyInCPE(cpeURI)
	if !found || version == "" {
		return nil
	}

	// 创建漏洞信息
	return &ContainerVulnerability{
		CVEId:            cveID,
		Technology:       tech,
		AffectedVersions: []string{version},
		CVSSScore:        cvssScore,
		Severity:         severity,
	}
}

// 在 CPE URI 中匹配容器技术
func matchContainerTechnologyInCPE(cpeURI string) (string, string, bool) {
	// 解析 CPE URI
	// 格式: cpe:2.3:part:vendor:product:version:update:edition:language:...
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

	// 跳过通配符版本
	if version == "*" {
		return "", "", false
	}

	// 检查容器技术
	for tech, aliases := range containerTechnologies {
		for _, alias := range aliases {
			if vendor == alias || product == alias {
				return tech, version, true
			}
		}
	}

	return "", "", false
}

// 保存漏洞数据
func saveVulnerabilityData(vulnerabilities []ContainerVulnerability) {
	if len(vulnerabilities) == 0 {
		log.Println("No container vulnerabilities found")
		return
	}

	// 创建输出目录
	outputDir := filepath.Join(dataDir, "vulnerabilities")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// 按技术分组漏洞
	techVulns := make(map[string][]ContainerVulnerability)
	for _, vuln := range vulnerabilities {
		techVulns[vuln.Technology] = append(techVulns[vuln.Technology], vuln)
	}

	// 将所有漏洞保存到一个文件
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

	// 按技术保存漏洞
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

	// 生成 CSV 摘要
	generateVulnerabilitySummaryCSV(vulnerabilities,
		filepath.Join(outputDir, "container-vulnerabilities-summary.csv"))
}

// 生成漏洞摘要 CSV
func generateVulnerabilitySummaryCSV(vulns []ContainerVulnerability, outputFile string) {
	// 创建 CSV 文件
	file, err := os.Create(outputFile)
	if err != nil {
		log.Printf("Failed to create CSV file: %v", err)
		return
	}
	defer file.Close()

	// 写入 CSV 表头
	_, err = file.WriteString("Technology,Version,CVE ID,CVSS Score,Severity\n")
	if err != nil {
		log.Printf("Failed to write CSV header: %v", err)
		return
	}

	// 写入数据行
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
