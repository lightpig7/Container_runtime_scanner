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
	// 这些是按年份分组的CVE数据
	nvdFeedsBaseURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"

	// 数据存储目录
	dataDir = "./internal/data/nvd-data"

	// 用户代理
	userAgent = "Mozilla/5.0 NVD Data Fetcher"
)

// CVE代表通用漏洞和暴露
type CVE struct {
	CVEDataType         string    `json:"dataType"`
	CVEDataFormat       string    `json:"dataFormat"`
	CVEDataVersion      string    `json:"dataVersion"`
	CVEDataNumberOfCVEs string    `json:"numberOfCVEs"`
	CVEDataTimestamp    string    `json:"timestamp"`
	CVEItems            []CVEItem `json:"CVE_Items"`
}

// CVEItem代表NVD中的单个CVE条目
type CVEItem struct {
	CVE struct {
		CVEDataMeta struct {
			ID string `json:"ID"`
		} `json:"CVE_data_meta"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		Nodes []struct {
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
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CVSSV3 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AttackVector          string  `json:"attackVector"`
				AttackComplexity      string  `json:"attackComplexity"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				UserInteraction       string  `json:"userInteraction"`
				Scope                 string  `json:"scope"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
			} `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3,omitempty"`
		BaseMetricV2 struct {
			CVSSV2 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			AcInsufInfo             bool    `json:"acInsufInfo,omitempty"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired,omitempty"`
		} `json:"baseMetricV2,omitempty"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

// ContainerVersionInfo 存储容器技术的版本信息
type ContainerVersionInfo struct {
	CVEId          string        `json:"cveId"`
	Technology     string        `json:"technology"`
	Version        string        `json:"version"`
	Vulnerable     bool          `json:"vulnerable"`
	CpeUri         string        `json:"cpeUri"`
	Description    string        `json:"description"`
	PublishedDate  string        `json:"publishedDate"`
	CVSSScore      float64       `json:"cvssScore,omitempty"`
	Severity       string        `json:"severity,omitempty"`
	MatchingSource string        `json:"matchingSource"`
	VersionRange   *VersionRange `json:"versionRange,omitempty"`
}

// VersionRange 表示版本范围信息
type VersionRange struct {
	StartIncluding string `json:"startIncluding,omitempty"`
	StartExcluding string `json:"startExcluding,omitempty"`
	EndIncluding   string `json:"endIncluding,omitempty"`
	EndExcluding   string `json:"endExcluding,omitempty"`
}

// UpdateContainerVersions 从NVD数据中提取容器技术版本信息
func UpdateContainerVersions() {
	// 创建数据目录
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("无法创建数据目录: %v", err)
	}

	fmt.Println("下载NVD Feeds获取容器相关版本信息...")
	versionInfos := fetchContainerVersionsFromFeeds()

	// 保存提取的版本信息
	saveVersionInfo(versionInfos)
}

// 从NVD Feeds获取容器相关技术的版本信息
func fetchContainerVersionsFromFeeds() []ContainerVersionInfo {
	// 获取当前年份
	currentYear := time.Now().Year()

	// 存储所有提取的版本信息
	var allVersionInfos []ContainerVersionInfo

	// 设置关注的技术列表
	targetTechnologies := []string{
		"docker", "runc", "containerd", "kubernetes", "k8s",
		"podman", "cri-o", "buildah", "skopeo", "moby",
		"lxc", "lxd", "cri", "oci",
	}

	// 版本提取正则表达式
	versionRegex := regexp.MustCompile(`(?i)(version|v)[:\s]*([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?|\d+\.\d+|\d+)`)

	// CPE版本提取正则表达式 - 匹配cpe:2.3:a:docker:docker:*
	cpeProductVersionRegex := regexp.MustCompile(`cpe:2\.3:[^:]+:[^:]+:([^:]+):([^:]+)`)

	for year := currentYear; year >= currentYear-5; year-- {
		yearStr := fmt.Sprintf("%d", year)
		feedURL := fmt.Sprintf(nvdFeedsBaseURL, yearStr)
		outputFile := filepath.Join(dataDir, fmt.Sprintf("nvdcve-%s.json", yearStr))
		gzOutputFile := outputFile + ".gz"

		fmt.Printf("处理 %d 年的CVE数据...\n", year)

		// 如果gzip文件不存在，下载它
		if _, err := os.Stat(gzOutputFile); err != nil {
			fmt.Printf("下载 %d 年的CVE数据...\n", year)
			// 创建HTTP客户端
			client := &http.Client{
				Timeout: 180 * time.Second,
			}

			// 创建请求
			req, err := http.NewRequest("GET", feedURL, nil)
			if err != nil {
				log.Printf("创建请求失败: %v", err)
				continue
			}

			// 设置请求头
			req.Header.Set("User-Agent", userAgent)

			// 发送请求
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("发送请求失败: %v", err)
				continue
			}

			// 检查响应状态
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				log.Printf("下载失败: %s", resp.Status)
				continue
			}

			// 保存gzip文件
			out, err := os.Create(gzOutputFile)
			if err != nil {
				resp.Body.Close()
				log.Printf("创建文件失败: %v", err)
				continue
			}

			_, err = io.Copy(out, resp.Body)
			resp.Body.Close()
			out.Close()
			if err != nil {
				log.Printf("保存文件失败: %v", err)
				continue
			}

			fmt.Printf("成功下载 %d 年的CVE数据\n", year)
		} else {
			fmt.Printf("文件 %s 已存在，跳过下载\n", gzOutputFile)
		}

		// 解压gzip文件
		if _, err := os.Stat(outputFile); err != nil {
			err := decompressGzFile(gzOutputFile, outputFile)
			if err != nil {
				log.Printf("解压文件失败: %v", err)
				continue
			}
			fmt.Printf("成功解压 %d 年的CVE数据\n", year)
		} else {
			fmt.Printf("文件 %s 已存在，跳过解压\n", outputFile)
		}

		// 读取解压后的文件
		data, err := os.ReadFile(outputFile)
		if err != nil {
			log.Printf("读取文件失败: %v", err)
			continue
		}

		// 解析CVE数据
		var cveData CVE
		if err := json.Unmarshal(data, &cveData); err != nil {
			log.Printf("解析JSON失败: %v", err)
			continue
		}

		fmt.Printf("开始从 %d 年数据中提取容器技术版本信息...\n", year)
		yearVersions := 0

		// 遍历CVE条目
		for _, item := range cveData.CVEItems {
			cveID := item.CVE.CVEDataMeta.ID

			// 获取英文描述
			var description string
			for _, desc := range item.CVE.Description.DescriptionData {
				if desc.Lang == "en" {
					description = desc.Value
					break
				}
			}

			// 处理CVE基本信息
			var cvssScore float64
			var severity string
			if item.Impact.BaseMetricV3.CVSSV3.BaseScore > 0 {
				cvssScore = item.Impact.BaseMetricV3.CVSSV3.BaseScore
				severity = item.Impact.BaseMetricV3.CVSSV3.BaseSeverity
			} else if item.Impact.BaseMetricV2.CVSSV2.BaseScore > 0 {
				cvssScore = item.Impact.BaseMetricV2.CVSSV2.BaseScore
				severity = item.Impact.BaseMetricV2.Severity
			}

			// 从描述中查找技术和版本信息
			for _, tech := range targetTechnologies {
				// 在描述中查找技术名称
				techRegex := regexp.MustCompile(fmt.Sprintf(`(?i)\b%s\b`, tech))
				if techRegex.MatchString(description) {
					// 查找版本号
					matches := versionRegex.FindAllStringSubmatch(description, -1)
					if len(matches) > 0 {
						for _, match := range matches {
							if len(match) > 2 {
								versionInfo := ContainerVersionInfo{
									CVEId:          cveID,
									Technology:     tech,
									Version:        match[2],
									Description:    description,
									PublishedDate:  item.PublishedDate,
									CVSSScore:      cvssScore,
									Severity:       severity,
									MatchingSource: "description",
								}
								allVersionInfos = append(allVersionInfos, versionInfo)
								yearVersions++
							}
						}
					}
				}
			}

			// 从CPE中查找技术和版本信息
			for _, node := range item.Configurations.Nodes {
				// 检查直接CPE匹配
				for _, match := range node.CpeMatch {
					cpeURI := match.Cpe23Uri

					// 检查CPE是否包含目标技术
					for _, tech := range targetTechnologies {
						if strings.Contains(strings.ToLower(cpeURI), tech) {
							// 从CPE中提取版本
							cpeMatches := cpeProductVersionRegex.FindStringSubmatch(cpeURI)

							if len(cpeMatches) > 2 {
								// 处理版本信息
								versionInfo := ContainerVersionInfo{
									CVEId:          cveID,
									Technology:     tech,
									Version:        cpeMatches[2],
									Vulnerable:     match.Vulnerable,
									CpeUri:         cpeURI,
									Description:    description,
									PublishedDate:  item.PublishedDate,
									CVSSScore:      cvssScore,
									Severity:       severity,
									MatchingSource: "cpe",
								}

								// 检查是否有版本范围信息
								if strings.Contains(cpeURI, "*") || strings.Contains(cpeURI, "-") {
									// 提取版本范围
									versionRange := extractVersionRange(cpeURI)
									if versionRange != nil {
										versionInfo.VersionRange = versionRange
									}
								}

								allVersionInfos = append(allVersionInfos, versionInfo)
								yearVersions++
							}
						}
					}
				}

				// 检查子节点的CPE匹配
				for _, child := range node.Children {
					for _, match := range child.CpeMatch {
						cpeURI := match.Cpe23Uri

						// 检查CPE是否包含目标技术
						for _, tech := range targetTechnologies {
							if strings.Contains(strings.ToLower(cpeURI), tech) {
								// 从CPE中提取版本
								cpeMatches := cpeProductVersionRegex.FindStringSubmatch(cpeURI)

								if len(cpeMatches) > 2 {
									// 处理版本信息
									versionInfo := ContainerVersionInfo{
										CVEId:          cveID,
										Technology:     tech,
										Version:        cpeMatches[2],
										Vulnerable:     match.Vulnerable,
										CpeUri:         cpeURI,
										Description:    description,
										PublishedDate:  item.PublishedDate,
										CVSSScore:      cvssScore,
										Severity:       severity,
										MatchingSource: "cpe_child",
									}

									// 检查是否有版本范围信息
									if strings.Contains(cpeURI, "*") || strings.Contains(cpeURI, "-") {
										// 提取版本范围
										versionRange := extractVersionRange(cpeURI)
										if versionRange != nil {
											versionInfo.VersionRange = versionRange
										}
									}

									allVersionInfos = append(allVersionInfos, versionInfo)
									yearVersions++
								}
							}
						}
					}
				}
			}
		}

		fmt.Printf("从 %d 年数据中提取了 %d 条容器技术版本信息\n", year, yearVersions)

		// 如果不再需要，删除解压后的JSON文件以节省空间，保留gz文件
		if err := os.Remove(outputFile); err != nil {
			log.Printf("删除文件失败: %v", err)
		}
	}

	fmt.Printf("共提取了 %d 条容器技术版本信息\n", len(allVersionInfos))
	return allVersionInfos
}

// 从CPE URI中提取版本范围信息
func extractVersionRange(cpeURI string) *VersionRange {
	// 匹配版本范围表达式
	startIncludingRegex := regexp.MustCompile(`cpe:2\.3:[^:]+:[^:]+:[^:]+:([^:]+)`)
	startExcludingRegex := regexp.MustCompile(`cpe:2\.3:[^:]+:[^:]+:[^:]+:([^:]+)`)
	endIncludingRegex := regexp.MustCompile(`cpe:2\.3:[^:]+:[^:]+:[^:]+:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^:]+):`)
	endExcludingRegex := regexp.MustCompile(`cpe:2\.3:[^:]+:[^:]+:[^:]+:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^:]+)`)

	versionRange := &VersionRange{}
	hasRange := false

	if match := startIncludingRegex.FindStringSubmatch(cpeURI); len(match) > 1 && match[1] != "*" {
		versionRange.StartIncluding = match[1]
		hasRange = true
	}

	if match := startExcludingRegex.FindStringSubmatch(cpeURI); len(match) > 1 && match[1] != "*" {
		versionRange.StartExcluding = match[1]
		hasRange = true
	}

	if match := endIncludingRegex.FindStringSubmatch(cpeURI); len(match) > 1 && match[1] != "*" {
		versionRange.EndIncluding = match[1]
		hasRange = true
	}

	if match := endExcludingRegex.FindStringSubmatch(cpeURI); len(match) > 1 && match[1] != "*" {
		versionRange.EndExcluding = match[1]
		hasRange = true
	}

	if hasRange {
		return versionRange
	}
	return nil
}

// 保存版本信息到文件
func saveVersionInfo(versionInfos []ContainerVersionInfo) {
	if len(versionInfos) == 0 {
		fmt.Println("没有找到容器技术版本信息")
		return
	}

	// 创建输出目录
	outputDir := filepath.Join(dataDir, "versions")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("无法创建输出目录: %v", err)
	}

	// 按技术分组版本信息
	techVersions := make(map[string][]ContainerVersionInfo)
	for _, info := range versionInfos {
		techVersions[info.Technology] = append(techVersions[info.Technology], info)
	}

	// 保存所有版本信息到一个文件
	allVersionsFile := filepath.Join(outputDir, "all-container-versions.json")
	allVersionsJSON, err := json.MarshalIndent(versionInfos, "", "  ")
	if err != nil {
		log.Printf("序列化所有版本信息失败: %v", err)
	} else {
		if err := os.WriteFile(allVersionsFile, allVersionsJSON, 0644); err != nil {
			log.Printf("保存所有版本信息失败: %v", err)
		} else {
			fmt.Printf("已保存 %d 条容器技术版本信息到 %s\n", len(versionInfos), allVersionsFile)
		}
	}

	// 为每个技术单独保存一个文件
	for tech, versions := range techVersions {
		techFile := filepath.Join(outputDir, fmt.Sprintf("%s-versions.json", tech))
		techJSON, err := json.MarshalIndent(versions, "", "  ")
		if err != nil {
			log.Printf("序列化 %s 版本信息失败: %v", tech, err)
			continue
		}

		if err := os.WriteFile(techFile, techJSON, 0644); err != nil {
			log.Printf("保存 %s 版本信息失败: %v", tech, err)
		} else {
			fmt.Printf("已保存 %d 条 %s 版本信息到 %s\n", len(versions), tech, techFile)
		}
	}

	// 生成CSV版本摘要
	generateVersionSummaryCSV(versionInfos, filepath.Join(outputDir, "container-versions-summary.csv"))
}

// 生成版本摘要CSV
func generateVersionSummaryCSV(versionInfos []ContainerVersionInfo, outputFile string) {
	// 创建CSV文件
	file, err := os.Create(outputFile)
	if err != nil {
		log.Printf("创建CSV文件失败: %v", err)
		return
	}
	defer file.Close()

	// 写入CSV头
	_, err = file.WriteString("Technology,Version,CVE Count,Max CVSS Score,Latest CVE Date\n")
	if err != nil {
		log.Printf("写入CSV头失败: %v", err)
		return
	}

	// 按技术和版本分组
	versionStats := make(map[string]map[string]struct {
		CVECount     int
		MaxCVSSScore float64
		LatestDate   string
		CVEIds       map[string]bool
	})

	for _, info := range versionInfos {
		tech := info.Technology
		version := info.Version

		// 初始化技术映射
		if _, exists := versionStats[tech]; !exists {
			versionStats[tech] = make(map[string]struct {
				CVECount     int
				MaxCVSSScore float64
				LatestDate   string
				CVEIds       map[string]bool
			})
		}

		// 初始化版本统计
		if _, exists := versionStats[tech][version]; !exists {
			versionStats[tech][version] = struct {
				CVECount     int
				MaxCVSSScore float64
				LatestDate   string
				CVEIds       map[string]bool
			}{
				CVECount:     0,
				MaxCVSSScore: 0,
				LatestDate:   "",
				CVEIds:       make(map[string]bool),
			}
		}

		// 更新统计信息
		stats := versionStats[tech][version]

		// 只有当这个CVE ID还没被计数时才增加计数
		if !stats.CVEIds[info.CVEId] {
			stats.CVECount++
			stats.CVEIds[info.CVEId] = true
		}

		// 更新最大CVSS分数
		if info.CVSSScore > stats.MaxCVSSScore {
			stats.MaxCVSSScore = info.CVSSScore
		}

		// 更新最新日期
		if stats.LatestDate == "" || info.PublishedDate > stats.LatestDate {
			stats.LatestDate = info.PublishedDate
		}

		versionStats[tech][version] = stats
	}

	// 写入CSV数据
	for tech, versions := range versionStats {
		for version, stats := range versions {
			line := fmt.Sprintf("%s,%s,%d,%.1f,%s\n",
				tech, version, stats.CVECount, stats.MaxCVSSScore, stats.LatestDate)
			if _, err := file.WriteString(line); err != nil {
				log.Printf("写入CSV数据失败: %v", err)
			}
		}
	}

	fmt.Printf("已生成版本摘要CSV: %s\n", outputFile)
}

// 解压gzip文件
func decompressGzFile(gzFilePath, outputFilePath string) error {
	// 打开gzip文件
	gzFile, err := os.Open(gzFilePath)
	if err != nil {
		return fmt.Errorf("打开gzip文件失败: %v", err)
	}
	defer gzFile.Close()

	// 创建gzip读取器
	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return fmt.Errorf("创建gzip读取器失败: %v", err)
	}
	defer gzReader.Close()

	// 创建输出文件
	outFile, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outFile.Close()

	// 复制解压数据
	_, err = io.Copy(outFile, gzReader)
	if err != nil {
		return fmt.Errorf("解压数据失败: %v", err)
	}

	return nil
}

// Main入口函数
func ExtractContainerVersions() {
	fmt.Println("开始提取容器技术版本信息...")
	UpdateContainerVersions()
	fmt.Println("容器技术版本信息提取完成。")
}
