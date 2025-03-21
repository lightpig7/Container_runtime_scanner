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
	"sort"
	"strings"
	"time"
)

const (
	// 这些是按年份分组的CVE数据
	nvdFeedsBaseURL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"

	// 数据存储目录
	dataDir = "./data/nvd-data"

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

// APIResponse代表NVD API的响应
type APIResponse struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		CVE struct {
			ID               string `json:"id"`
			SourceIdentifier string `json:"sourceIdentifier"`
			Published        string `json:"published"`
			LastModified     string `json:"lastModified"`
			VulnStatus       string `json:"vulnStatus"`
			Descriptions     []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					Source   string `json:"source"`
					Type     string `json:"type"`
					CvssData struct {
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
					} `json:"cvssData"`
					ExploitabilityScore float64 `json:"exploitabilityScore"`
					ImpactScore         float64 `json:"impactScore"`
				} `json:"cvssMetricV31,omitempty"`
				CvssMetricV2 []struct {
					Source   string `json:"source"`
					Type     string `json:"type"`
					CvssData struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AccessVector          string  `json:"accessVector"`
						AccessComplexity      string  `json:"accessComplexity"`
						Authentication        string  `json:"authentication"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity        string  `json:"baseSeverity"`
					ExploitabilityScore float64 `json:"exploitabilityScore"`
					ImpactScore         float64 `json:"impactScore"`
				} `json:"cvssMetricV2,omitempty"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					Operator string `json:"operator"`
					Negate   bool   `json:"negate"`
					CpeMatch []struct {
						Vulnerable      bool   `json:"vulnerable"`
						Criteria        string `json:"criteria"`
						MatchCriteriaId string `json:"matchCriteriaId"`
					} `json:"cpeMatch,omitempty"`
					Children []struct {
						Operator string `json:"operator"`
						Negate   bool   `json:"negate"`
						CpeMatch []struct {
							Vulnerable      bool   `json:"vulnerable"`
							Criteria        string `json:"criteria"`
							MatchCriteriaId string `json:"matchCriteriaId"`
						} `json:"cpeMatch,omitempty"`
					} `json:"children,omitempty"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func UpdateData() {
	// 创建数据目录
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("无法创建数据目录: %v", err)
	}

	// 从命令行参数解析选项
	var skipDownload bool = false

	if !skipDownload {
		// 使用Feeds方法 - 批量下载但数据量大
		fmt.Println("下载NVD Feeds获取CVE数据...")
		fetchCVEsUsingFeeds()
	} else {
		fmt.Println("跳过下载，直接分析现有数据...")
	}

	// 筛选并显示容器相关漏洞
	displaySampleCVEs()
}

// 使用NVD Feeds获取CVE数据并筛选容器相关漏洞
func fetchCVEsUsingFeeds() {
	// 获取当前年份
	currentYear := time.Now().Year()

	// 下载最近几年的CVE数据
	// 可以根据需要调整年份范围，这里使用最近3年的数据
	containerVulnerabilities := make(map[string]interface{})

	// 记录匹配原因，帮助调试
	matchReasons := make(map[string]string)

	for year := currentYear; year >= currentYear-2; year-- {
		yearStr := fmt.Sprintf("%d", year)
		feedURL := fmt.Sprintf(nvdFeedsBaseURL, yearStr)
		outputFile := filepath.Join(dataDir, fmt.Sprintf("nvdcve-%s.json", yearStr))
		gzOutputFile := outputFile + ".gz"

		fmt.Printf("下载 %d 年的CVE数据...\n", year)

		// 如果gzip文件已存在，跳过下载
		if _, err := os.Stat(gzOutputFile); err == nil {
			fmt.Printf("文件 %s 已存在，跳过下载\n", gzOutputFile)
		} else {
			// 创建HTTP客户端
			client := &http.Client{
				Timeout: 180 * time.Second, // 文件较大，增加超时时间
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
		}

		// 解压gzip文件
		err := decompressGzFile(gzOutputFile, outputFile)
		if err != nil {
			log.Printf("解压文件失败: %v", err)
			continue
		}

		fmt.Printf("成功解压 %d 年的CVE数据\n", year)

		// 立即筛选该年份的容器相关漏洞
		fmt.Printf("筛选 %d 年的容器相关漏洞...\n", year)

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

		// 获取更精确的容器关键词列表
		containerKeywords := getContainerKeywords()

		// 筛选容器相关漏洞
		yearContainerVulns := []CVEItem{}
		yearMatchReasons := make(map[string]string)

		for _, item := range cveData.CVEItems {
			cveID := item.CVE.CVEDataMeta.ID
			isContainerRelated, reason := isContainerRelatedCVE(item, containerKeywords)

			// 保存容器相关漏洞
			if isContainerRelated {
				yearContainerVulns = append(yearContainerVulns, item)
				containerVulnerabilities[cveID] = true
				matchReasons[cveID] = reason
				yearMatchReasons[cveID] = reason
			}
		}

		// 保存该年份的容器相关漏洞到单独的文件
		containerFile := filepath.Join(dataDir, fmt.Sprintf("container-cve-%s.json", yearStr))
		containerData := map[string]interface{}{
			"dataType":     "CVE-Container-Related",
			"dataFormat":   "MITRE",
			"dataVersion":  cveData.CVEDataVersion,
			"numberOfCVEs": len(yearContainerVulns),
			"timestamp":    time.Now().Format(time.RFC3339),
			"CVE_Items":    yearContainerVulns,
		}

		containerJSON, err := json.MarshalIndent(containerData, "", "  ")
		if err != nil {
			log.Printf("序列化容器漏洞数据失败: %v", err)
		} else {
			if err := os.WriteFile(containerFile, containerJSON, 0644); err != nil {
				log.Printf("保存容器漏洞数据失败: %v", err)
			} else {
				fmt.Printf("已保存 %d 个容器相关漏洞到 %s\n", len(yearContainerVulns), containerFile)
			}
		}

		// 保存该年份的匹配原因日志
		reasonsFile := filepath.Join(dataDir, fmt.Sprintf("container-match-reasons-%s.txt", yearStr))
		saveMatchReasons(yearMatchReasons, reasonsFile)

		// 删除完整的年度数据文件以节省空间（保留gz文件以供需要）
		if err := os.Remove(outputFile); err != nil {
			log.Printf("删除文件失败: %v", err)
		}
	}

	// 保存所有年份的容器相关漏洞ID列表
	allVulnsFile := filepath.Join(dataDir, "all-container-cve-ids.json")
	vulnIDs := make([]string, 0, len(containerVulnerabilities))
	for id := range containerVulnerabilities {
		vulnIDs = append(vulnIDs, id)
	}

	allVulnsJSON, err := json.MarshalIndent(vulnIDs, "", "  ")
	if err != nil {
		log.Printf("序列化所有容器漏洞ID失败: %v", err)
	} else {
		if err := os.WriteFile(allVulnsFile, allVulnsJSON, 0644); err != nil {
			log.Printf("保存所有容器漏洞ID失败: %v", err)
		} else {
			fmt.Printf("已保存 %d 个容器相关漏洞ID到 %s\n", len(vulnIDs), allVulnsFile)
		}
	}

	// 保存所有匹配原因
	allReasonsFile := filepath.Join(dataDir, "all-container-match-reasons.txt")
	saveMatchReasons(matchReasons, allReasonsFile)
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

// 获取容器关键词列表
func getContainerKeywords() map[string][]string {
	// 按类别组织容器关键词，提高可维护性
	return map[string][]string{
		// 核心容器技术
		"core": {
			"\\bdocker\\b",
			"\\bkubernetes\\b",
			"\\bk8s\\b",
			"\\bcontainerd\\b",
			"\\brunc\\b",
		},
		// 注意: 使用 \b 确保只匹配完整单词 "container"，避免匹配如 "containerization" 等单词
		"container": {
			"\\bcontainer\\b",
		},
		// 容器编排和管理工具
		"management": {
			"\\bpodman\\b",
			"\\bcri-o\\b",
			"\\bbuildah\\b",
			"\\bskopeo\\b",
		},
		// 容器相关标准和接口
		"standards": {
			"\\boci\\b",
			"\\bcri\\b",
		},
		// Kubernetes组件
		"k8s-components": {
			"\\bkubelet\\b",
			"\\bkube-apiserver\\b",
			"etcd.*kubernetes",
		},
		// 容器网络
		"networking": {
			"\\bcalico\\b",
			"\\bflannel\\b",
			"\\bcilium\\b",
		},
		// 其他相关技术
		"other": {
			"\\bmoby\\b",
			"\\blxc\\b",
			"\\blxd\\b",
		},
	}
}

// 判断CVE是否与容器相关
func isContainerRelatedCVE(item CVEItem, containerKeywordsByCategory map[string][]string) (bool, string) {
	//cveID := item.CVE.CVEDataMeta.ID

	// 首先检查描述中是否包含容器关键词
	for _, desc := range item.CVE.Description.DescriptionData {
		if desc.Lang != "en" {
			continue
		}

		descLower := strings.ToLower(desc.Value)

		for category, keywords := range containerKeywordsByCategory {
			for _, keywordPattern := range keywords {
				// 使用正则表达式进行更精确的匹配
				matched, _ := regexp.MatchString(keywordPattern, descLower)
				if matched {
					reason := fmt.Sprintf("在描述中匹配到 %s 类别的关键词: %s", category, keywordPattern)
					return true, reason
				}
			}
		}
	}

	// 其次检查CPE匹配中是否包含容器关键词
	for _, node := range item.Configurations.Nodes {
		// 检查直接CPE匹配
		for _, match := range node.CpeMatch {
			cpeURI := strings.ToLower(match.Cpe23Uri)

			for category, keywords := range containerKeywordsByCategory {
				for _, keywordPattern := range keywords {
					matched, _ := regexp.MatchString(keywordPattern, cpeURI)
					if matched {
						reason := fmt.Sprintf("在CPE URI中匹配到 %s 类别的关键词: %s", category, keywordPattern)
						return true, reason
					}
				}
			}
		}

		// 检查子节点的CPE匹配
		for _, child := range node.Children {
			for _, match := range child.CpeMatch {
				cpeURI := strings.ToLower(match.Cpe23Uri)

				for category, keywords := range containerKeywordsByCategory {
					for _, keywordPattern := range keywords {
						matched, _ := regexp.MatchString(keywordPattern, cpeURI)
						if matched {
							reason := fmt.Sprintf("在子节点CPE URI中匹配到 %s 类别的关键词: %s", category, keywordPattern)
							return true, reason
						}
					}
				}
			}
		}
	}

	return false, ""
}

// 保存匹配原因到文本文件
func saveMatchReasons(reasons map[string]string, filePath string) {
	var builder strings.Builder

	// 按CVE ID排序
	ids := make([]string, 0, len(reasons))
	for id := range reasons {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		builder.WriteString(fmt.Sprintf("%s: %s\n", id, reasons[id]))
	}

	if err := os.WriteFile(filePath, []byte(builder.String()), 0644); err != nil {
		log.Printf("保存匹配原因失败: %v", err)
		return
	}

	fmt.Printf("已保存 %d 个匹配原因到 %s\n", len(reasons), filePath)
}

// 显示与指定技术相关的CVE数据
func displaySampleCVEs() {
	// 获取容器关键词
	containerKeywordsByCategory := getContainerKeywords()

	// 展平关键词分类，便于打印
	var containerKeywords []string
	for _, keywords := range containerKeywordsByCategory {
		for _, keyword := range keywords {
			// 去掉正则表达式中的边界符号，便于显示
			cleanKeyword := strings.ReplaceAll(keyword, "\\b", "")
			containerKeywords = append(containerKeywords, cleanKeyword)
		}
	}

	// 寻找最新的数据文件
	files, err := os.ReadDir(dataDir)
	if err != nil {
		log.Fatalf("读取数据目录失败: %v", err)
	}

	// 优先寻找容器相关的文件
	var latestFile string
	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "container-cve-") && strings.HasSuffix(file.Name(), ".json") {
			latestFile = filepath.Join(dataDir, file.Name())
			break
		}
	}

	// 如果没有找到容器相关文件，寻找普通CVE文件
	if latestFile == "" {
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") && !strings.HasSuffix(file.Name(), ".gz") {
				latestFile = filepath.Join(dataDir, file.Name())
				break
			}
		}
	}

	if latestFile == "" {
		fmt.Println("未找到CVE数据文件")
		return
	}

	fmt.Printf("从 %s 读取数据并显示容器相关漏洞\n", latestFile)

	// 读取文件内容
	data, err := os.ReadFile(latestFile)
	if err != nil {
		log.Fatalf("读取文件失败: %v", err)
	}

	// 存储找到的容器相关漏洞
	var containerVulns []string
	matchReasons := make(map[string]string)

	// 检查文件是否已经是筛选后的容器相关漏洞文件
	if strings.HasPrefix(filepath.Base(latestFile), "container-cve-") {
		// 已经是筛选后的文件，直接解析
		var containerData map[string]interface{}
		if err := json.Unmarshal(data, &containerData); err != nil {
			log.Fatalf("解析JSON失败: %v", err)
		}

		items, ok := containerData["CVE_Items"].([]interface{})
		if !ok {
			log.Fatalf("解析CVE_Items失败")
		}

		fmt.Println("\n======= 容器相关CVE漏洞 =======")
		count := 0

		for _, itemInterface := range items {
			if count >= 20 {
				break
			}

			// 转换为map便于访问
			itemMap, ok := itemInterface.(map[string]interface{})
			if !ok {
				continue
			}

			cveMap, ok := itemMap["cve"].(map[string]interface{})
			if !ok {
				continue
			}

			cveDataMetaMap, ok := cveMap["CVE_data_meta"].(map[string]interface{})
			if !ok {
				continue
			}

			cveID, ok := cveDataMetaMap["ID"].(string)
			if !ok {
				continue
			}

			publishedDate, ok := itemMap["publishedDate"].(string)
			if !ok {
				publishedDate = "未知"
			}

			// 显示CVE基本信息
			fmt.Printf("ID: %s\n", cveID)
			fmt.Printf("发布日期: %s\n", publishedDate)

			// 显示描述
			description := "描述未找到"
			if descMap, ok := cveMap["description"].(map[string]interface{}); ok {
				if descDataArray, ok := descMap["description_data"].([]interface{}); ok {
					for _, descDataInterface := range descDataArray {
						descData, ok := descDataInterface.(map[string]interface{})
						if !ok {
							continue
						}

						lang, ok := descData["lang"].(string)
						if !ok || lang != "en" {
							continue
						}

						value, ok := descData["value"].(string)
						if ok {
							description = value
							break
						}
					}
				}
			}
			fmt.Printf("描述: %s\n", description)

			// 记录匹配原因 (基于描述关键词匹配)
			for category, keywords := range containerKeywordsByCategory {
				for _, keywordPattern := range keywords {
					cleanPattern := strings.ReplaceAll(keywordPattern, "\\b", "")
					matched, _ := regexp.MatchString(keywordPattern, strings.ToLower(description))
					if matched {
						matchReasons[cveID] = fmt.Sprintf("在描述中匹配到 %s 类别的关键词: %s", category, cleanPattern)
						break
					}
				}
				if _, found := matchReasons[cveID]; found {
					break
				}
			}

			// 尝试显示CVSS分数
			if impactMap, ok := itemMap["impact"].(map[string]interface{}); ok {
				if metricV3, ok := impactMap["baseMetricV3"].(map[string]interface{}); ok {
					if cvssV3, ok := metricV3["cvssV3"].(map[string]interface{}); ok {
						baseScore, scoreOk := cvssV3["baseScore"].(float64)
						baseSeverity, sevOk := cvssV3["baseSeverity"].(string)

						if scoreOk && sevOk {
							fmt.Printf("CVSS v3分数: %.1f (%s)\n", baseScore, baseSeverity)
						}
					}
				}
			}

			containerVulns = append(containerVulns, cveID)
			fmt.Println("----------")
			count++
		}

		fmt.Printf("\n显示了 %d 个容器相关漏洞\n", count)
	} else if strings.Contains(latestFile, "nvd-api") {
		// API响应格式
		var apiResponse APIResponse
		if err := json.Unmarshal(data, &apiResponse); err != nil {
			log.Fatalf("解析JSON失败: %v", err)
		}

		fmt.Println("\n======= 容器相关CVE漏洞 (API格式) =======")
		count := 0

		// 遍历所有漏洞
		for _, vuln := range apiResponse.Vulnerabilities {
			if count >= 20 {
				break
			}

			cve := vuln.CVE
			isContainerRelated := false
			var matchReason string

			// 检查描述中是否包含容器关键词
			for _, desc := range cve.Descriptions {
				if desc.Lang != "en" {
					continue
				}

				descLower := strings.ToLower(desc.Value)

				for category, keywords := range containerKeywordsByCategory {
					for _, keywordPattern := range keywords {
						matched, _ := regexp.MatchString(keywordPattern, descLower)
						if matched {
							isContainerRelated = true
							cleanPattern := strings.ReplaceAll(keywordPattern, "\\b", "")
							matchReason = fmt.Sprintf("在描述中匹配到 %s 类别的关键词: %s", category, cleanPattern)
							break
						}
					}
					if isContainerRelated {
						break
					}
				}

				if isContainerRelated {
					break
				}
			}

			// 检查CPE匹配中是否包含容器关键词
			if !isContainerRelated && len(cve.Configurations) > 0 {
				for _, config := range cve.Configurations {
					for _, node := range config.Nodes {
						for _, match := range node.CpeMatch {
							matchLower := strings.ToLower(match.Criteria)

							for category, keywords := range containerKeywordsByCategory {
								for _, keywordPattern := range keywords {
									matched, _ := regexp.MatchString(keywordPattern, matchLower)
									if matched {
										isContainerRelated = true
										cleanPattern := strings.ReplaceAll(keywordPattern, "\\b", "")
										matchReason = fmt.Sprintf("在CPE URI中匹配到 %s 类别的关键词: %s", category, cleanPattern)
										break
									}
								}
								if isContainerRelated {
									break
								}
							}

							if isContainerRelated {
								break
							}
						}

						if isContainerRelated {
							break
						}
					}

					if isContainerRelated {
						break
					}
				}
			}

			// 打印容器相关漏洞
			if isContainerRelated {
				fmt.Printf("ID: %s\n", cve.ID)
				fmt.Printf("发布日期: %s\n", cve.Published)
				fmt.Printf("匹配原因: %s\n", matchReason)

				// 显示描述
				for _, desc := range cve.Descriptions {
					if desc.Lang == "en" {
						fmt.Printf("描述: %s\n", desc.Value)
						break
					}
				}

				// 显示CVSS v3分数（如果有）
				if len(cve.Metrics.CvssMetricV31) > 0 {
					fmt.Printf("CVSS v3分数: %.1f (%s)\n",
						cve.Metrics.CvssMetricV31[0].CvssData.BaseScore,
						cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity)
				}

				// 记录CVE ID和匹配原因
				containerVulns = append(containerVulns, cve.ID)
				matchReasons[cve.ID] = matchReason

				fmt.Println("----------")
				count++
			}
		}

		fmt.Printf("\n找到 %d 个容器相关漏洞\n", count)
	} else {
		// 解析Feeds格式
		var cveData CVE
		if err := json.Unmarshal(data, &cveData); err != nil {
			log.Fatalf("解析JSON失败: %v", err)
		}

		fmt.Println("\n======= 容器相关CVE漏洞 (Feeds格式) =======")
		count := 0

		// 遍历所有漏洞
		for _, item := range cveData.CVEItems {
			if count >= 20 {
				break
			}

			isContainerRelated, reason := isContainerRelatedCVE(item, containerKeywordsByCategory)

			// 打印容器相关漏洞
			if isContainerRelated {
				fmt.Printf("ID: %s\n", item.CVE.CVEDataMeta.ID)
				fmt.Printf("发布日期: %s\n", item.PublishedDate)
				fmt.Printf("匹配原因: %s\n", reason)

				// 显示描述
				for _, desc := range item.CVE.Description.DescriptionData {
					if desc.Lang == "en" {
						fmt.Printf("描述: %s\n", desc.Value)
						break
					}
				}

				// 显示CVSS v3分数（如果有）
				if item.Impact.BaseMetricV3.CVSSV3.BaseScore > 0 {
					fmt.Printf("CVSS v3分数: %.1f (%s)\n",
						item.Impact.BaseMetricV3.CVSSV3.BaseScore,
						item.Impact.BaseMetricV3.CVSSV3.BaseSeverity)
				}

				// 记录CVE ID和匹配原因
				containerVulns = append(containerVulns, item.CVE.CVEDataMeta.ID)
				matchReasons[item.CVE.CVEDataMeta.ID] = reason

				fmt.Println("----------")
				count++
			}
		}

		fmt.Printf("\n找到 %d 个容器相关漏洞\n", count)
	}

	// 保存筛选结果到文件
	if len(containerVulns) > 0 {
		// 保存CVE ID列表
		vulnsFile := filepath.Join(dataDir, "displayed-container-vulns.json")
		vulnsJSON, err := json.MarshalIndent(containerVulns, "", "  ")
		if err != nil {
			log.Printf("无法序列化结果: %v", err)
		} else {
			if err := os.WriteFile(vulnsFile, vulnsJSON, 0644); err != nil {
				log.Printf("无法保存结果: %v", err)
			} else {
				fmt.Printf("已将显示的容器相关漏洞ID保存到 %s\n", vulnsFile)
			}
		}

		// 保存匹配原因
		if len(matchReasons) > 0 {
			reasonsFile := filepath.Join(dataDir, "displayed-container-match-reasons.txt")
			saveMatchReasons(matchReasons, reasonsFile)
		}
	}

	fmt.Println("\n数据筛选完成。可以进一步开发漏洞匹配功能。")
}

// TODO: 添加漏洞数据库更新功能
// TODO: 添加Docker版本与CVE匹配功能
// TODO: 添加优化的数据存储（考虑使用BadgerDB或SQLite）
