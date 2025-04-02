package audit

import (
	"Container_runtime_scanner/internal/docker"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

// CVE 结构体，与JSON字段匹配
type CVE struct {
	CVEId          string        `json:"cveId"`
	Technology     string        `json:"technology"`
	Version        string        `json:"version"`
	Vulnerable     bool          `json:"vulnerable"`
	CpeUri         string        `json:"cpeUri,omitempty"`
	Description    string        `json:"description"`
	PublishedDate  string        `json:"publishedDate"`
	CVSSScore      float64       `json:"cvssScore,omitempty"` // 注意这里是float64类型
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

type CVEs []CVE

// MatchResult 存储匹配结果
type MatchResult struct {
	Component   string
	Version     string
	MatchedCVEs []CVE
}

func VersionMatch() []MatchResult {
	// 获取Docker信息
	versionInfo := docker.GetInfo()

	// 存储所有匹配结果
	var results []MatchResult

	// 检查Docker版本
	dockerMatches := checkComponentVersion("docker", versionInfo.DockerVersion)
	if len(dockerMatches) > 0 {
		results = append(results, MatchResult{
			Component:   "docker",
			Version:     versionInfo.DockerVersion,
			MatchedCVEs: dockerMatches,
		})
	}

	// 检查containerd版本
	if versionInfo.ContainerVersion != "" {
		containerdMatches := checkComponentVersion("containerd", versionInfo.ContainerVersion)
		if len(containerdMatches) > 0 {
			results = append(results, MatchResult{
				Component:   "containerd",
				Version:     versionInfo.ContainerVersion,
				MatchedCVEs: containerdMatches,
			})
		}
	}

	// 检查runc版本
	if versionInfo.RuncVersion != "" {
		runcMatches := checkComponentVersion("runc", versionInfo.RuncVersion)
		if len(runcMatches) > 0 {
			results = append(results, MatchResult{
				Component:   "runc",
				Version:     versionInfo.RuncVersion,
				MatchedCVEs: runcMatches,
			})
		}
	}

	// 打印版本信息
	fmt.Printf("Docker 版本: %s\n", versionInfo.DockerVersion)
	fmt.Printf("API 版本: %s\n", versionInfo.APIVersion)
	fmt.Printf("Go 版本: %s\n", versionInfo.GoVersion)
	fmt.Printf("Git commit: %s\n", versionInfo.GitVersion)
	fmt.Printf("操作系统: %s\n", versionInfo.OSVersion)
	fmt.Printf("runc 版本: %s\n", versionInfo.RuncVersion)
	fmt.Printf("内核版本: %s\n", versionInfo.KernelVersion)
	fmt.Printf("containerd 版本: %s\n", versionInfo.ContainerVersion)

	// 打印匹配结果摘要
	fmt.Println("\n漏洞匹配结果:")
	for _, result := range results {
		fmt.Printf("%s %s 有 %d 个匹配的CVE\n",
			result.Component, result.Version, len(result.MatchedCVEs))

		for _, cve := range result.MatchedCVEs {
			fmt.Printf("  - %s (CVSS: %.1f, %s)\n",
				cve.CVEId, cve.CVSSScore, cve.Severity)
		}
	}

	return results
}

// 检查特定组件的版本是否存在漏洞
func checkComponentVersion(component, version string) []CVE {
	// 清理版本号
	version = cleanVersion(version)

	// 构建文件路径
	filename := fmt.Sprintf("internal/data/nvd-data/versions/%s-versions.json", component)

	// 如果文件不存在，尝试使用总文件
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		filename = "internal/data/nvd-data/versions/all-container-versions.json"
	}

	// 读取文件
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("警告: 无法打开文件 %s: %v", filename, err)
		return nil
	}

	var cves CVEs
	err = json.Unmarshal(content, &cves)
	if err != nil {
		log.Printf("警告: JSON 解析失败: %v", err)
		return nil
	}

	// 过滤出当前组件的CVE
	var componentCVEs []CVE
	for _, cve := range cves {
		if strings.ToLower(cve.Technology) == strings.ToLower(component) {
			componentCVEs = append(componentCVEs, cve)
		}
	}

	// 匹配版本号
	var matches []CVE
	for _, cve := range componentCVEs {
		if isVersionMatched(version, cve) {
			matches = append(matches, cve)
		}
	}

	return matches
}

// 清理版本号，去除前缀和后缀
func cleanVersion(version string) string {
	// 去除前缀如 "v" 或 "version "
	version = regexp.MustCompile(`^[vV]`).ReplaceAllString(version, "")

	// 提取语义化版本号 (x.y.z)
	re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1]
	}

	// 如果没有完整的语义化版本，尝试提取 x.y 格式
	re = regexp.MustCompile(`(\d+\.\d+)`)
	matches = re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1]
	}

	return version
}

// 判断版本是否匹配CVE
func isVersionMatched(version string, cve CVE) bool {
	// 1. 直接版本匹配
	if cleanVersion(cve.Version) == version {
		return true
	}

	// 2. 版本范围匹配
	if cve.VersionRange != nil {
		// 实现版本范围比较
		// 这里需要比较复杂的语义化版本比较逻辑
		// 简化实现：检查版本是否在范围内
		if isVersionInRange(version, cve.VersionRange) {
			return true
		}
	}

	// 3. 版本前缀匹配 (如果CVE版本是2.0，匹配2.0.x的所有版本)
	if strings.HasPrefix(version, cve.Version+".") {
		return true
	}

	return false
}

// 检查版本是否在范围内
func isVersionInRange(version string, vRange *VersionRange) bool {
	// 这里应该实现完整的语义化版本比较
	// 简化实现，仅作示例

	// 如果没有范围信息，无法确定
	if vRange.StartIncluding == "" && vRange.StartExcluding == "" &&
		vRange.EndIncluding == "" && vRange.EndExcluding == "" {
		return false
	}

	// 版本字符串比较（简单实现，实际应该使用语义化版本比较库）
	if vRange.StartIncluding != "" && compareVersions(version, vRange.StartIncluding) < 0 {
		return false
	}

	if vRange.StartExcluding != "" && compareVersions(version, vRange.StartExcluding) <= 0 {
		return false
	}

	if vRange.EndIncluding != "" && compareVersions(version, vRange.EndIncluding) > 0 {
		return false
	}

	if vRange.EndExcluding != "" && compareVersions(version, vRange.EndExcluding) >= 0 {
		return false
	}

	return true
}

// 简单的版本比较函数
func compareVersions(v1, v2 string) int {
	// 将版本号分割为部分
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// 比较每个部分
	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		// 尝试将部分转换为整数进行比较
		var num1, num2 int
		fmt.Sscanf(parts1[i], "%d", &num1)
		fmt.Sscanf(parts2[i], "%d", &num2)

		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}

	// 如果前面部分相同，较长的版本号较大
	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}

	return 0 // 版本相同
}
