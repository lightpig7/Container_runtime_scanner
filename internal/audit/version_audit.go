package audit

import (
	"Container_runtime_scanner/internal/docker"
	"context"
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CVE 结构体，与JSON数据匹配
type CVE struct {
	CVEId            string   `json:"cveId"`
	Technology       string   `json:"technology"`
	AffectedVersions []string `json:"affectedVersions"`
	CVSSScore        float64  `json:"cvssScore"`
	Severity         string   `json:"severity"`
}

// MatchResult 存储匹配结果
type MatchResult struct {
	Component   string
	Version     string
	MatchedCVEs []CVE
}

func getContainerdVersionAPI() (string, error) {
	// 连接到 containerd
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return "", err
	}
	defer client.Close()

	// 获取版本信息
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	version, err := client.Version(ctx)
	if err != nil {
		return "", err
	}

	return version.Version, nil
}

// VersionMatch 检查已安装组件是否存在漏洞
func VersionMatch(logger *log.Logger) []MatchResult {
	// 获取Docker信息
	versionInfo := docker.GetInfo()

	// 存储所有匹配结果
	var results []MatchResult

	// 首先打印版本信息
	logger.Printf("Docker 版本: %s\n", versionInfo.DockerVersion)
	logger.Printf("API 版本: %s\n", versionInfo.APIVersion)
	logger.Printf("Go 版本: %s\n", versionInfo.GoVersion)
	logger.Printf("Git commit: %s\n", versionInfo.GitVersion)
	logger.Printf("操作系统: %s\n", versionInfo.OSVersion)
	logger.Printf("runc 版本: %s\n", versionInfo.RuncVersion)
	logger.Printf("内核版本: %s\n", versionInfo.KernelVersion)
	logger.Printf("containerd 版本: %s\n", versionInfo.ContainerVersion)
	a, err := getContainerdVersionAPI()
	fmt.Println("containerd", a, err)
	// 检查Docker版本
	dockerMatches := checkComponentVersion("docker", versionInfo.DockerVersion)
	// 从匹配结果中移除重复项
	//dockerMatches = removeDuplicateCVEs(dockerMatches)
	if len(dockerMatches) > 0 {
		results = append(results, MatchResult{
			Component:   "docker",
			Version:     versionInfo.DockerVersion,
			MatchedCVEs: dockerMatches,
		})
	}
	fmt.Println(results)
	// 检查containerd版本
	if versionInfo.ContainerVersion != "" {
		containerdMatches := checkComponentVersion("containerd", versionInfo.ContainerVersion)
		// 从匹配结果中移除重复项
		//containerdMatches = removeDuplicateCVEs(containerdMatches)
		if len(containerdMatches) > 0 {
			results = append(results, MatchResult{
				Component:   "containerd",
				Version:     versionInfo.ContainerVersion,
				MatchedCVEs: containerdMatches,
			})
		}
	}
	fmt.Println(results)
	// 检查runc版本
	if versionInfo.RuncVersion != "" {
		runcMatches := checkComponentVersion("runc", versionInfo.RuncVersion)
		// 从匹配结果中移除重复项
		//runcMatches = removeDuplicateCVEs(runcMatches)
		if len(runcMatches) > 0 {
			results = append(results, MatchResult{
				Component:   "runc",
				Version:     versionInfo.RuncVersion,
				MatchedCVEs: runcMatches,
			})
		}
	}
	fmt.Println(results)
	// 打印匹配结果摘要
	logger.Println("\n漏洞匹配结果:")
	fmt.Println(results)
	// 确保结果以一致的方式输出
	for _, result := range results {
		// 先打印组件的概要信息
		//logger.Printf("%s %s 有 %d 个匹配的CVE\n",
		//	result.Component, result.Version, len(result.MatchedCVEs))
		fmt.Printf("%s %s 有 %d 个匹配的CVE\n",
			result.Component, result.Version, len(result.MatchedCVEs))
		// 然后打印详细的CVE列表
		for _, cve := range result.MatchedCVEs {
			//logger.Printf("  - %s (CVSS: %.1f, %s)\n",
			//	cve.CVEId, cve.CVSSScore, cve.Severity)
			fmt.Printf("  - %s (CVSS: %.1f, %s)\n",
				cve.CVEId, cve.CVSSScore, cve.Severity)
		}
	}

	return results
}

// 检查特定组件版本是否存在漏洞
func checkComponentVersion(component, version string) []CVE {
	// 清理版本号
	version = cleanVersion(version)

	// 构建文件路径
	filename := fmt.Sprintf("internal/data/nvd-data/vulnerabilities/%s-vulnerabilities.json", component)

	// 如果组件特定文件不存在，尝试使用组合文件
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		filename = "internal/data/nvd-data/vulnerabilities/all-container-vulnerabilities.json"
	}

	// 读取文件
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("警告: 无法打开文件 %s: %v", filename, err)
		return nil
	}

	var cves []CVE
	err = json.Unmarshal(content, &cves)
	if err != nil {
		log.Printf("警告: JSON解析失败: %v", err)
		return nil
	}

	// 过滤当前组件的CVE
	var componentCVEs []CVE
	for _, cve := range cves {
		fmt.Println("cve.Technology,component", cve.Technology, component)
		if strings.ToLower(cve.Technology) == strings.ToLower(component) {
			fmt.Println("cve.Technology,component", cve.Technology, component)
			// 跳过空严重性或CVSS评分为0的CVE（可能是不完整数据）
			//if cve.Severity == "" || cve.CVSSScore == 0 {
			//	continue
			//}
			componentCVEs = append(componentCVEs, cve)
		}
	}

	// 匹配版本号
	var matches []CVE
	for _, cve := range componentCVEs {

		if isVersionAffected(version, cve) {
			fmt.Println("version, cve", version, cve)
			matches = append(matches, cve)
		}
	}

	return matches
}

// removeDuplicateCVEs 从列表中移除重复的CVE
func removeDuplicateCVEs(cves []CVE) []CVE {
	if len(cves) == 0 {
		return cves
	}

	// 使用map跟踪唯一CVE ID
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

// isVersionAffected 检查给定版本是否受CVE影响
func isVersionAffected(version string, cve CVE) bool {
	// 如果没有列出受影响版本，则跳过
	if len(cve.AffectedVersions) == 0 {
		return false
	}

	cleanedVersion := cleanVersion(version)
	fmt.Println("version, cve", version, cve)
	// 检查每个受影响版本
	for _, affectedVersion := range cve.AffectedVersions {
		// 处理特殊情况
		if affectedVersion == "-" || affectedVersion == "*" {
			// 保守处理，不自动匹配所有版本
			continue
		}
		fmt.Println("version, cve", version, cve)
		// 处理精确匹配
		cleanedAffectedVersion := cleanVersion(affectedVersion)
		if cleanedAffectedVersion == cleanedVersion {
			return true
		}

		// 对Docker和其他组件，我们需要更具体的版本匹配
		// 只有当版本部分完全相同时才匹配 - 不匹配部分版本
		versionParts := strings.Split(cleanedVersion, ".")
		affectedParts := strings.Split(cleanedAffectedVersion, ".")

		// 如果受影响版本比已安装版本有更多的具体版本部分，则跳过
		// 例如，如果已安装的是24.0，而受影响的是24.0.2，则不匹配
		if len(affectedParts) > len(versionParts) {
			continue
		}

		// 主版本必须匹配，否则跳过
		// 例如，如果已安装的是24.0.2，而受影响的是23.0或25.0，则不匹配
		if len(affectedParts) > 0 && len(versionParts) > 0 && affectedParts[0] != versionParts[0] {
			continue
		}

		// 只有当受影响版本是已安装版本的完整前缀时才匹配
		// 例如，如果已安装的是24.0.2，而受影响的是24.0，则视为匹配
		// 但如果已安装的是24.1.0，而受影响的是24.0，则不匹配
		isPrefix := true
		for i := 0; i < len(affectedParts); i++ {
			if i >= len(versionParts) || versionParts[i] != affectedParts[i] {
				isPrefix = false
				break
			}
		}

		if isPrefix {
			// 如果我们基于前缀匹配，确保版本实际上是有漏洞的
			// 例如，如果受影响版本是1.2，它应该匹配1.2.0但不匹配1.20.0
			if len(versionParts) > len(affectedParts) {
				// 只有当下一个版本部分是次要/补丁版本时才匹配（例如，1.2匹配1.2.3但不匹配1.20）
				if len(versionParts) > len(affectedParts) && len(versionParts[len(affectedParts)]) > 1 {
					// 如果下一部分超过一个数字，它可能是不同的版本
					// （例如，1.2与1.20）所以不匹配
					continue
				}
			}
			return true
		}
	}

	return false
}

// compareVersions 比较两个版本字符串
// 返回-1如果v1 < v2，0如果v1 == v2，1如果v1 > v2
func compareVersions(v1, v2 string) int {
	// 清理版本号
	v1 = cleanVersion(v1)
	v2 = cleanVersion(v2)

	// 将版本拆分为部分
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// 比较每个部分
	maxLength := len(parts1)
	if len(parts2) > maxLength {
		maxLength = len(parts2)
	}

	// 确保两个版本数组具有相同长度，用零填充
	for i := len(parts1); i < maxLength; i++ {
		parts1 = append(parts1, "0")
	}
	for i := len(parts2); i < maxLength; i++ {
		parts2 = append(parts2, "0")
	}

	// 比较每个部分
	for i := 0; i < maxLength; i++ {
		num1, err1 := strconv.Atoi(parts1[i])
		num2, err2 := strconv.Atoi(parts2[i])

		// 通过默认为0来处理解析错误
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

	return 0 // 版本完全相同
}

// cleanVersion 移除前缀并提取语义版本
func cleanVersion(version string) string {
	// 移除前缀，如"v"或"version"
	version = regexp.MustCompile(`^[vV]`).ReplaceAllString(version, "")

	// 如果版本包含非语义版本的元素（例如hash），只提取语义版本部分
	if strings.Contains(version, "-") || strings.Contains(version, "+") {
		parts := strings.Split(version, "-")
		version = parts[0]
	}

	// 提取语义版本(x.y.z)
	re := regexp.MustCompile(`(\d+(?:\.\d+){0,2})`)
	matches := re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1]
	}

	return version
}
