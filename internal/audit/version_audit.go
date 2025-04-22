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

	// 打印匹配结果摘要
	logger.Println("漏洞匹配结果:")
	logger.Println(results)
	// 确保结果以一致的方式输出
	for _, result := range results {
		// 先打印组件的概要信息
		logger.Printf("%s %s 有 %d 个匹配的CVE\n",
			result.Component, result.Version, len(result.MatchedCVEs))
		// 然后打印详细的CVE列表
		for _, cve := range result.MatchedCVEs {
			//logger.Printf("  - %s (CVSS: %.1f, %s)\n",
			//	cve.CVEId, cve.CVSSScore, cve.Severity)
			logger.Printf("  - %s (CVSS: %.1f, %s)\n",
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
		if strings.ToLower(cve.Technology) == strings.ToLower(component) {
			componentCVEs = append(componentCVEs, cve)
		}
	}

	// 匹配版本号
	var matches []CVE
	for _, cve := range componentCVEs {
		if isVersionAffected(version, cve) {
			matches = append(matches, cve)
		}
	}
	return matches
}

// isVersionAffected 检查给定版本是否受CVE影响
func isVersionAffected(version string, cve CVE) bool {
	// 如果没有列出受影响版本，则跳过
	if len(cve.AffectedVersions) == 0 {
		return false
	}

	for _, affectedVersion := range cve.AffectedVersions {
		// 处理特殊情况
		if affectedVersion == "-" || affectedVersion == "*" {
			// 保守处理，不自动匹配所有版本
			continue
		}

		// 处理精确匹配
		cleanedAffectedVersion := cleanVersion(affectedVersion)
		if cleanedAffectedVersion == version {
			return true
		}

		// 对Docker和其他组件，我们需要更具体的版本匹配
		// 只有当版本部分完全相同时才匹配 - 不匹配部分版本
		versionParts := strings.Split(version, ".")
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
			return true
		}
	}

	return false
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
