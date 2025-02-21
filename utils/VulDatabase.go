package utils

import (
	"encoding/json"
	"fmt"
	"os"
)

type Poc struct {
	PocName           string   `json:"name"`
	VulType           string   `json:"type"`
	CveID             string   `json:"cve"`
	Description       string   `json:"description"`
	AffectedVersions  []string `json:"versions_affected"`
	Severity          string   `json:"severity"`
	CvssScore         float64  `json:"cvss_score"`
	TestCmd           string   `json:"test_command"`
	ExpectedResult    string   `json:"expected_output"`
	ExploitationSteps []string `json:"steps_to_exploit"`
	VerifySteps       []string `json:"steps_to_verify"`
	Mitigation        string   `json:"mitigation"`
	References        []string `json:"references"`
}
type Data struct {
	Pocs []Poc `json:"vuls"`
}

// 读取 JSON 文件并解析
func ReadFile(filename string) ([]Poc, error) {
	// 读取文件
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件 %s: %v", filename, err)
	}

	// 解析 JSON
	var payload Data
	err = json.Unmarshal(content, &payload)
	if err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %v", err)
	}

	return payload.Pocs, nil
}
