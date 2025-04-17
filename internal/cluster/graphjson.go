package cluster

import (
	"Container_runtime_scanner/internal/cluster/model"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// GraphJSON 表示攻击图的JSON结构
type GraphJSON struct {
	Nodes []NodeJSON `json:"nodes"`
	Edges []EdgeJSON `json:"edges"`
}

// NodeJSON 表示节点的JSON结构
type NodeJSON struct {
	ID              string                 `json:"id"`
	Label           string                 `json:"label"`
	Type            string                 `json:"type"`
	RiskScore       float64                `json:"riskScore"`
	Service         string                 `json:"service"`
	Host            string                 `json:"host"`
	Vulnerabilities []VulnJSON             `json:"vulnerabilities,omitempty"`
	Context         map[string]interface{} `json:"context,omitempty"`
}

// EdgeJSON 表示边的JSON结构
type EdgeJSON struct {
	ID            string   `json:"id"`
	Source        string   `json:"source"`
	Target        string   `json:"target"`
	Action        string   `json:"action"`
	Prerequisites []string `json:"prerequisites,omitempty"`
}

// VulnJSON 表示漏洞的JSON结构
type VulnJSON struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	CvssScore   float64 `json:"cvssScore"`
	ContainerID string  `json:"containerId,omitempty"`
}

// ExportToJSON 将攻击图导出为JSON文件
func ExportToJSON(graph *model.StateAttackGraph, filePath string) error {
	// 创建JSON结构
	graphJSON := GraphJSON{
		Nodes: make([]NodeJSON, 0, len(graph.Nodes)),
		Edges: make([]EdgeJSON, 0, len(graph.Edges)),
	}

	// 转换节点
	for id, node := range graph.Nodes {
		// 确定节点类型
		nodeType := getNodeType(id)

		// 转换漏洞
		vulns := make([]VulnJSON, 0, len(node.Vulnerability))
		for _, v := range node.Vulnerability {
			vulns = append(vulns, VulnJSON{
				ID:          v.ID,
				Name:        v.Name,
				Severity:    v.Severity,
				CvssScore:   v.CvssScore,
				ContainerID: v.ContainerID,
			})
		}

		// 创建节点JSON对象
		nodeJSON := NodeJSON{
			ID:              id,
			Label:           node.Host,
			Type:            nodeType,
			RiskScore:       node.RiskScore,
			Service:         node.Service,
			Host:            node.Host,
			Vulnerabilities: vulns,
			Context:         node.Context,
		}

		graphJSON.Nodes = append(graphJSON.Nodes, nodeJSON)
	}

	// 转换边
	for i, edge := range graph.Edges {
		edgeJSON := EdgeJSON{
			ID:            fmt.Sprintf("e%d", i),
			Source:        edge.From.ID,
			Target:        edge.To.ID,
			Action:        edge.Action,
			Prerequisites: edge.Prerequisites,
		}

		graphJSON.Edges = append(graphJSON.Edges, edgeJSON)
	}

	// 将JSON结构写入文件
	jsonData, err := json.MarshalIndent(graphJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON编码失败: %v", err)
	}

	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("写入JSON文件失败: %v", err)
	}

	return nil
}

// 确定节点类型
func getNodeType(nodeID string) string {
	if nodeID == "internet" {
		return "internet"
	} else if nodeID == "api-server" {
		return "apiserver"
	} else if strings.HasPrefix(nodeID, "node-") {
		return "node"
	} else if strings.HasPrefix(nodeID, "pod-") {
		return "pod"
	} else if strings.HasPrefix(nodeID, "svc-") {
		return "service"
	}
	return "other"
}
