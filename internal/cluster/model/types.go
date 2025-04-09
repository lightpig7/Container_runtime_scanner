// model/types.go

package model

import "fmt"

// StateNode 表示攻击图中的状态节点
type StateNode struct {
	ID            string                 // 节点唯一标识
	Host          string                 // 容器或宿主节点标识
	Service       string                 // 涉及的服务或进程
	Vulnerability *Vulnerability         // 该状态下的漏洞
	Context       map[string]interface{} // 其他关键因素(x)
	RiskScore     float64                // 风险评分
}

// Vulnerability 表示安全漏洞信息
type Vulnerability struct {
	ID          string  // 漏洞ID
	Name        string  // 漏洞名称
	Description string  // 描述
	CVE         string  // CVE编号
	Severity    float64 // 严重性评分 (0-10)
}

// AttackEdge 表示攻击行为(状态转移)
type AttackEdge struct {
	ID            string     // 边的唯一标识
	From          *StateNode // 源状态
	To            *StateNode // 目标状态
	Action        string     // 攻击行为描述
	Difficulty    float64    // 难度系数 (0-1, 1最难)
	Prerequisites []string   // 前置条件
}

// Path 表示一条攻击路径
type Path struct {
	Edges     []*AttackEdge // 路径上的边
	TotalRisk float64       // 总体风险值
}

// Print 打印路径详情
func (p *Path) Print() {
	if len(p.Edges) == 0 {
		return
	}

	fmt.Printf("起点: %s (%s)\n", p.Edges[0].From.ID, p.Edges[0].From.Host)
	for i, edge := range p.Edges {
		fmt.Printf("  步骤 %d: %s (难度: %.2f)\n", i+1, edge.Action, edge.Difficulty)
		fmt.Printf("    → %s (%s)\n", edge.To.ID, edge.To.Host)
	}
	fmt.Printf("总风险值: %.2f\n", p.TotalRisk)
}

// ClusterInfo 存储集群扫描结果
type ClusterInfo struct {
	Nodes       []NodeInfo
	Pods        []PodInfo
	Services    []ServiceInfo
	Deployments []DeploymentInfo
}

// NodeInfo 存储节点信息
type NodeInfo struct {
	Name   string
	Role   string
	Labels map[string]string
	Taints []string
	Vulns  []*Vulnerability
}

// PodInfo 存储Pod信息
type PodInfo struct {
	Name           string
	Namespace      string
	NodeName       string
	Images         []string
	Labels         map[string]string
	ServiceAccount string
	Vulns          []*Vulnerability
}

// ServiceInfo 存储服务信息
type ServiceInfo struct {
	Name      string
	Namespace string
	Type      string
	Selector  map[string]string
	Ports     []int32
}

// DeploymentInfo 存储部署信息
type DeploymentInfo struct {
	Name      string
	Namespace string
	Replicas  int32
	Selector  map[string]string
}

// AnalysisResults 存储分析结果
type AnalysisResults struct {
	CriticalPaths []*Path      // 关键攻击路径
	CriticalNodes []*StateNode // 关键风险节点
}
