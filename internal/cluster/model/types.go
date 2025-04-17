package model

import (
	"fmt"
	"time"
)

// ScanOptions 定义扫描选项
type ScanOptions struct {
	SkipNamespaces []string // 要跳过的命名空间
	EnableVulnScan bool     // 是否启用漏洞扫描
}

// StateNode 表示攻击图中的状态节点
type StateNode struct {
	ID            string                 // 节点唯一标识
	Host          string                 // 容器或宿主节点标识
	Service       string                 // 涉及的服务或进程
	Vulnerability []*Vulnerability       // 该状态下的漏洞
	Context       map[string]interface{} // 其他关键因素
	RiskScore     float64                // 风险评分
}

// Vulnerability 表示安全漏洞信息
type Vulnerability struct {
	ID          string // 漏洞ID
	Name        string // 漏洞名称
	Type        string // 类型
	Severity    string
	CvssScore   float64
	ContainerID string
}

// AttackEdge 表示攻击行为(状态转移)
type AttackEdge struct {
	ID            string     // 边的唯一标识
	From          *StateNode // 源状态
	To            *StateNode // 目标状态
	Action        string     // 攻击行为描述
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
		fmt.Printf("  步骤 %d: %s (难度: %.2f)\n", i+1, edge.Action)
		fmt.Printf("    → %s (%s)\n", edge.To.ID, edge.To.Host)
	}
	fmt.Printf("总风险值: %.2f\n", p.TotalRisk)
}

// ClusterInfo 存储集群扫描结果
type ClusterInfo struct {
	Nodes            []NodeInfo
	Pods             []PodInfo
	Services         []ServiceInfo
	Deployments      []DeploymentInfo
	NetworkPolicies  []NetworkPolicyInfo
	ServiceAccounts  []ServiceAccountInfo
	SecurityIssues   []SecurityIssue
	ClusterVersion   string
	ScanTime         time.Time
	ScanDuration     time.Duration
	OverallRiskScore float64
	CriticalVulns    int
	HighVulns        int
	MediumVulns      int
	LowVulns         int
	APIServer        APIServerInfo
}
type APIServerInfo struct {
	Endpoint                string
	Version                 string
	AuthModes               []string
	InsecurePort            bool
	EnabledAdmissionPlugins []string
	ExternallyExposed       bool
	ExternalProtocol        string
	ExternalPort            int32
	ControlPlaneComponents  []ControlPlaneComponentInfo
	Vulnerabilities         []*Vulnerability
}
type ControlPlaneComponentInfo struct {
	Name       string
	Version    string
	Running    bool
	PodName    string
	Port       int32
	AuthMethod string
}

// SecurityIssue 存储安全问题信息
type SecurityIssue struct {
	ResourceType string  // 资源类型（Node、Pod、Service等）
	ResourceName string  // 资源名称
	Namespace    string  // 命名空间
	Issue        string  // 问题描述
	Severity     string  // 严重性（Critical、High、Medium、Low）
	RiskScore    float64 // 风险评分
	Remediation  string  // 修复建议
}

// NodeInfo 存储节点信息
type NodeInfo struct {
	Name             string
	Role             string
	Labels           map[string]string
	Taints           []string
	Vulns            []*Vulnerability
	KubeletVersion   string
	OSImage          string
	KernelVersion    string
	ContainerRuntime string
	IPAddress        string
	SecurityIssues   []string
	CPUPressure      bool
	MemoryPressure   bool
	DiskPressure     bool
	Ready            bool
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
	Privileged     bool
	HostPID        bool
	HostIPC        bool
	HostNetwork    bool
	SecurityIssues []string
	Containers     []ContainerInfo
	Status         string
	CreationTime   time.Time
}

// ContainerInfo 存储容器信息
type ContainerInfo struct {
	Name            string
	Image           string
	ImagePullPolicy string
	Ports           []int32
	VolumeMounts    []string
	SecurityIssues  []string
}

// ServiceInfo 存储服务信息
type ServiceInfo struct {
	Name                string
	Namespace           string
	Type                string
	Selector            map[string]string
	ClusterIP           string
	ExternalIPs         []string
	ServicePorts        []ServicePortInfo
	SecurityIssues      []string
	IsExternallyExposed bool
	CreationTime        time.Time
	Annotations         map[string]string
}

// ServicePortInfo 存储服务端口信息
type ServicePortInfo struct {
	Name       string
	Protocol   string
	Port       int32
	TargetPort string
	NodePort   int32
}

// DeploymentInfo 存储部署信息
type DeploymentInfo struct {
	Name              string
	Namespace         string
	Replicas          int32
	AvailableReplicas int32
	Selector          map[string]string
	Strategy          string
	CreationTime      time.Time
	ServiceAccount    string
	Labels            map[string]string
	Annotations       map[string]string
	Containers        []string
	Images            []string
	SecurityIssues    []string
}

// NetworkPolicyInfo 存储网络策略信息
type NetworkPolicyInfo struct {
	Name         string
	Namespace    string
	PodSelector  map[string]string
	CreationTime time.Time
}

// ServiceAccountInfo 存储服务账户信息
type ServiceAccountInfo struct {
	Name           string
	Namespace      string
	CreationTime   time.Time
	Secrets        []string
	AutomountToken bool
}

// Permission 表示权限项
type Permission struct {
	Resource     string
	ResourceName string
	Verb         string
}

// AnalysisResults 存储分析结果
type AnalysisResults struct {
	CriticalPaths   []*Path      // 关键攻击路径
	CriticalNodes   []*StateNode // 关键风险节点
	RiskScore       float64      // 整体风险评分
	Recommendations []string     // 安全建议
}
