package model

import "fmt"

type StateAttackGraph struct {
	Nodes map[string]*StateNode
	Edges []*AttackEdge
}

func NewStateAttackGraph() *StateAttackGraph {
	return &StateAttackGraph{
		Nodes: make(map[string]*StateNode),
		Edges: make([]*AttackEdge, 0),
	}
}

func (g *StateAttackGraph) AddNode(node *StateNode) {
	g.Nodes[node.ID] = node
}

func (g *StateAttackGraph) AddEdge(edge *AttackEdge) {
	g.Edges = append(g.Edges, edge)
}

func (g *StateAttackGraph) BuildFromClusterInfo(info *ClusterInfo) error {
	for _, node := range info.Nodes {
		fmt.Println("node.Role", node.Role)
		if node.Role == "master" {
			continue
		}
		// 创建节点对应的图节点
		stateNode := &StateNode{
			ID:            "node-" + node.Name,
			Host:          "node/" + node.Name,
			Service:       node.ContainerRuntime,
			Vulnerability: make([]*Vulnerability, 0),
			Context: map[string]interface{}{
				"role":           node.Role,
				"kubeletVersion": node.KubeletVersion,
				"osImage":        node.OSImage,
			},
			RiskScore: 0.0,
		}

		highestScore := 0.0
		for _, vuln := range node.Vulns {
			// 创建图漏洞结构
			graphVuln := &Vulnerability{
				ID:          vuln.ID,
				Name:        vuln.Name,
				Severity:    vuln.Severity,
				CvssScore:   vuln.CvssScore,
				ContainerID: vuln.ContainerID,
			}

			stateNode.Vulnerability = append(stateNode.Vulnerability, graphVuln)

			if vuln.CvssScore > highestScore {
				highestScore = vuln.CvssScore
			}
		}

		stateNode.RiskScore = highestScore

		g.AddNode(stateNode)
	}

	for _, pod := range info.Pods {
		podNode := &StateNode{
			ID:      "pod-" + pod.Namespace + "-" + pod.Name,
			Host:    "pod/" + pod.Namespace + "/" + pod.Name,
			Service: pod.ServiceAccount,
			Context: map[string]interface{}{
				"nodeName":    pod.NodeName,
				"privileged":  pod.Privileged,
				"hostNetwork": pod.HostNetwork,
				"hostPID":     pod.HostPID,
				"hostIPC":     pod.HostIPC,
			},
			RiskScore: 0.0,
		}
		g.AddNode(podNode)
	}

	for _, svc := range info.Services {
		svcNode := &StateNode{
			ID:      "svc-" + svc.Namespace + "-" + svc.Name,
			Host:    "service/" + svc.Namespace + "/" + svc.Name,
			Service: svc.Type,
			Context: map[string]interface{}{
				"externallyExposed": svc.IsExternallyExposed,
				"clusterIP":         svc.ClusterIP,
				"externalIPs":       svc.ExternalIPs,
			},
			RiskScore: 0.0,
		}
		g.AddNode(svcNode)
	}

	apiServerNode := &StateNode{
		ID:      "api-server",
		Host:    "kubernetes-apiserver",
		Service: "apiserver",
		Context: map[string]interface{}{
			"externallyExposed": info.APIServer.ExternallyExposed,       // 是否对外暴露
			"endpoint":          info.APIServer.Endpoint,                // API Server端点
			"authModes":         info.APIServer.AuthModes,               // 认证模式
			"insecurePort":      info.APIServer.InsecurePort,            // 是否开启不安全端口
			"admissionPlugins":  info.APIServer.EnabledAdmissionPlugins, // 启用的准入控制插件
			"version":           info.APIServer.Version,                 // Kubernetes版本
		},
		RiskScore: 0.0, // 初始风险评分设为0
	}
	g.AddNode(apiServerNode)

	internetNode := &StateNode{
		ID:      "internet",
		Host:    "external-network",
		Service: "internet",
		Context: map[string]interface{}{
			"description": "外部网络访问入口点",
		},
	}

	g.AddNode(internetNode)
	return nil
}

func podMatchesService(podLabels, serviceSelector map[string]string) bool {
	if len(serviceSelector) == 0 {
		return false
	}

	for key, value := range serviceSelector {
		podValue, exists := podLabels[key]
		if !exists || podValue != value {
			return false
		}
	}

	return true
}
