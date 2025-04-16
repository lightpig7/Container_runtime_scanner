package model

import (
	"fmt"
	"log"
	"strings"
)

// AnalyzeAttackGraph 分析攻击图并建立攻击边
// 此函数通过检查每个节点的状态和关系，创建可能的攻击路径（边）
func AnalyzeAttackGraph(graph *StateAttackGraph, clusterInfo *ClusterInfo) error {
	log.Println("开始分析攻击图并建立攻击路径...")

	// 1. 创建互联网入口点节点（如果不存在）
	internetNodeID := "internet"
	if _, exists := graph.Nodes[internetNodeID]; !exists {
		internetNode := &StateNode{
			ID:        internetNodeID,
			Host:      "external-network",
			Service:   "internet",
			RiskScore: 0.0,
		}
		graph.AddNode(internetNode)
	}

	// 2. 分析API Server的攻击路径
	analyzeAPIServerAttackPaths(graph, clusterInfo)

	// 3. 分析暴露的服务的攻击路径
	analyzeExposedServicesAttackPaths(graph, clusterInfo)

	// 4. 分析特权容器的攻击路径
	analyzePrivilegedContainersAttackPaths(graph, clusterInfo)

	// 5. 分析节点间的攻击路径
	analyzeNodeToNodeAttackPaths(graph, clusterInfo)

	// 6. 分析高风险漏洞的攻击路径
	analyzeVulnerabilityAttackPaths(graph, clusterInfo)

	// 7. 分析容器逃逸路径
	analyzeContainerEscapePaths(graph, clusterInfo)

	// 8. 分析服务账户的权限提升
	analyzeServiceAccountEscalationPaths(graph, clusterInfo)

	log.Printf("攻击图分析完成，总共生成 %d 条攻击边。", len(graph.Edges))
	return nil
}

// analyzeAPIServerAttackPaths 分析API Server相关的攻击路径
func analyzeAPIServerAttackPaths(graph *StateAttackGraph, clusterInfo *ClusterInfo) {
	// 获取API Server节点
	apiServerNode, exists := graph.Nodes["api-server"]
	if !exists {
		log.Println("警告: API Server节点不存在，跳过相关攻击路径分析")
		return
	}

	// 获取互联网节点
	internetNode, exists := graph.Nodes["internet"]
	if !exists {
		log.Println("警告: 互联网节点不存在，跳过从互联网到API Server的攻击路径分析")
		return
	}

	// 检查API Server是否对外暴露
	externallyExposed, ok := apiServerNode.Context["externallyExposed"].(bool)
	if ok && externallyExposed {
		// 创建从互联网到API Server的攻击边
		edge := &AttackEdge{
			ID:     fmt.Sprintf("edge-%s-to-%s", internetNode.ID, apiServerNode.ID),
			From:   internetNode,
			To:     apiServerNode,
			Action: "通过互联网访问对外暴露的API Server",
			Prerequisites: []string{
				"发现API Server端点",
				"有效的认证凭据或利用认证漏洞",
			},
		}
		graph.AddEdge(edge)

		// 检查是否开启了不安全端口
		insecurePort, ok := apiServerNode.Context["insecurePort"].(bool)
		if ok && insecurePort {
			// 创建从互联网到不安全API Server的低难度攻击边
			edge := &AttackEdge{
				ID:     fmt.Sprintf("edge-%s-to-%s-insecure", internetNode.ID, apiServerNode.ID),
				From:   internetNode,
				To:     apiServerNode,
				Action: "通过互联网访问API Server的不安全端口",
				Prerequisites: []string{
					"发现API Server不安全端口",
				},
			}
			graph.AddEdge(edge)
		}
	}

	// 分析API Server与控制平面组件的关系
	// 为简化示例，假设控制平面组件作为Pod存在
	// 实际应用中可能需要更复杂的逻辑
	for _, node := range graph.Nodes {
		if strings.HasPrefix(node.ID, "pod-") &&
			(strings.Contains(node.Host, "kube-system") ||
				strings.Contains(node.Host, "control-plane")) {

			// 检查是否为控制平面组件
			isControlPlane := false
			for _, container := range getPodContainers(node.ID, clusterInfo) {
				if isControlPlaneComponent(container.Name) {
					isControlPlane = true
					break
				}
			}

			if isControlPlane {
				// 创建从API Server到控制平面组件的边
				edge := &AttackEdge{
					ID:     fmt.Sprintf("edge-%s-to-%s", apiServerNode.ID, node.ID),
					From:   apiServerNode,
					To:     node,
					Action: "通过API Server访问控制平面组件",
					Prerequisites: []string{
						"API Server访问权限",
						"控制平面组件的凭据",
					},
				}
				graph.AddEdge(edge)
			}
		}
	}
}

// analyzeExposedServicesAttackPaths 分析暴露的服务的攻击路径
func analyzeExposedServicesAttackPaths(graph *StateAttackGraph, clusterInfo *ClusterInfo) {
	// 获取互联网节点
	internetNode, exists := graph.Nodes["internet"]
	if !exists {
		log.Println("警告: 互联网节点不存在，跳过从互联网到服务的攻击路径分析")
		return
	}

	// 遍历所有服务节点
	for _, node := range graph.Nodes {
		if strings.HasPrefix(node.ID, "svc-") {
			// 检查服务是否对外暴露
			externallyExposed, ok := node.Context["externallyExposed"].(bool)
			if ok && externallyExposed {
				// 创建从互联网到服务的攻击边
				edge := &AttackEdge{
					ID:     fmt.Sprintf("edge-%s-to-%s", internetNode.ID, node.ID),
					From:   internetNode,
					To:     node,
					Action: "通过互联网访问对外暴露的服务",
					Prerequisites: []string{
						"发现服务端点",
					},
				}
				graph.AddEdge(edge)

				// 查找并连接该服务到其对应的Pod
				connectServiceToPods(graph, node, clusterInfo)
			}
		}
	}
}

// connectServiceToPods 连接服务到相关的Pod
func connectServiceToPods(graph *StateAttackGraph, serviceNode *StateNode, clusterInfo *ClusterInfo) {
	// 解析服务命名空间和名称
	parts := strings.Split(serviceNode.ID, "-")
	if len(parts) < 3 {
		return
	}

	serviceNamespace := parts[1]
	serviceName := strings.Join(parts[2:], "-")

	// 从clusterInfo中获取服务信息
	var serviceInfo *ServiceInfo
	for i := range clusterInfo.Services {
		if clusterInfo.Services[i].Name == serviceName &&
			clusterInfo.Services[i].Namespace == serviceNamespace {
			serviceInfo = &clusterInfo.Services[i]
			break
		}
	}

	if serviceInfo == nil {
		return
	}

	// 遍历所有Pod，查找与该服务关联的Pod
	for _, pod := range clusterInfo.Pods {
		if pod.Namespace == serviceNamespace && podMatchesService(pod.Labels, serviceInfo.Selector) {
			// 构造Pod节点ID
			podID := fmt.Sprintf("pod-%s-%s", pod.Namespace, pod.Name)

			// 检查Pod节点是否存在
			podNode, exists := graph.Nodes[podID]
			if exists {
				// 创建从服务到Pod的攻击边
				edge := &AttackEdge{
					ID:     fmt.Sprintf("edge-%s-to-%s", serviceNode.ID, podID),
					From:   serviceNode,
					To:     podNode,
					Action: "通过服务访问Pod",
					Prerequisites: []string{
						"服务访问权限",
					},
				}
				graph.AddEdge(edge)
			}
		}
	}
}

// analyzePrivilegedContainersAttackPaths 分析特权容器的攻击路径
func analyzePrivilegedContainersAttackPaths(graph *StateAttackGraph, clusterInfo *ClusterInfo) {
	// 遍历所有Pod节点
	for _, node := range graph.Nodes {
		if strings.HasPrefix(node.ID, "pod-") {
			// 检查Pod是否为特权Pod
			privileged, ok := node.Context["privileged"].(bool)
			if ok && privileged {
				// 获取Pod所在节点
				nodeName, ok := node.Context["nodeName"].(string)
				if ok {
					// 构造节点ID
					nodeID := "node-" + nodeName

					// 检查节点是否存在
					hostNode, exists := graph.Nodes[nodeID]
					if exists {
						// 创建从特权Pod到节点的攻击边
						edge := &AttackEdge{
							ID:     fmt.Sprintf("edge-%s-to-%s", node.ID, nodeID),
							From:   node,
							To:     hostNode,
							Action: "利用特权容器逃逸到宿主节点",
							Prerequisites: []string{
								"对特权容器的访问权限",
							},
						}
						graph.AddEdge(edge)
					}
				}
			}
		}
	}
}

// analyzeNodeToNodeAttackPaths 分析节点间的攻击路径
func analyzeNodeToNodeAttackPaths(graph *StateAttackGraph, clusterInfo *ClusterInfo) {
	// 获取所有节点ID
	nodeIDs := make([]string, 0)
	for id := range graph.Nodes {
		if strings.HasPrefix(id, "node-") {
			nodeIDs = append(nodeIDs, id)
		}
	}

	// 遍历所有节点对，建立可能的攻击路径
	for i := 0; i < len(nodeIDs); i++ {
		for j := 0; j < len(nodeIDs); j++ {
			if i != j { // 不考虑自身到自身的攻击
				fromNode := graph.Nodes[nodeIDs[i]]
				toNode := graph.Nodes[nodeIDs[j]]

				// 创建从一个节点到另一个节点的攻击边
				// 在实际应用中，可能需要考虑网络拓扑、节点间的连通性等
				edge := &AttackEdge{
					ID:     fmt.Sprintf("edge-%s-to-%s", fromNode.ID, toNode.ID),
					From:   fromNode,
					To:     toNode,
					Action: "通过网络从一个节点攻击另一个节点",
					Prerequisites: []string{
						"源节点的控制权",
						"节点间的网络连通性",
					},
				}
				graph.AddEdge(edge)
			}
		}
	}
}

// analyzeVulnerabilityAttackPaths 分析高风险漏洞的攻击路径
func analyzeVulnerabilityAttackPaths(graph *StateAttackGraph, clusterInfo *ClusterInfo) {
	// 遍历所有节点，寻找高风险漏洞
	//for _, node := range graph.Nodes {
	//	// 检查节点是否有漏洞
	//	if vulns, ok := node.Vulnerability.([]*Vulnerability); ok && len(vulns) > 0 {
	//		// 寻找高风险漏洞（CVSS分数大于7.0）
	//		hasHighRiskVuln := false
	//		for _, vuln := range vulns {
	//			if vuln.CvssScore >= 7.0 {
	//				hasHighRiskVuln = true
	//				break
	//			}
	//		}
	//
	//		if hasHighRiskVuln {
	//			// 对于有高风险漏洞的节点，建立从互联网到该节点的攻击路径
	//			// 在实际应用中，可能需要更精确的判断漏洞是否可从外部利用
	//			internetNode, exists := graph.Nodes["internet"]
	//			if exists {
	//				edge := &AttackEdge{
	//					ID:         fmt.Sprintf("edge-%s-to-%s-vuln", internetNode.ID, node.ID),
	//					From:       internetNode,
	//					To:         node,
	//					Action:     "利用高风险漏洞直接攻击节点",
	//					Difficulty: 3.0, // 中等难度
	//					Prerequisites: []string{
	//						"发现节点及其漏洞",
	//						"漏洞利用技术",
	//					},
	//				}
	//				graph.AddEdge(edge)
	//			}
	//		}
	//	}
	//}
}

// analyzeContainerEscapePaths 分析容器逃逸路径
func analyzeContainerEscapePaths(graph *StateAttackGraph, clusterInfo *ClusterInfo) {
	// 遍历所有Pod节点
	for _, node := range graph.Nodes {
		if strings.HasPrefix(node.ID, "pod-") {
			// 检查Pod是否使用主机网络、PID或IPC命名空间
			hostNetwork, okNetwork := node.Context["hostNetwork"].(bool)
			hostPID, okPID := node.Context["hostPID"].(bool)
			hostIPC, okIPC := node.Context["hostIPC"].(bool)

			if (okNetwork && hostNetwork) || (okPID && hostPID) || (okIPC && hostIPC) {
				// 获取Pod所在节点
				nodeName, ok := node.Context["nodeName"].(string)
				if ok {
					// 构造节点ID
					nodeID := "node-" + nodeName

					// 检查节点是否存在
					hostNode, exists := graph.Nodes[nodeID]
					if exists {
						// 创建从Pod到节点的攻击边
						action := "利用共享主机命名空间逃逸到宿主节点"
						if hostNetwork {
							action = "利用共享主机网络命名空间逃逸到宿主节点"
						} else if hostPID {
							action = "利用共享主机PID命名空间逃逸到宿主节点"
						} else if hostIPC {
							action = "利用共享主机IPC命名空间逃逸到宿主节点"
						}

						edge := &AttackEdge{
							ID:     fmt.Sprintf("edge-%s-to-%s-escape", node.ID, nodeID),
							From:   node,
							To:     hostNode,
							Action: action,
							Prerequisites: []string{
								"对Pod的访问权限",
								"利用共享命名空间的技术",
							},
						}
						graph.AddEdge(edge)
					}
				}
			}
		}
	}
}

// analyzeServiceAccountEscalationPaths 分析服务账户的权限提升
func analyzeServiceAccountEscalationPaths(graph *StateAttackGraph, clusterInfo *ClusterInfo) {
	// 获取API Server节点
	//apiServerNode, exists := graph.Nodes["api-server"]
	//if !exists {
	//	return
	//}

	// 遍历所有Pod节点
	//for _, node := range graph.Nodes {
	//	if strings.HasPrefix(node.ID, "pod-") {
	//		// 获取Pod使用的服务账户
	//		serviceAccount, ok := node.Service.(string)
	//		if ok && serviceAccount != "default" && serviceAccount != "" {
	//			// 创建从Pod到API Server的攻击边，代表使用服务账户访问API Server
	//			edge := &AttackEdge{
	//				ID:         fmt.Sprintf("edge-%s-to-%s-sa", node.ID, apiServerNode.ID),
	//				From:       node,
	//				To:         apiServerNode,
	//				Action:     fmt.Sprintf("利用服务账户 %s 访问API Server", serviceAccount),
	//				Difficulty: 2.0, // 中低难度
	//				Prerequisites: []string{
	//					"对Pod的访问权限",
	//					"服务账户令牌的访问权限",
	//				},
	//			}
	//			graph.AddEdge(edge)
	//		}
	//	}
	//}
}

// getPodContainers 获取Pod中的容器信息
func getPodContainers(podID string, clusterInfo *ClusterInfo) []ContainerInfo {
	// 解析Pod命名空间和名称
	parts := strings.Split(podID, "-")
	if len(parts) < 3 {
		return nil
	}

	podNamespace := parts[1]
	podName := strings.Join(parts[2:], "-")

	// 查找对应的Pod
	for _, pod := range clusterInfo.Pods {
		if pod.Name == podName && pod.Namespace == podNamespace {
			return pod.Containers
		}
	}

	return nil
}

// isControlPlaneComponent 判断是否为控制平面组件
func isControlPlaneComponent(containerName string) bool {
	controlPlaneKeywords := []string{
		"kube-apiserver",
		"kube-scheduler",
		"kube-controller-manager",
		"etcd",
		"cloud-controller-manager",
	}

	for _, keyword := range controlPlaneKeywords {
		if strings.Contains(containerName, keyword) {
			return true
		}
	}

	return false
}
