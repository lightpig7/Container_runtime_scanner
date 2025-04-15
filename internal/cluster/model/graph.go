package model

// StateAttackGraph 表示状态攻击图
// 该结构体是整个攻击图的核心，包含所有节点和边
// 这种图结构用于模拟在Kubernetes集群中可能的攻击路径
type StateAttackGraph struct {
	Nodes map[string]*StateNode // 节点集合，以ID为键，便于快速查找特定节点
	Edges []*AttackEdge         // 边集合，表示从一个节点到另一个节点的攻击可能性
}

// NewStateAttackGraph 创建新的状态攻击图
// 返回一个初始化好的空图结构，准备添加节点和边
func NewStateAttackGraph() *StateAttackGraph {
	return &StateAttackGraph{
		Nodes: make(map[string]*StateNode), // 初始化节点映射
		Edges: make([]*AttackEdge, 0),      // 初始化空的边集合
	}
}

// AddNode 添加状态节点到图中
// 使用节点ID作为映射的键，便于后续通过ID快速查找节点
func (g *StateAttackGraph) AddNode(node *StateNode) {
	g.Nodes[node.ID] = node
}

// AddEdge 添加攻击边到图中
// 边表示从一个节点到另一个节点的攻击路径
func (g *StateAttackGraph) AddEdge(edge *AttackEdge) {
	g.Edges = append(g.Edges, edge)
}

// BuildFromClusterInfo 从集群信息构建攻击图
// 此方法是整个攻击图构建的核心，它基于Kubernetes集群的扫描信息，
// 创建相应的节点和边来表示集群中的安全风险和潜在攻击路径
// 参数:
//   - info: 包含集群扫描结果的ClusterInfo结构体
//
// 返回:
//   - error: 构建过程中如有错误则返回
func (g *StateAttackGraph) BuildFromClusterInfo(info *ClusterInfo) error {
	// 1. 处理集群中的节点（物理或虚拟机）信息
	// 每个Kubernetes节点都被表示为攻击图中的一个节点
	for _, node := range info.Nodes {
		// 为每个Kubernetes节点创建一个对应的图节点
		stateNode := &StateNode{
			ID:      "node-" + node.Name,   // 使用前缀+名称作为唯一标识
			Host:    "node/" + node.Name,   // 节点主机路径
			Service: node.ContainerRuntime, // 使用容器运行时作为服务标识
			Vulnerability: &Vulnerability{ // 节点相关的漏洞信息
				ID:       "NODE-VULN-" + node.Name, // 漏洞ID
				Name:     "cve",                    // 漏洞名称
				Severity: 0.0,                      // 不考虑风险评分，设置为0
			},
			Context: map[string]interface{}{ // 节点上下文信息，用于提供额外属性
				"role":           node.Role,           // 节点角色（主节点、工作节点等）
				"kubeletVersion": node.KubeletVersion, // kubelet版本
				"osImage":        node.OSImage,        // 操作系统镜像
			},
			RiskScore: 0.0, // 不考虑风险评分，设置为0
		}
		// 将创建的节点添加到图中
		g.AddNode(stateNode)
	}

	// 2. 处理Pod信息（容器组）
	// 每个Pod都被表示为攻击图中的一个节点
	for _, pod := range info.Pods {
		// 为每个Pod创建一个对应的图节点
		podNode := &StateNode{
			ID:      "pod-" + pod.Namespace + "-" + pod.Name, // 使用命名空间+名称作为唯一标识
			Host:    "pod/" + pod.Namespace + "/" + pod.Name, // Pod主机路径
			Service: pod.ServiceAccount,                      // 使用服务账户作为服务标识
			Vulnerability: &Vulnerability{ // Pod相关的漏洞信息
				ID:       "POD-VULN-" + pod.Name, // 漏洞ID
				Name:     "Podcve",               // 漏洞名称
				Severity: 0.0,                    // 不考虑风险评分，设置为0
			},
			Context: map[string]interface{}{ // Pod上下文信息
				"nodeName":    pod.NodeName,    // Pod所在节点
				"privileged":  pod.Privileged,  // 是否是特权容器
				"hostNetwork": pod.HostNetwork, // 是否使用主机网络
				"hostPID":     pod.HostPID,     // 是否共享主机PID命名空间
				"hostIPC":     pod.HostIPC,     // 是否共享主机IPC命名空间
			},
			RiskScore: 0.0, // 不考虑风险评分，设置为0
		}
		// 将创建的Pod节点添加到图中
		g.AddNode(podNode)

		// 特权容器检查：如果Pod是特权容器，创建从Pod到对应节点的攻击边
		// 特权容器可能导致容器逃逸，攻击宿主节点
		if pod.Privileged {
			// 构造节点ID，用于查找Pod所在的宿主节点
			nodeID := "node-" + pod.NodeName
			// 检查宿主节点是否存在于图中
			if nodeNode, exists := g.Nodes[nodeID]; exists {
				// 创建一条从Pod到宿主节点的攻击边
				edge := &AttackEdge{
					ID:            "edge-" + podNode.ID + "-to-" + nodeID, // 边的唯一标识
					From:          podNode,                                // 源节点（Pod）
					To:            nodeNode,                               // 目标节点（宿主节点）
					Action:        "Action",                               // 攻击行为描述
					Difficulty:    0.0,                                    // 不考虑难度系数，设置为0
					Prerequisites: []string{},                             // 无前置条件
				}
				// 将创建的攻击边添加到图中
				g.AddEdge(edge)
			}
		}
	}

	// 3. 处理服务信息（Service）
	// 每个服务都被表示为攻击图中的一个节点
	for _, svc := range info.Services {
		// 为每个服务创建一个对应的图节点
		svcNode := &StateNode{
			ID:      "svc-" + svc.Namespace + "-" + svc.Name,     // 使用命名空间+名称作为唯一标识
			Host:    "service/" + svc.Namespace + "/" + svc.Name, // 服务主机路径
			Service: svc.Type,                                    // 服务类型（ClusterIP, NodePort, LoadBalancer等）
			Vulnerability: &Vulnerability{ // 服务相关的漏洞信息
				ID:       "SVC-VULN-" + svc.Name, // 漏洞ID
				Name:     "service cvce",         // 漏洞名称
				Severity: 0.0,                    // 不考虑风险评分，设置为0
			},
			Context: map[string]interface{}{ // 服务上下文信息
				"externallyExposed": svc.IsExternallyExposed, // 是否对外暴露
				"clusterIP":         svc.ClusterIP,           // 集群内部IP
				"externalIPs":       svc.ExternalIPs,         // 外部IP列表
			},
			RiskScore: 0.0, // 不考虑风险评分，设置为0
		}
		// 将创建的服务节点添加到图中
		g.AddNode(svcNode)

		// 外部暴露检查：如果服务对外暴露（如NodePort或LoadBalancer类型），
		// 则可能提供额外的攻击入口点
		if svc.IsExternallyExposed {
			// 遍历所有Pod，查找与该服务关联的Pod
			for _, pod := range info.Pods {
				// 判断Pod是否与服务匹配：
				// 1. 在同一命名空间
				// 2. Pod标签匹配服务选择器
				if pod.Namespace == svc.Namespace && podMatchesService(pod.Labels, svc.Selector) {
					// 构造Pod节点ID
					podID := "pod-" + pod.Namespace + "-" + pod.Name
					// 检查Pod节点是否存在于图中
					if podNode, exists := g.Nodes[podID]; exists {
						// 创建一条从服务到Pod的攻击边
						edge := &AttackEdge{
							ID:            "edge-" + svcNode.ID + "-to-" + podID, // 边的唯一标识
							From:          svcNode,                               // 源节点（服务）
							To:            podNode,                               // 目标节点（Pod）
							Action:        "action",                              // 攻击行为描述
							Difficulty:    0.0,                                   // 不考虑难度系数，设置为0
							Prerequisites: []string{},                            // 无前置条件
						}
						// 将创建的攻击边添加到图中
						g.AddEdge(edge)
					}
				}
			}
		}
	}

	// 构建完成，返回nil表示无错误
	return nil
}

// podMatchesService 判断Pod是否匹配服务选择器
// 在Kubernetes中，服务通过标签选择器选择目标Pod，
// 此函数检查Pod的标签是否满足服务的选择条件
// 参数:
//   - podLabels: Pod的标签映射
//   - serviceSelector: 服务的标签选择器
//
// 返回:
//   - bool: 如果Pod匹配服务选择器则返回true，否则返回false
func podMatchesService(podLabels, serviceSelector map[string]string) bool {
	// 如果选择器为空，则不匹配任何Pod
	// 这是一个安全检查，实际上Kubernetes服务通常会有选择器
	if len(serviceSelector) == 0 {
		return false
	}

	// 检查服务选择器中的每个键值对
	// Pod必须包含选择器中所有的标签，且值相同才算匹配
	for key, value := range serviceSelector {
		// 从Pod标签中获取对应键的值
		podValue, exists := podLabels[key]
		// 如果键不存在或值不匹配，则Pod与服务不匹配
		if !exists || podValue != value {
			return false
		}
	}

	// 所有选择器标签都匹配，返回true
	return true
}
