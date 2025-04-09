// model/graph.go

package model

import (
	"sort"
)

// StateAttackGraph 表示状态攻击图
type StateAttackGraph struct {
	Nodes map[string]*StateNode // 节点集合，以ID为键
	Edges []*AttackEdge         // 边集合
}

// NewStateAttackGraph 创建新的状态攻击图
func NewStateAttackGraph() *StateAttackGraph {
	return &StateAttackGraph{
		Nodes: make(map[string]*StateNode),
		Edges: make([]*AttackEdge, 0),
	}
}

// AddNode 添加状态节点
func (g *StateAttackGraph) AddNode(node *StateNode) {
	g.Nodes[node.ID] = node
}

// AddEdge 添加攻击边
func (g *StateAttackGraph) AddEdge(edge *AttackEdge) {
	g.Edges = append(g.Edges, edge)
}

// BuildFromClusterInfo 从集群信息构建攻击图
func (g *StateAttackGraph) BuildFromClusterInfo(info *ClusterInfo) error {
	// 为演示目的，我们创建一些示例节点和边

	// 1. 先创建节点 - 在实际应用中，这些会基于集群信息动态生成

	// 示例: 暴露的Pod节点
	exposedPod := &StateNode{
		ID:      "pod-frontend",
		Host:    "pod/default/frontend",
		Service: "nginx",
		Vulnerability: &Vulnerability{
			ID:          "CVE-2021-12345",
			Name:        "Nginx配置错误",
			Description: "Nginx配置不当导致信息泄露",
			CVE:         "CVE-2021-12345",
			Severity:    5.5,
		},
		Context: map[string]interface{}{
			"exposed": true,
			"port":    80,
		},
		RiskScore: 6.0,
	}
	g.AddNode(exposedPod)

	// 宿主机节点
	hostNode := &StateNode{
		ID:      "node-worker1",
		Host:    "node/worker1",
		Service: "kubelet",
		Vulnerability: &Vulnerability{
			ID:          "CVE-2020-67890",
			Name:        "容器逃逸漏洞",
			Description: "特权容器可能导致宿主机逃逸",
			CVE:         "CVE-2020-67890",
			Severity:    8.0,
		},
		Context: map[string]interface{}{
			"privileged_containers": true,
		},
		RiskScore: 7.5,
	}
	g.AddNode(hostNode)

	// API服务器节点
	apiServer := &StateNode{
		ID:      "kube-apiserver",
		Host:    "node/master",
		Service: "kube-apiserver",
		Vulnerability: &Vulnerability{
			ID:          "RBAC-MISCONFIGURATION",
			Name:        "RBAC权限过大",
			Description: "服务账户权限配置不当",
			CVE:         "",
			Severity:    7.0,
		},
		Context: map[string]interface{}{
			"serviceaccount": "default",
			"permissions":    "cluster-admin",
		},
		RiskScore: 8.0,
	}
	g.AddNode(apiServer)

	// 2. 创建攻击边

	// Pod到宿主机的攻击路径
	edgePodToHost := &AttackEdge{
		ID:            "edge-pod-to-host",
		From:          exposedPod,
		To:            hostNode,
		Action:        "容器逃逸攻击",
		Difficulty:    0.6,
		Prerequisites: []string{"privileged_containers"},
	}
	g.AddEdge(edgePodToHost)

	// 宿主机到API服务器的攻击路径
	edgeHostToAPI := &AttackEdge{
		ID:            "edge-host-to-api",
		From:          hostNode,
		To:            apiServer,
		Action:        "凭据窃取并提权",
		Difficulty:    0.7,
		Prerequisites: []string{"kubelet_credentials"},
	}
	g.AddEdge(edgeHostToAPI)

	return nil
}

// AnalyzePaths 分析攻击路径
func (g *StateAttackGraph) AnalyzePaths() *AnalysisResults {
	results := &AnalysisResults{
		CriticalPaths: make([]*Path, 0),
		CriticalNodes: make([]*StateNode, 0),
	}

	// 简单起见，我们找出所有可能的路径
	// 在真实系统中，这里需要使用图算法如DFS或BFS

	// 找出所有入口点 (没有入边的节点)
	entryPoints := g.findEntryPoints()

	// 对于每个入口点，找出所有可能的路径
	for _, entry := range entryPoints {
		paths := g.findAllPathsFromNode(entry, nil, make(map[string]bool))
		for _, path := range paths {
			// 计算路径风险值
			path.TotalRisk = g.calculatePathRisk(path)
			results.CriticalPaths = append(results.CriticalPaths, path)
		}
	}

	// 按风险值排序路径
	sort.Slice(results.CriticalPaths, func(i, j int) bool {
		return results.CriticalPaths[i].TotalRisk > results.CriticalPaths[j].TotalRisk
	})

	// 只保留风险最高的5条路径
	if len(results.CriticalPaths) > 5 {
		results.CriticalPaths = results.CriticalPaths[:5]
	}

	// 找出关键节点 (风险评分最高的节点)
	nodeSlice := make([]*StateNode, 0, len(g.Nodes))
	for _, node := range g.Nodes {
		nodeSlice = append(nodeSlice, node)
	}

	sort.Slice(nodeSlice, func(i, j int) bool {
		return nodeSlice[i].RiskScore > nodeSlice[j].RiskScore
	})

	// 选取风险最高的几个节点
	count := min(5, len(nodeSlice))
	results.CriticalNodes = nodeSlice[:count]

	return results
}

// findEntryPoints 查找图中的入口点
func (g *StateAttackGraph) findEntryPoints() []*StateNode {
	entryPoints := make([]*StateNode, 0)
	incomingEdges := make(map[string]int)

	// 计算每个节点的入边数量
	for _, edge := range g.Edges {
		incomingEdges[edge.To.ID]++
	}

	// 入边数为0的节点是入口点
	for id, node := range g.Nodes {
		if incomingEdges[id] == 0 {
			entryPoints = append(entryPoints, node)
		}
	}

	return entryPoints
}

// findAllPathsFromNode 使用DFS查找从给定节点出发的所有路径
func (g *StateAttackGraph) findAllPathsFromNode(
	node *StateNode,
	currentPath *Path,
	visited map[string]bool,
) []*Path {
	// 标记当前节点为已访问
	visited[node.ID] = true

	// 如果当前路径为空，创建一个新路径
	if currentPath == nil {
		currentPath = &Path{
			Edges:     make([]*AttackEdge, 0),
			TotalRisk: 0,
		}
	}

	// 查找从当前节点出发的所有边
	outEdges := make([]*AttackEdge, 0)
	for _, edge := range g.Edges {
		if edge.From.ID == node.ID && !visited[edge.To.ID] {
			outEdges = append(outEdges, edge)
		}
	}

	// 如果没有出边，说明是终点，返回当前路径
	if len(outEdges) == 0 {
		return []*Path{currentPath}
	}

	// 否则，继续DFS
	allPaths := make([]*Path, 0)
	for _, edge := range outEdges {
		// 创建新路径以避免修改当前路径
		newPath := &Path{
			Edges: append(append([]*AttackEdge{}, currentPath.Edges...), edge),
		}

		// 递归查找从目标节点出发的所有路径
		newVisited := make(map[string]bool)
		for k, v := range visited {
			newVisited[k] = v
		}

		subPaths := g.findAllPathsFromNode(edge.To, newPath, newVisited)
		allPaths = append(allPaths, subPaths...)
	}

	return allPaths
}

// calculatePathRisk 计算路径的总风险值
func (g *StateAttackGraph) calculatePathRisk(path *Path) float64 {
	if len(path.Edges) == 0 {
		return 0
	}

	// 初始风险值为起点的风险评分
	risk := path.Edges[0].From.RiskScore

	// 累加每一步的风险
	for _, edge := range path.Edges {
		// 风险增量基于目标节点风险和攻击难度的反比
		// 难度越低，风险越高
		riskIncrement := edge.To.RiskScore * (1 - edge.Difficulty)
		risk += riskIncrement
	}

	// 考虑路径长度的调整因子
	// 路径越短，风险越高
	lengthFactor := 1.0 / float64(len(path.Edges))
	risk *= (1 + lengthFactor)

	return risk
}

// min returns the smaller of x or y.
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
