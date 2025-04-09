// scanner/scanner.go

package scanner

import (
	"context"
	"fmt"

	"Container_runtime_scanner/internal/cluster/model"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ScanCluster 扫描Kubernetes集群并收集安全相关信息
// 参数:
//   - ctx: 上下文，用于控制API请求的生命周期
//   - clientset: Kubernetes客户端集，用于与K8s API交互
//
// 返回:
//   - *model.ClusterInfo: 包含集群扫描结果的结构体
//   - error: 如有错误发生则返回
func ScanCluster(ctx context.Context, clientset *kubernetes.Clientset) (*model.ClusterInfo, error) {
	// 初始化集群信息结构体，为各类资源预分配空切片
	clusterInfo := &model.ClusterInfo{
		Nodes:       make([]model.NodeInfo, 0),       // 存储节点信息
		Pods:        make([]model.PodInfo, 0),        // 存储Pod信息
		Services:    make([]model.ServiceInfo, 0),    // 存储服务信息
		Deployments: make([]model.DeploymentInfo, 0), // 存储部署信息
	}

	// ==================== 节点扫描部分 ====================
	// 通过K8s API获取所有节点列表
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		// 如果获取节点列表失败，返回错误并包装错误信息
		return nil, fmt.Errorf("获取节点列表失败: %w", err)
	}

	// 遍历每个节点，收集节点信息
	for _, node := range nodes.Items {
		// 为当前节点创建信息结构体
		nodeInfo := model.NodeInfo{
			Name:   node.Name,                       // 节点名称
			Labels: node.Labels,                     // 节点标签
			Taints: make([]string, 0),               // 初始化污点信息
			Vulns:  make([]*model.Vulnerability, 0), // 初始化漏洞信息
		}

		// 根据节点标签确定节点角色
		if _, isMaster := node.Labels["node-role.kubernetes.io/master"]; isMaster {
			nodeInfo.Role = "master" // 主节点
		} else if _, isControl := node.Labels["node-role.kubernetes.io/control-plane"]; isControl {
			nodeInfo.Role = "control-plane" // 控制平面节点
		} else {
			nodeInfo.Role = "worker" // 工作节点
		}

		// 收集节点上的污点信息
		for _, taint := range node.Spec.Taints {
			nodeInfo.Taints = append(nodeInfo.Taints, taint.Key)
		}

		// 模拟漏洞扫描结果添加
		// 注意: 在实际生产系统中，应替换为真实的漏洞扫描逻辑
		if nodeInfo.Role == "worker" {
			// 为工作节点添加模拟的容器逃逸漏洞
			nodeInfo.Vulns = append(nodeInfo.Vulns, &model.Vulnerability{
				ID:          "CVE-2020-67890", // 漏洞ID
				Name:        "容器逃逸漏洞",         // 漏洞名称
				Description: "特权容器可能导致宿主机逃逸",  // 漏洞描述
				CVE:         "CVE-2020-67890", // CVE编号
				Severity:    8.0,              // 严重性评分
			})
		}

		// 将当前节点信息添加到集群信息中
		clusterInfo.Nodes = append(clusterInfo.Nodes, nodeInfo)
	}

	// ==================== Pod扫描部分 ====================
	// 获取所有命名空间中的Pod列表
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// 如果获取Pod列表失败，返回错误
		return nil, fmt.Errorf("获取Pod列表失败: %w", err)
	}

	// 遍历每个Pod，收集Pod信息
	for _, pod := range pods.Items {
		// 为当前Pod创建信息结构体
		podInfo := model.PodInfo{
			Name:           pod.Name,                        // Pod名称
			Namespace:      pod.Namespace,                   // Pod所在命名空间
			NodeName:       pod.Spec.NodeName,               // Pod运行的节点名称
			Images:         make([]string, 0),               // 初始化镜像列表
			Labels:         pod.Labels,                      // Pod标签
			ServiceAccount: pod.Spec.ServiceAccountName,     // Pod使用的服务账号
			Vulns:          make([]*model.Vulnerability, 0), // 初始化漏洞信息
		}

		// 收集Pod中所有容器使用的镜像
		for _, container := range pod.Spec.Containers {
			podInfo.Images = append(podInfo.Images, container.Image)
		}

		// 模拟镜像漏洞扫描
		// 注意: 实际系统中应该集成镜像漏洞扫描器
		//for _, image := range podInfo.Images {
		//	// 简单示例: 如果镜像是nginx，添加一个模拟漏洞
		//	if image == "nginx" {
		//		podInfo.Vulns = append(podInfo.Vulns, &model.Vulnerability{
		//			ID:          "CVE-2021-12345",  // 漏洞ID
		//			Name:        "Nginx配置错误",       // 漏洞名称
		//			Description: "Nginx配置不当导致信息泄露", // 漏洞描述
		//			CVE:         "CVE-2021-12345",  // CVE编号
		//			Severity:    5.5,               // 严重性评分
		//		})
		//	}
		//}

		// 将当前Pod信息添加到集群信息中
		clusterInfo.Pods = append(clusterInfo.Pods, podInfo)
	}

	// ==================== 服务扫描部分 ====================
	// 获取所有命名空间中的服务列表
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// 如果获取服务列表失败，返回错误
		return nil, fmt.Errorf("获取服务列表失败: %w", err)
	}

	// 遍历每个服务，收集服务信息
	for _, svc := range services.Items {
		// 为当前服务创建信息结构体
		svcInfo := model.ServiceInfo{
			Name:      svc.Name,              // 服务名称
			Namespace: svc.Namespace,         // 服务所在命名空间
			Type:      string(svc.Spec.Type), // 服务类型(ClusterIP, NodePort, LoadBalancer等)
			Selector:  svc.Spec.Selector,     // 服务选择器，用于匹配Pod
			Ports:     make([]int32, 0),      // 初始化端口列表
		}

		// 收集服务暴露的所有端口
		for _, port := range svc.Spec.Ports {
			svcInfo.Ports = append(svcInfo.Ports, port.Port)
		}

		// 将当前服务信息添加到集群信息中
		clusterInfo.Services = append(clusterInfo.Services, svcInfo)
	}

	// ==================== 部署扫描部分 ====================
	// 获取所有命名空间中的Deployment列表
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// 如果获取部署列表失败，返回错误
		return nil, fmt.Errorf("获取部署列表失败: %w", err)
	}

	// 遍历每个部署，收集部署信息
	for _, deploy := range deployments.Items {
		// 为当前部署创建信息结构体
		deployInfo := model.DeploymentInfo{
			Name:      deploy.Name,                      // 部署名称
			Namespace: deploy.Namespace,                 // 部署所在命名空间
			Replicas:  deploy.Status.Replicas,           // 当前副本数
			Selector:  deploy.Spec.Selector.MatchLabels, // 部署选择器，用于匹配Pod
		}

		// 将当前部署信息添加到集群信息中
		clusterInfo.Deployments = append(clusterInfo.Deployments, deployInfo)
	}

	// 输出扫描结果摘要
	fmt.Printf("扫描完成: 找到 %d 个节点, %d 个Pod, %d 个服务, %d 个部署\n",
		len(clusterInfo.Nodes), len(clusterInfo.Pods), len(clusterInfo.Services), len(clusterInfo.Deployments))

	// 返回完整的集群信息
	return clusterInfo, nil
}
