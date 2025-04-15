package scanner

import (
	"Container_runtime_scanner/internal/cluster/controller"
	"Container_runtime_scanner/internal/pentest"
	"context"
	"fmt"
	"log"
	"time"

	"Container_runtime_scanner/internal/cluster/model"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ScanCluster 扫描Kubernetes集群并收集安全相关信息
// 参数:
//   - ctx: 上下文，用于控制API请求的生命周期
//   - clientset: Kubernetes客户端集，用于与K8s API交互
//   - options: 扫描选项，用于自定义扫描行为
//
// 返回:
//   - *model.ClusterInfo: 包含集群扫描结果的结构体
//   - error: 如有错误发生则返回
func ScanCluster(ctx context.Context, clientset *kubernetes.Clientset) (*model.ClusterInfo, error) {
	startTime := time.Now()
	log.Printf("开始扫描集群，时间: %s", startTime.Format("2006-01-02 15:04:05"))

	options := &model.ScanOptions{
		SkipNamespaces: []string{"kube-system", "kube-public", "kube-flannel"},
		EnableVulnScan: true,
	}

	// 初始化集群信息结构体，为各类资源预分配空切片
	clusterInfo := &model.ClusterInfo{
		Nodes:            make([]model.NodeInfo, 0),
		Pods:             make([]model.PodInfo, 0),
		Services:         make([]model.ServiceInfo, 0),
		Deployments:      make([]model.DeploymentInfo, 0),
		NetworkPolicies:  make([]model.NetworkPolicyInfo, 0),
		ServiceAccounts:  make([]model.ServiceAccountInfo, 0),
		SecurityIssues:   make([]model.SecurityIssue, 0),
		ClusterVersion:   "",
		ScanTime:         startTime,
		OverallRiskScore: 0,
		CriticalVulns:    0,
		HighVulns:        0,
		MediumVulns:      0,
		LowVulns:         0,
	}

	// ==================== 集群版本信息获取 ====================
	versionInfo, err := clientset.Discovery().ServerVersion()
	if err != nil {
		log.Printf("警告: 获取集群版本信息失败: %v", err)
	} else {
		clusterInfo.ClusterVersion = fmt.Sprintf("%s.%s", versionInfo.Major, versionInfo.Minor)
	}

	// ==================== 节点扫描部分 ====================
	// 通过K8s API获取所有节点列表
	nodes, err := controller.GetNodeList()
	if err != nil {
		// 如果获取节点列表失败，返回错误并包装错误信息
		return nil, fmt.Errorf("获取节点列表失败: %w", err)
	}

	// 遍历每个节点，收集节点信息
	for _, node := range nodes.Items {
		// 为当前节点创建信息结构体
		nodeInfo := model.NodeInfo{
			Name:             node.Name,
			Labels:           node.Labels,
			Taints:           make([]string, 0),
			Vulns:            make([]*model.Vulnerability, 0),
			KubeletVersion:   node.Status.NodeInfo.KubeletVersion,
			OSImage:          node.Status.NodeInfo.OSImage,
			KernelVersion:    node.Status.NodeInfo.KernelVersion,
			ContainerRuntime: node.Status.NodeInfo.ContainerRuntimeVersion,
			SecurityIssues:   make([]string, 0),
		}

		// 获取节点IP地址
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				nodeInfo.IPAddress = addr.Address
				break
			}
		}

		// 根据节点标签确定节点角色
		if _, isMaster := node.Labels["node-role.kubernetes.io/master"]; isMaster {
			nodeInfo.Role = "master" // 主节点
		} else if _, isControl := node.Labels["node-role.kubernetes.io/control-plane"]; isControl {
			nodeInfo.Role = "control-plane" // 控制平面节点
		} else {
			nodeInfo.Role = "worker" // 工作节点
		}

		// 收集节点上的污点信息，包含完整的污点表达式
		for _, taint := range node.Spec.Taints {
			nodeInfo.Taints = append(nodeInfo.Taints,
				fmt.Sprintf("%s=%s:%s", taint.Key, taint.Value, taint.Effect))
		}

		// 评估节点资源状态
		nodeInfo.CPUPressure = isNodeUnderPressure(node.Status.Conditions, "CPUPressure")
		nodeInfo.MemoryPressure = isNodeUnderPressure(node.Status.Conditions, "MemoryPressure")
		nodeInfo.DiskPressure = isNodeUnderPressure(node.Status.Conditions, "DiskPressure")

		// 检查节点是否就绪
		nodeInfo.Ready = isNodeReady(node.Status.Conditions)

		// 如果启用了漏洞扫描
		if options.EnableVulnScan && nodeInfo.Role != "master" {
			// 集成真实的漏洞扫描，这里应该与实际的漏洞扫描器集成
			containerVulnsMap, err := pentest.ScanNode(nodeInfo.IPAddress)
			if err != nil {
				log.Printf("节点 %s 漏洞扫描失败: %v", node.Name, err)
				// 添加模拟漏洞数据作为回退

			} else {
				for containerName, vulns := range containerVulnsMap {
					for _, v := range vulns {
						modelVuln := convertVulnerability(containerName, v)
						nodeInfo.Vulns = append(nodeInfo.Vulns, modelVuln)
					}
				}
			}
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
	fmt.Println("------------------pods----------------------", len(pods.Items))
	// 遍历每个Pod，收集Pod信息
	for _, pod := range pods.Items {
		// 跳过指定命名空间中的Pod
		if shouldSkipNamespace(pod.Namespace, options.SkipNamespaces) {
			continue
		}

		// 为当前Pod创建信息结构体
		podInfo := model.PodInfo{
			Name:           pod.Name,
			Namespace:      pod.Namespace,
			NodeName:       pod.Spec.NodeName,
			Images:         make([]string, 0),
			Labels:         pod.Labels,
			ServiceAccount: pod.Spec.ServiceAccountName,
			Vulns:          make([]*model.Vulnerability, 0),
			Privileged:     isPodPrivileged(&pod),
			HostPID:        pod.Spec.HostPID,
			HostIPC:        pod.Spec.HostIPC,
			HostNetwork:    pod.Spec.HostNetwork,
			SecurityIssues: make([]string, 0),
			Containers:     make([]model.ContainerInfo, 0),
			Status:         string(pod.Status.Phase),
			CreationTime:   pod.CreationTimestamp.Time,
		}

		// 检查Pod安全相关问题
		if podInfo.Privileged {
			podInfo.SecurityIssues = append(podInfo.SecurityIssues, "Pod包含特权容器")
		}
		if podInfo.HostPID {
			podInfo.SecurityIssues = append(podInfo.SecurityIssues, "Pod共享主机PID命名空间")
		}
		if podInfo.HostIPC {
			podInfo.SecurityIssues = append(podInfo.SecurityIssues, "Pod共享主机IPC命名空间")
		}
		if podInfo.HostNetwork {
			podInfo.SecurityIssues = append(podInfo.SecurityIssues, "Pod使用主机网络")
		}

		// 收集Pod中所有容器信息
		for _, container := range pod.Spec.Containers {
			// 为当前容器创建信息结构体
			containerInfo := model.ContainerInfo{
				Name:            container.Name,
				Image:           container.Image,
				ImagePullPolicy: string(container.ImagePullPolicy),
				Ports:           make([]int32, 0),
				VolumeMounts:    make([]string, 0),
				SecurityIssues:  make([]string, 0),
			}

			// 分析容器安全上下文
			if container.SecurityContext != nil {
				// 检查危险设置
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					containerInfo.SecurityIssues = append(containerInfo.SecurityIssues, "容器具有特权模式")
				}
				if container.SecurityContext.AllowPrivilegeEscalation != nil &&
					*container.SecurityContext.AllowPrivilegeEscalation {
					containerInfo.SecurityIssues = append(containerInfo.SecurityIssues, "容器允许特权提升")
				}
				if container.SecurityContext.RunAsNonRoot == nil ||
					(container.SecurityContext.RunAsNonRoot != nil && !*container.SecurityContext.RunAsNonRoot) {
					containerInfo.SecurityIssues = append(containerInfo.SecurityIssues, "容器可能以root用户运行")
				}
			} else {
				containerInfo.SecurityIssues = append(containerInfo.SecurityIssues, "容器未配置SecurityContext")
			}

			// 收集容器端口
			for _, port := range container.Ports {
				containerInfo.Ports = append(containerInfo.Ports, port.ContainerPort)
			}

			// 收集卷挂载
			for _, volumeMount := range container.VolumeMounts {
				containerInfo.VolumeMounts = append(containerInfo.VolumeMounts, volumeMount.Name)
			}

			// 将容器信息添加到Pod信息中
			podInfo.Containers = append(podInfo.Containers, containerInfo)
			// 将容器镜像添加到Pod镜像列表
			podInfo.Images = append(podInfo.Images, container.Image)
		}

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
		// 跳过指定命名空间中的服务
		if shouldSkipNamespace(svc.Namespace, options.SkipNamespaces) {
			continue
		}

		// 为当前服务创建信息结构体
		svcInfo := model.ServiceInfo{
			Name:           svc.Name,
			Namespace:      svc.Namespace,
			Type:           string(svc.Spec.Type),
			Selector:       svc.Spec.Selector,
			ClusterIP:      svc.Spec.ClusterIP,
			ExternalIPs:    svc.Spec.ExternalIPs,
			SecurityIssues: make([]string, 0),
			CreationTime:   svc.CreationTimestamp.Time,
			Annotations:    svc.Annotations,
			ServicePorts:   make([]model.ServicePortInfo, 0),
		}

		// 收集服务暴露的所有端口，包含更详细信息
		for _, port := range svc.Spec.Ports {
			portInfo := model.ServicePortInfo{
				Name:       port.Name,
				Protocol:   string(port.Protocol),
				Port:       port.Port,
				TargetPort: port.TargetPort.String(),
				NodePort:   port.NodePort,
			}
			svcInfo.ServicePorts = append(svcInfo.ServicePorts, portInfo)
		}

		// 安全分析逻辑
		if svc.Spec.Type == "LoadBalancer" || svc.Spec.Type == "NodePort" {
			svcInfo.IsExternallyExposed = true
			// 检查是否有敏感端口暴露
			for _, port := range svcInfo.ServicePorts {
				if isSensitivePort(port.Port) {
					svcInfo.SecurityIssues = append(svcInfo.SecurityIssues,
						fmt.Sprintf("服务暴露了敏感端口: %d", port.Port))
				}
			}
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
		// 跳过指定命名空间中的部署
		if shouldSkipNamespace(deploy.Namespace, options.SkipNamespaces) {
			continue
		}

		// 为当前部署创建信息结构体
		deployInfo := model.DeploymentInfo{
			Name:              deploy.Name,
			Namespace:         deploy.Namespace,
			Replicas:          deploy.Status.Replicas,
			AvailableReplicas: deploy.Status.AvailableReplicas,
			Selector:          deploy.Spec.Selector.MatchLabels,
			Strategy:          string(deploy.Spec.Strategy.Type),
			CreationTime:      deploy.CreationTimestamp.Time,
			ServiceAccount:    deploy.Spec.Template.Spec.ServiceAccountName,
			Labels:            deploy.Labels,
			Annotations:       deploy.Annotations,
			Containers:        make([]string, 0),
			Images:            make([]string, 0),
			SecurityIssues:    make([]string, 0),
		}

		// 收集部署中使用的容器和镜像
		for _, container := range deploy.Spec.Template.Spec.Containers {
			deployInfo.Containers = append(deployInfo.Containers, container.Name)
			deployInfo.Images = append(deployInfo.Images, container.Image)

			// 检查镜像拉取策略
			if container.ImagePullPolicy != corev1.PullAlways {
				deployInfo.SecurityIssues = append(deployInfo.SecurityIssues,
					fmt.Sprintf("容器 %s 未设置ImagePullPolicy=Always", container.Name))
			}
		}

		// 检查部署的其他安全设置
		if deploy.Spec.Template.Spec.HostNetwork {
			deployInfo.SecurityIssues = append(deployInfo.SecurityIssues, "部署使用主机网络")
		}
		if deploy.Spec.Template.Spec.HostPID {
			deployInfo.SecurityIssues = append(deployInfo.SecurityIssues, "部署共享主机PID命名空间")
		}
		if deploy.Spec.Template.Spec.HostIPC {
			deployInfo.SecurityIssues = append(deployInfo.SecurityIssues, "部署共享主机IPC命名空间")
		}

		// 将当前部署信息添加到集群信息中
		clusterInfo.Deployments = append(clusterInfo.Deployments, deployInfo)
	}

	// ==================== 网络策略扫描部分 ====================
	// 获取所有命名空间中的NetworkPolicy列表
	if networkPoliciesAvailable(clientset) {
		networkPolicies, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("警告: 获取网络策略列表失败: %v", err)
		} else {
			// 遍历每个网络策略，收集信息
			for _, policy := range networkPolicies.Items {
				// 跳过指定命名空间中的网络策略
				if shouldSkipNamespace(policy.Namespace, options.SkipNamespaces) {
					continue
				}

				// 为当前网络策略创建信息结构体
				policyInfo := model.NetworkPolicyInfo{
					Name:         policy.Name,
					Namespace:    policy.Namespace,
					PodSelector:  policy.Spec.PodSelector.MatchLabels,
					CreationTime: policy.CreationTimestamp.Time,
				}

				// 将当前网络策略信息添加到集群信息中
				clusterInfo.NetworkPolicies = append(clusterInfo.NetworkPolicies, policyInfo)
			}
		}
	}

	// ==================== 服务账户扫描部分 ====================
	// 获取所有命名空间中的ServiceAccount列表
	serviceAccounts, err := clientset.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("警告: 获取服务账户列表失败: %v", err)
	} else {
		// 遍历每个服务账户，收集信息
		for _, sa := range serviceAccounts.Items {
			// 跳过指定命名空间中的服务账户
			if shouldSkipNamespace(sa.Namespace, options.SkipNamespaces) {
				continue
			}

			// 为当前服务账户创建信息结构体
			saInfo := model.ServiceAccountInfo{
				Name:         sa.Name,
				Namespace:    sa.Namespace,
				CreationTime: sa.CreationTimestamp.Time,
				Secrets:      make([]string, 0),
			}

			// 收集服务账户的Secret
			for _, secret := range sa.Secrets {
				saInfo.Secrets = append(saInfo.Secrets, secret.Name)
			}

			// 检查默认令牌自动挂载
			if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
				saInfo.AutomountToken = true
			}

			// 将当前服务账户信息添加到集群信息中
			clusterInfo.ServiceAccounts = append(clusterInfo.ServiceAccounts, saInfo)
		}
	}

	// 计算漏洞统计数据
	calculateVulnerabilityStats(clusterInfo)

	// 计算整体风险评分
	clusterInfo.OverallRiskScore = calculateOverallRiskScore(clusterInfo)

	// 记录扫描耗时
	scanDuration := time.Since(startTime)
	clusterInfo.ScanDuration = scanDuration

	// 输出扫描结果摘要
	fmt.Printf("扫描完成: 找到 %d 个节点, %d 个Pod, %d 个服务, %d 个部署\n",
		len(clusterInfo.Nodes), len(clusterInfo.Pods), len(clusterInfo.Services), len(clusterInfo.Deployments))
	fmt.Printf("漏洞统计: 严重: %d, 高危: %d, 中危: %d, 低危: %d\n",
		clusterInfo.CriticalVulns, clusterInfo.HighVulns, clusterInfo.MediumVulns, clusterInfo.LowVulns)
	fmt.Printf("扫描耗时: %v\n", scanDuration)
	fmt.Printf("整体风险评分: %.2f/10.0\n", clusterInfo.OverallRiskScore)

	// 返回完整的集群信息
	return clusterInfo, nil
}

// shouldSkipNamespace 判断是否应该跳过指定命名空间
func shouldSkipNamespace(namespace string, skipNamespaces []string) bool {
	for _, ns := range skipNamespaces {
		if namespace == ns {
			return true
		}
	}
	return false
}

// isPodPrivileged 判断Pod是否包含特权容器
func isPodPrivileged(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

// isSensitivePort 判断端口是否为敏感端口
func isSensitivePort(port int32) bool {
	sensitivePorts := []int32{22, 3389, 445, 135, 139, 1433, 3306, 5432, 6379, 27017}
	for _, p := range sensitivePorts {
		if port == p {
			return true
		}
	}
	return false
}

// isNodeUnderPressure 判断节点是否处于资源压力状态
func isNodeUnderPressure(conditions []corev1.NodeCondition, conditionType string) bool {
	for _, condition := range conditions {
		if string(condition.Type) == conditionType && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// isNodeReady 判断节点是否就绪
func isNodeReady(conditions []corev1.NodeCondition) bool {
	for _, condition := range conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// networkPoliciesAvailable 检查集群是否支持网络策略API
func networkPoliciesAvailable(clientset *kubernetes.Clientset) bool {
	_, resourceErr := clientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{Limit: 1})
	return resourceErr == nil
}

// calculateVulnerabilityStats 计算漏洞统计信息
func calculateVulnerabilityStats(clusterInfo *model.ClusterInfo) {
	// 重置统计数据
	clusterInfo.CriticalVulns = 0
	clusterInfo.HighVulns = 0
	clusterInfo.MediumVulns = 0
	clusterInfo.LowVulns = 0

	// 统计节点漏洞
	for _, node := range clusterInfo.Nodes {
		for _, vuln := range node.Vulns {
			categorizeVulnerability(vuln.CvssScore, clusterInfo)
		}
	}

	// 统计Pod漏洞
	for _, pod := range clusterInfo.Pods {
		for _, vuln := range pod.Vulns {
			categorizeVulnerability(vuln.CvssScore, clusterInfo)

		}
	}
}

// categorizeVulnerability 根据严重性评分对漏洞进行分类
func categorizeVulnerability(severity float64, clusterInfo *model.ClusterInfo) {
	if severity >= 9.0 {
		clusterInfo.CriticalVulns++
	} else if severity >= 7.0 {
		clusterInfo.HighVulns++
	} else if severity >= 4.0 {
		clusterInfo.MediumVulns++
	} else {
		clusterInfo.LowVulns++
	}
}

// calculateOverallRiskScore 计算整体风险评分
func calculateOverallRiskScore(clusterInfo *model.ClusterInfo) float64 {
	// 基础分数
	score := 0.0

	// 漏洞因素 (占总分的50%)
	vulnScore := 0.0
	vulnScore += float64(clusterInfo.CriticalVulns) * 10.0
	vulnScore += float64(clusterInfo.HighVulns) * 5.0
	vulnScore += float64(clusterInfo.MediumVulns) * 2.0
	vulnScore += float64(clusterInfo.LowVulns) * 0.5

	// 标准化漏洞分数，最高为5分
	if vulnScore > 0 {
		vulnScore = min(5.0, 5.0*vulnScore/100.0)
	}
	score += vulnScore

	// 配置安全因素 (占总分的30%)
	configScore := 0.0

	// 统计特权容器
	privilegedCount := 0
	for _, pod := range clusterInfo.Pods {
		if pod.Privileged {
			privilegedCount++
		}
	}

	// 如果存在特权容器，增加风险分数
	if privilegedCount > 0 {
		configScore += min(3.0, float64(privilegedCount)*0.5)
	}

	score += configScore

	// 集群暴露因素 (占总分的20%)
	exposureScore := 0.0

	// 统计外部暴露的服务
	exposedServices := 0
	for _, svc := range clusterInfo.Services {
		if svc.Type == "LoadBalancer" || svc.Type == "NodePort" {
			exposedServices++
		}
	}

	// 根据暴露服务的数量计算风险分数
	if exposedServices > 0 {
		exposureScore += min(2.0, float64(exposedServices)*0.2)
	}

	score += exposureScore

	return score
}

// min 返回两个浮点数中的较小值
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func convertVulnerability(containerName string, pentestVuln *pentest.Vulnerability) *model.Vulnerability {
	return &model.Vulnerability{
		ID:          pentestVuln.ID,
		Name:        pentestVuln.Name,
		Severity:    pentestVuln.Severity,
		CvssScore:   pentestVuln.CvssScore,
		ContainerID: containerName,
	}
}
