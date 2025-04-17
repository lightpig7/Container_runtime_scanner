package model

import (
	"fmt"
	"strings"
)

// PrintClusterInfo 打印集群信息的完整详情
func PrintClusterInfo(info *ClusterInfo) {
	fmt.Println("======== Kubernetes 集群扫描报告 ========")
	fmt.Printf("集群版本: %s\n", info.ClusterVersion)
	fmt.Printf("扫描时间: %s\n", info.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("扫描耗时: %s\n", info.ScanDuration)
	fmt.Printf("整体风险评分: %.2f\n", info.OverallRiskScore)
	fmt.Printf("漏洞统计: 严重(%d) 高危(%d) 中危(%d) 低危(%d)\n",
		info.CriticalVulns, info.HighVulns, info.MediumVulns, info.LowVulns)

	// 打印API服务器信息
	printAPIServerInfo(&info.APIServer)

	// 打印节点信息
	printNodesInfo(info.Nodes)

	// 打印Pod信息
	printPodsInfo(info.Pods)

	// 打印服务信息
	printServicesInfo(info.Services)

	// 打印部署信息
	printDeploymentsInfo(info.Deployments)

	// 打印网络策略信息
	printNetworkPoliciesInfo(info.NetworkPolicies)

	// 打印服务账户信息
	printServiceAccountsInfo(info.ServiceAccounts)

	// 打印安全问题
	printSecurityIssues(info.SecurityIssues)

	fmt.Println("======== 扫描报告结束 ========")
}

// 打印API服务器信息
func printAPIServerInfo(apiServer *APIServerInfo) {
	fmt.Println("\n=== API 服务器信息 ===")
	fmt.Printf("端点: %s\n", apiServer.Endpoint)
	fmt.Printf("版本: %s\n", apiServer.Version)
	fmt.Printf("认证模式: %s\n", strings.Join(apiServer.AuthModes, ", "))
	fmt.Printf("是否开启不安全端口: %t\n", apiServer.InsecurePort)
	fmt.Printf("已启用的准入控制插件: %s\n", strings.Join(apiServer.EnabledAdmissionPlugins, ", "))
	fmt.Printf("是否对外暴露: %t\n", apiServer.ExternallyExposed)
	if apiServer.ExternallyExposed {
		fmt.Printf("外部协议: %s\n", apiServer.ExternalProtocol)
		fmt.Printf("外部端口: %d\n", apiServer.ExternalPort)
	}

	// 打印控制平面组件
	if len(apiServer.ControlPlaneComponents) > 0 {
		fmt.Println("\n--- 控制平面组件 ---")
		for _, component := range apiServer.ControlPlaneComponents {
			fmt.Printf("  • %s:\n", component.Name)
			fmt.Printf("    版本: %s\n", component.Version)
			fmt.Printf("    运行状态: %t\n", component.Running)
			fmt.Printf("    Pod名称: %s\n", component.PodName)
			fmt.Printf("    端口: %d\n", component.Port)
			fmt.Printf("    认证方式: %s\n", component.AuthMethod)
		}
	}

	// 打印API服务器漏洞
	if len(apiServer.Vulnerabilities) > 0 {
		fmt.Println("\n--- API服务器漏洞 ---")
		for _, vuln := range apiServer.Vulnerabilities {
			fmt.Printf("  • %s (%s):\n", vuln.Name, vuln.ID)
			fmt.Printf("    严重性: %s\n", vuln.Severity)
			fmt.Printf("    CVSS评分: %.1f\n", vuln.CvssScore)
		}
	}
}

// 打印节点信息
func printNodesInfo(nodes []NodeInfo) {
	fmt.Println("\n=== 节点信息 ===")
	fmt.Printf("总节点数: %d\n", len(nodes))

	for i, node := range nodes {
		fmt.Printf("\n--- 节点 #%d: %s ---\n", i+1, node.Name)
		fmt.Printf("角色: %s\n", node.Role)
		fmt.Printf("Kubelet版本: %s\n", node.KubeletVersion)
		fmt.Printf("操作系统: %s\n", node.OSImage)
		fmt.Printf("内核版本: %s\n", node.KernelVersion)
		fmt.Printf("容器运行时: %s\n", node.ContainerRuntime)
		fmt.Printf("IP地址: %s\n", node.IPAddress)
		fmt.Printf("状态: %s\n", getNodeStatus(node))

		// 打印标签
		if len(node.Labels) > 0 {
			fmt.Println("\n标签:")
			for k, v := range node.Labels {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		// 打印污点
		if len(node.Taints) > 0 {
			fmt.Println("\n污点:")
			for _, taint := range node.Taints {
				fmt.Printf("  • %s\n", taint)
			}
		}

		// 打印安全问题
		if len(node.SecurityIssues) > 0 {
			fmt.Println("\n安全问题:")
			for _, issue := range node.SecurityIssues {
				fmt.Printf("  • %s\n", issue)
			}
		}

		// 打印漏洞
		if len(node.Vulns) > 0 {
			fmt.Println("\n漏洞:")
			for _, vuln := range node.Vulns {
				fmt.Printf("  • %s (%s): %s (CVSS: %.1f)\n",
					vuln.Name, vuln.ID, vuln.Severity, vuln.CvssScore)
			}
		}
	}
}

// 获取节点状态
func getNodeStatus(node NodeInfo) string {
	if !node.Ready {
		return "NotReady"
	}

	var issues []string
	if node.CPUPressure {
		issues = append(issues, "CPUPressure")
	}
	if node.MemoryPressure {
		issues = append(issues, "MemoryPressure")
	}
	if node.DiskPressure {
		issues = append(issues, "DiskPressure")
	}

	if len(issues) > 0 {
		return fmt.Sprintf("Ready,但有问题: %s", strings.Join(issues, ","))
	}

	return "Ready"
}

// 打印Pod信息
func printPodsInfo(pods []PodInfo) {
	fmt.Println("\n=== Pod信息 ===")
	fmt.Printf("总Pod数: %d\n", len(pods))

	for i, pod := range pods {
		fmt.Printf("\n--- Pod #%d: %s/%s ---\n", i+1, pod.Namespace, pod.Name)
		fmt.Printf("所在节点: %s\n", pod.NodeName)
		fmt.Printf("服务账户: %s\n", pod.ServiceAccount)
		fmt.Printf("状态: %s\n", pod.Status)
		fmt.Printf("创建时间: %s\n", pod.CreationTime.Format("2006-01-02 15:04:05"))

		// 打印安全相关信息
		fmt.Println("\n安全配置:")
		fmt.Printf("  特权容器: %t\n", pod.Privileged)
		fmt.Printf("  主机网络: %t\n", pod.HostNetwork)
		fmt.Printf("  主机PID: %t\n", pod.HostPID)
		fmt.Printf("  主机IPC: %t\n", pod.HostIPC)

		// 打印标签
		if len(pod.Labels) > 0 {
			fmt.Println("\n标签:")
			for k, v := range pod.Labels {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		// 打印镜像
		if len(pod.Images) > 0 {
			fmt.Println("\n镜像:")
			for _, img := range pod.Images {
				fmt.Printf("  • %s\n", img)
			}
		}

		// 打印容器
		if len(pod.Containers) > 0 {
			fmt.Println("\n容器:")
			for j, container := range pod.Containers {
				fmt.Printf("  --- 容器 #%d: %s ---\n", j+1, container.Name)
				fmt.Printf("    镜像: %s\n", container.Image)
				fmt.Printf("    镜像拉取策略: %s\n", container.ImagePullPolicy)

				if len(container.Ports) > 0 {
					fmt.Println("    端口:")
					for _, port := range container.Ports {
						fmt.Printf("      • %d\n", port)
					}
				}

				if len(container.VolumeMounts) > 0 {
					fmt.Println("    挂载卷:")
					for _, vol := range container.VolumeMounts {
						fmt.Printf("      • %s\n", vol)
					}
				}

				if len(container.SecurityIssues) > 0 {
					fmt.Println("    安全问题:")
					for _, issue := range container.SecurityIssues {
						fmt.Printf("      • %s\n", issue)
					}
				}
			}
		}

		// 打印安全问题
		if len(pod.SecurityIssues) > 0 {
			fmt.Println("\nPod级安全问题:")
			for _, issue := range pod.SecurityIssues {
				fmt.Printf("  • %s\n", issue)
			}
		}

		// 打印漏洞
		if len(pod.Vulns) > 0 {
			fmt.Println("\n漏洞:")
			for _, vuln := range pod.Vulns {
				fmt.Printf("  • %s (%s): %s (CVSS: %.1f)\n",
					vuln.Name, vuln.ID, vuln.Severity, vuln.CvssScore)
				if vuln.ContainerID != "" {
					fmt.Printf("    容器ID: %s\n", vuln.ContainerID)
				}
			}
		}
	}
}

// 打印服务信息
func printServicesInfo(services []ServiceInfo) {
	fmt.Println("\n=== 服务信息 ===")
	fmt.Printf("总服务数: %d\n", len(services))

	for i, svc := range services {
		fmt.Printf("\n--- 服务 #%d: %s/%s ---\n", i+1, svc.Namespace, svc.Name)
		fmt.Printf("类型: %s\n", svc.Type)
		fmt.Printf("创建时间: %s\n", svc.CreationTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("集群IP: %s\n", svc.ClusterIP)
		fmt.Printf("对外暴露: %t\n", svc.IsExternallyExposed)

		if len(svc.ExternalIPs) > 0 {
			fmt.Printf("外部IP: %s\n", strings.Join(svc.ExternalIPs, ", "))
		}

		// 打印选择器
		if len(svc.Selector) > 0 {
			fmt.Println("\n选择器:")
			for k, v := range svc.Selector {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		// 打印端口
		if len(svc.ServicePorts) > 0 {
			fmt.Println("\n端口:")
			for _, port := range svc.ServicePorts {
				nodePortInfo := ""
				if port.NodePort > 0 {
					nodePortInfo = fmt.Sprintf(" (NodePort: %d)", port.NodePort)
				}
				fmt.Printf("  • %s: %s %d → %s%s\n",
					port.Name, port.Protocol, port.Port, port.TargetPort, nodePortInfo)
			}
		}

		// 打印注解
		if len(svc.Annotations) > 0 {
			fmt.Println("\n注解:")
			for k, v := range svc.Annotations {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		// 打印安全问题
		if len(svc.SecurityIssues) > 0 {
			fmt.Println("\n安全问题:")
			for _, issue := range svc.SecurityIssues {
				fmt.Printf("  • %s\n", issue)
			}
		}
	}
}

// 打印部署信息
func printDeploymentsInfo(deployments []DeploymentInfo) {
	fmt.Println("\n=== 部署信息 ===")
	fmt.Printf("总部署数: %d\n", len(deployments))

	for i, deployment := range deployments {
		fmt.Printf("\n--- 部署 #%d: %s/%s ---\n", i+1, deployment.Namespace, deployment.Name)
		fmt.Printf("副本数: %d/%d\n", deployment.AvailableReplicas, deployment.Replicas)
		fmt.Printf("部署策略: %s\n", deployment.Strategy)
		fmt.Printf("服务账户: %s\n", deployment.ServiceAccount)
		fmt.Printf("创建时间: %s\n", deployment.CreationTime.Format("2006-01-02 15:04:05"))

		// 打印选择器
		if len(deployment.Selector) > 0 {
			fmt.Println("\n选择器:")
			for k, v := range deployment.Selector {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		// 打印标签
		if len(deployment.Labels) > 0 {
			fmt.Println("\n标签:")
			for k, v := range deployment.Labels {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		// 打印注解
		if len(deployment.Annotations) > 0 {
			fmt.Println("\n注解:")
			for k, v := range deployment.Annotations {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}

		// 打印容器
		if len(deployment.Containers) > 0 {
			fmt.Println("\n容器:")
			for _, container := range deployment.Containers {
				fmt.Printf("  • %s\n", container)
			}
		}

		// 打印镜像
		if len(deployment.Images) > 0 {
			fmt.Println("\n镜像:")
			for _, img := range deployment.Images {
				fmt.Printf("  • %s\n", img)
			}
		}

		// 打印安全问题
		if len(deployment.SecurityIssues) > 0 {
			fmt.Println("\n安全问题:")
			for _, issue := range deployment.SecurityIssues {
				fmt.Printf("  • %s\n", issue)
			}
		}
	}
}

// 打印网络策略信息
func printNetworkPoliciesInfo(policies []NetworkPolicyInfo) {
	fmt.Println("\n=== 网络策略信息 ===")
	fmt.Printf("总网络策略数: %d\n", len(policies))

	for i, policy := range policies {
		fmt.Printf("\n--- 网络策略 #%d: %s/%s ---\n", i+1, policy.Namespace, policy.Name)
		fmt.Printf("创建时间: %s\n", policy.CreationTime.Format("2006-01-02 15:04:05"))

		// 打印Pod选择器
		if len(policy.PodSelector) > 0 {
			fmt.Println("\nPod选择器:")
			for k, v := range policy.PodSelector {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
	}
}

// 打印服务账户信息
func printServiceAccountsInfo(serviceAccounts []ServiceAccountInfo) {
	fmt.Println("\n=== 服务账户信息 ===")
	fmt.Printf("总服务账户数: %d\n", len(serviceAccounts))

	for i, sa := range serviceAccounts {
		fmt.Printf("\n--- 服务账户 #%d: %s/%s ---\n", i+1, sa.Namespace, sa.Name)
		fmt.Printf("创建时间: %s\n", sa.CreationTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("自动挂载令牌: %t\n", sa.AutomountToken)

		// 打印密钥
		if len(sa.Secrets) > 0 {
			fmt.Println("\n密钥:")
			for _, secret := range sa.Secrets {
				fmt.Printf("  • %s\n", secret)
			}
		}
	}
}

// 打印安全问题
func printSecurityIssues(issues []SecurityIssue) {
	fmt.Println("\n=== 安全问题汇总 ===")

	// 按严重性对问题进行分类
	criticalIssues := make([]SecurityIssue, 0)
	highIssues := make([]SecurityIssue, 0)
	mediumIssues := make([]SecurityIssue, 0)
	lowIssues := make([]SecurityIssue, 0)

	for _, issue := range issues {
		switch issue.Severity {
		case "Critical":
			criticalIssues = append(criticalIssues, issue)
		case "High":
			highIssues = append(highIssues, issue)
		case "Medium":
			mediumIssues = append(mediumIssues, issue)
		case "Low":
			lowIssues = append(lowIssues, issue)
		}
	}

	// 打印严重问题
	if len(criticalIssues) > 0 {
		fmt.Println("\n严重问题:")
		printIssuesByType(criticalIssues)
	}

	// 打印高危问题
	if len(highIssues) > 0 {
		fmt.Println("\n高危问题:")
		printIssuesByType(highIssues)
	}

	// 打印中危问题
	if len(mediumIssues) > 0 {
		fmt.Println("\n中危问题:")
		printIssuesByType(mediumIssues)
	}

	// 打印低危问题
	if len(lowIssues) > 0 {
		fmt.Println("\n低危问题:")
		printIssuesByType(lowIssues)
	}
}

// 按类型打印安全问题
func printIssuesByType(issues []SecurityIssue) {
	// 对问题按资源类型分组
	issuesByType := make(map[string][]SecurityIssue)
	for _, issue := range issues {
		issuesByType[issue.ResourceType] = append(issuesByType[issue.ResourceType], issue)
	}

	// 打印每种类型的问题
	for resType, typeIssues := range issuesByType {
		fmt.Printf("\n  %s 问题:\n", resType)
		for i, issue := range typeIssues {
			namespaceInfo := ""
			if issue.Namespace != "" {
				namespaceInfo = fmt.Sprintf(" (命名空间: %s)", issue.Namespace)
			}

			fmt.Printf("    %d. %s%s - 风险评分: %.2f\n",
				i+1, issue.ResourceName, namespaceInfo, issue.RiskScore)
			fmt.Printf("       问题: %s\n", issue.Issue)
			fmt.Printf("       修复建议: %s\n", issue.Remediation)
		}
	}
}
