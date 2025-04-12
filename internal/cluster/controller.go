package cluster

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"k8s.io/apimachinery/pkg/util/wait"
	"log"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"
)

// GetPod 通过名称在指定命名空间中获取 Pod
func GetPod(namespace, name string) (*corev1.Pod, error) {
	return K8sClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListPods 列出指定命名空间中的所有 pod，可选标签选择器
func ListPods(namespace string, labelSelector string) (*corev1.PodList, error) {
	listOptions := metav1.ListOptions{}
	if labelSelector != "" {
		listOptions.LabelSelector = labelSelector
	}
	return K8sClient.CoreV1().Pods(namespace).List(context.TODO(), listOptions)
}

// CreatePod 在指定命名空间中创建新的 Pod
func CreatePod(namespace string, pod *corev1.Pod) (*corev1.Pod, error) {
	return K8sClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
}

// DeletePod 通过名称删除指定命名空间中的 Pod
func DeletePod(namespace, name string) error {
	return K8sClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// UpdatePod 更新现有的 Pod
func UpdatePod(namespace string, pod *corev1.Pod) (*corev1.Pod, error) {
	return K8sClient.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
}

// GetDeployment 通过名称在指定命名空间中获取 Deployment
func GetDeployment(namespace, name string) (*appsv1.Deployment, error) {
	return K8sClient.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// ListDeployments 列出指定命名空间中的所有 deployments
func ListDeployments(namespace string) (*appsv1.DeploymentList, error) {
	return K8sClient.AppsV1().Deployments(namespace).List(context.TODO(), metav1.ListOptions{})
}

// CreateDeployment 在指定命名空间中创建新的 Deployment
func CreateDeployment(namespace string, deployment *appsv1.Deployment) (*appsv1.Deployment, error) {
	return K8sClient.AppsV1().Deployments(namespace).Create(context.TODO(), deployment, metav1.CreateOptions{})
}

// UpdateDeployment 使用重试逻辑更新现有的 Deployment
func UpdateDeployment(namespace string, deployment *appsv1.Deployment) (*appsv1.Deployment, error) {
	var result *appsv1.Deployment
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var updateErr error
		result, updateErr = K8sClient.AppsV1().Deployments(namespace).Update(context.TODO(), deployment, metav1.UpdateOptions{})
		return updateErr
	})
	return result, err
}

// DeleteDeployment 通过名称删除指定命名空间中的 Deployment
func DeleteDeployment(namespace, name string) error {
	return K8sClient.AppsV1().Deployments(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// ScaleDeployment 将 deployment 扩展到指定的副本数
func ScaleDeployment(namespace, name string, replicas int32) (*appsv1.Deployment, error) {
	var result *appsv1.Deployment
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// 更新前获取 Deployment 的最新版本
		deployment, getErr := K8sClient.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}

		deployment.Spec.Replicas = &replicas
		var updateErr error
		result, updateErr = K8sClient.AppsV1().Deployments(namespace).Update(context.TODO(), deployment, metav1.UpdateOptions{})
		return updateErr
	})
	return result, err
}

// GetService 通过名称在指定命名空间中获取 Service
func GetService(namespace, name string) (*corev1.Service, error) {
	return K8sClient.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// CreateService 在指定命名空间中创建新的 Service
func CreateService(namespace string, service *corev1.Service) (*corev1.Service, error) {
	return K8sClient.CoreV1().Services(namespace).Create(context.TODO(), service, metav1.CreateOptions{})
}

// DeleteService 通过名称删除指定命名空间中的 Service
func DeleteService(namespace, name string) error {
	return K8sClient.CoreV1().Services(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// GetConfigMap 通过名称在指定命名空间中获取 ConfigMap
func GetConfigMap(namespace, name string) (*corev1.ConfigMap, error) {
	return K8sClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// CreateConfigMap 在指定命名空间中创建新的 ConfigMap
func CreateConfigMap(namespace string, configMap *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	return K8sClient.CoreV1().ConfigMaps(namespace).Create(context.TODO(), configMap, metav1.CreateOptions{})
}

// UpdateConfigMap 更新现有的 ConfigMap
func UpdateConfigMap(namespace string, configMap *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	return K8sClient.CoreV1().ConfigMaps(namespace).Update(context.TODO(), configMap, metav1.UpdateOptions{})
}

// GetSecret 通过名称在指定命名空间中获取 Secret
func GetSecret(namespace, name string) (*corev1.Secret, error) {
	return K8sClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// CreateSecret 在指定命名空间中创建新的 Secret
func CreateSecret(namespace string, secret *corev1.Secret) (*corev1.Secret, error) {
	return K8sClient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
}

// GetPodLogs 获取 Pod 的日志
func GetPodLogs(namespace, name string, tailLines int64) (string, error) {
	podLogOptions := corev1.PodLogOptions{
		TailLines: &tailLines,
	}

	req := K8sClient.CoreV1().Pods(namespace).GetLogs(name, &podLogOptions)
	podLogs, err := req.Stream(context.TODO())
	if err != nil {
		return "", err
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

// WaitForPodRunning 等待 pod 进入 Running 状态
func WaitForPodRunning(namespace, name string, timeout time.Duration) error {
	return wait.PollImmediate(time.Second, timeout, func() (bool, error) {
		pod, err := K8sClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if pod.Status.Phase == corev1.PodRunning {
			return true, nil
		}
		return false, nil
	})
}

// GetNodeList 获取集群中的所有节点
func GetNodeList() (*corev1.NodeList, error) {
	return K8sClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
}

// GetNamespaceList 获取所有命名空间
func GetNamespaceList() (*corev1.NamespaceList, error) {
	return K8sClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
}

// CreateNamespace 创建新的命名空间
func CreateNamespace(name string) (*corev1.Namespace, error) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	return K8sClient.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
}

// GetPodsBySelector 获取命名空间中匹配标签选择器的 pods
func GetPodsBySelector(namespace string, selector map[string]string) (*corev1.PodList, error) {
	labelSelector := labels.SelectorFromSet(selector)
	listOptions := metav1.ListOptions{
		LabelSelector: labelSelector.String(),
	}
	return K8sClient.CoreV1().Pods(namespace).List(context.TODO(), listOptions)
}
func TestAB() {
	// 假设K8sClient已经在cluster包中被初始化

	fmt.Println("开始测试Kubernetes API接口...")

	// 测试1: 获取所有命名空间
	namespaces, err := GetNamespaceList()
	if err != nil {
		log.Fatalf("获取命名空间列表失败: %v", err)
	}
	fmt.Printf("集群中有 %d 个命名空间\n", len(namespaces.Items))

	// 打印部分命名空间
	fmt.Println("部分命名空间:")
	for i, ns := range namespaces.Items {
		if i < 5 { // 只显示前5个
			fmt.Printf("  - %s (创建于: %s)\n", ns.Name, ns.CreationTimestamp.Format(time.RFC3339))
		} else {
			break
		}
	}

	// 测试2: 获取default命名空间中的所有Pod
	pods, err := ListPods("default", "")
	if err != nil {
		log.Fatalf("获取Pod列表失败: %v", err)
	}
	fmt.Printf("\ndefault命名空间中有 %d 个Pod\n", len(pods.Items))

	// 打印部分Pod
	if len(pods.Items) > 0 {
		fmt.Println("部分Pod:")
		limit := 3
		if len(pods.Items) < limit {
			limit = len(pods.Items)
		}
		for i := 0; i < limit; i++ {
			pod := pods.Items[i]
			fmt.Printf("  - %s (状态: %s, IP: %s)\n", pod.Name, pod.Status.Phase, pod.Status.PodIP)
		}

		// 如果存在Pod，获取第一个Pod的日志
		if len(pods.Items) > 0 {
			podName := pods.Items[0].Name
			logs, err := GetPodLogs("default", podName, 10) // 获取最后10行日志
			if err != nil {
				fmt.Printf("获取Pod %s 的日志失败: %v\n", podName, err)
			} else {
				fmt.Printf("\nPod %s 的最后10行日志:\n%s\n", podName, logs)
			}
		}
	} else {
		fmt.Println("default命名空间中没有Pod")
	}

	// 测试3: 获取所有节点
	nodes, err := GetNodeList()
	if err != nil {
		log.Fatalf("获取节点列表失败: %v", err)
	}
	fmt.Printf("\n集群中有 %d 个节点\n", len(nodes.Items))

	// 打印所有节点信息
	for _, node := range nodes.Items {
		var status string
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady {
				if condition.Status == corev1.ConditionTrue {
					status = "就绪"
				} else {
					status = "未就绪"
				}
				break
			}
		}
		fmt.Printf("  - %s (状态: %s, 内部IP: %s)\n", node.Name, status, getNodeInternalIP(node))
	}

	// 测试8: 清理资源（如果需要）
	fmt.Println("\n是否清理测试资源? [已跳过]")
	// 通常这里会提示用户是否清理资源，但为了简单起见，我们这里省略了交互
	// cleanupResources(testNS)

	fmt.Println("\nKubernetes API接口测试完成")
}

// 获取节点的内部IP
func getNodeInternalIP(node corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	return "未知"
}
