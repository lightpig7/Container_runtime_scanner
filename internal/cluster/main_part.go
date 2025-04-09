package cluster

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"Container_runtime_scanner/internal/cluster/model"
	"Container_runtime_scanner/internal/cluster/scanner"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func Test() {
	// 解析Kubernetes配置文件位置
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// 创建Kubernetes客户端配置
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %s", err.Error())
	}

	// 创建Kubernetes客户端
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %s", err.Error())
	}

	// 创建上下文
	ctx := context.Background()

	// 扫描集群获取信息
	fmt.Println("开始扫描集群以收集节点和Pod信息...")
	clusterInfo, err := scanner.ScanCluster(ctx, clientset)
	if err != nil {
		log.Fatalf("扫描集群失败: %s", err.Error())
	}

	// 构建攻击图
	fmt.Println("构建状态攻击图...")
	attackGraph := model.NewStateAttackGraph()
	err = attackGraph.BuildFromClusterInfo(clusterInfo)
	if err != nil {
		log.Fatalf("构建攻击图失败: %s", err.Error())
	}

	fmt.Println("分析潜在攻击路径...")
	results := attackGraph.AnalyzePaths()

	// 输出结果
	fmt.Println("\n===== 安全评估结果 =====")
	for i, path := range results.CriticalPaths {
		fmt.Printf("关键攻击路径 #%d:\n", i+1)
		path.Print()
		fmt.Println()
	}

	fmt.Printf("识别出 %d 个关键安全风险点\n", len(results.CriticalNodes))
	for i, node := range results.CriticalNodes {
		fmt.Printf("风险点 #%d: %s (风险评分: %.2f)\n", i+1, node.ID, node.RiskScore)
	}

	// 生成DOT文件并转换为图片
	outputDir := "./output"
	os.MkdirAll(outputDir, 0755)

	// 生成完整攻击图的DOT文件和图片
	dotFilePath := filepath.Join(outputDir, "attack_graph.dot")
	if err := ExportToDOT(attackGraph, dotFilePath); err != nil {
		log.Printf("导出DOT文件失败: %s", err.Error())
	} else {
		fmt.Printf("\n攻击图DOT文件已导出至: %s\n", dotFilePath)

		imageFilePath := filepath.Join(outputDir, "attack_graph.png")

		err := GenerateGraphImageWithGoGraphviz(dotFilePath, imageFilePath)
		if err != nil {
			log.Printf("生成关键路径图片失败: %s", err.Error())
		}
	}

	// 生成关键路径的DOT文件和图片
	criticalDotPath := filepath.Join(outputDir, "critical_paths.dot")
	if err := ExportCriticalPathsToDOT(results, criticalDotPath); err != nil {
		log.Printf("导出关键路径DOT文件失败: %s", err.Error())
	} else {
		fmt.Printf("关键路径DOT文件已导出至: %s\n", criticalDotPath)
		criticalImagePath := filepath.Join(outputDir, "critical_paths.png")
		err := GenerateGraphImageWithGoGraphviz(criticalDotPath, criticalImagePath)
		if err != nil {
			log.Printf("生成关键路径图片失败: %s", err.Error())
		}
	}
}
