package cluster

import (
	"Container_runtime_scanner/internal/cluster/controller"
	"Container_runtime_scanner/internal/cluster/model"
	"Container_runtime_scanner/internal/cluster/scanner"
	"context"
	"fmt"
	"log"
)

func Test() {

	clientset := controller.K8sClient
	// 创建上下文
	ctx := context.Background()

	// 扫描集群获取信息
	fmt.Println("开始扫描集群以收集节点和Pod信息...")
	clusterInfo, err := scanner.ScanCluster(ctx, clientset)

	if err != nil {
		log.Fatalf("扫描集群失败: %s", err.Error())
	}
	model.PrintClusterInfo(clusterInfo)

	// 构建攻击图
	fmt.Println("构建状态攻击图...")
	attackGraph := model.NewStateAttackGraph()
	err = attackGraph.BuildFromClusterInfo(clusterInfo)
	if err != nil {
		log.Fatalf("构建攻击图失败: %s", err.Error())
	}

	// 分析攻击图并建立攻击边
	err = model.AnalyzeAttackGraph(attackGraph, clusterInfo)
	if err != nil {
		log.Fatalf("分析攻击图失败: %v", err)
	}

	outputDir := "internal/cluster/output/"
	err = ExportToJSON(attackGraph, outputDir+"graph.json")
	if err != nil {
		return
	}
}
