// internal/cluster/visualization.go
package cluster

import (
	"Container_runtime_scanner/internal/cluster/model"
	"fmt"
	"os"
	"os/exec"
)

// ExportToDOT 将攻击图导出为DOT格式
func ExportToDOT(graph *model.StateAttackGraph, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建DOT文件失败: %v", err)
	}
	defer file.Close()

	// 写入DOT文件头
	fmt.Fprintln(file, "digraph AttackGraph {")
	fmt.Fprintln(file, "  rankdir=LR;")
	fmt.Fprintln(file, "  node [shape=box, style=filled];")

	// 写入节点
	for id, node := range graph.Nodes {
		// 根据风险评分确定颜色
		color := "white"
		if node.RiskScore >= 7.0 {
			color = "red"
		} else if node.RiskScore >= 4.0 {
			color = "orange"
		} else if node.RiskScore > 0 {
			color = "yellow"
		}

		// 创建标签内容
		label := fmt.Sprintf("%s\\n%s", node.Host, node.Service)
		if node.Vulnerability != nil {
			label += fmt.Sprintf("\\nVulnerability: %s", node.Vulnerability.Name)
		}
		//label += fmt.Sprintf("\\n风险评分: %.1f", node.RiskScore)

		// 写入节点定义
		fmt.Fprintf(file, "  \"%s\" [label=\"%s\", fillcolor=\"%s\"];\n", id, label, color)
	}

	// 写入边
	for _, edge := range graph.Edges {
		// 根据难度确定线条粗细
		penwidth := 1.0 + (1.0-edge.Difficulty)*3.0

		// 写入边定义
		fmt.Fprintf(file, "  \"%s\" -> \"%s\" [label=\"%s\\n难度: %.1f\", penwidth=%.1f];\n",
			edge.From.ID, edge.To.ID, edge.Action, edge.Difficulty, penwidth)
	}

	// 写入DOT文件尾
	fmt.Fprintln(file, "}")

	return nil
}

// GenerateAttackGraphImage 生成攻击图图片
func GenerateAttackGraphImage(dotFilePath, imageFilePath string) error {
	// 检查是否安装了Graphviz
	_, err := exec.LookPath("dot")
	if err != nil {
		return fmt.Errorf("未找到Graphviz的dot命令，请安装Graphviz: %v", err)
	}

	// 使用dot命令生成图片
	cmd := exec.Command("dot", "-Tpng", dotFilePath, "-o", imageFilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("生成图片失败: %v, 输出: %s", err, string(output))
	}

	return nil
}

// 生成关键路径的DOT表示
func ExportCriticalPathsToDOT(results *model.AnalysisResults, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建DOT文件失败: %v", err)
	}
	defer file.Close()

	// 写入DOT文件头
	fmt.Fprintln(file, "digraph CriticalPaths {")
	fmt.Fprintln(file, "  rankdir=LR;")
	fmt.Fprintln(file, "  node [shape=box, style=filled];")

	// 为每条关键路径生成子图
	for i, path := range results.CriticalPaths {
		fmt.Fprintf(file, "  subgraph cluster_%d {\n", i)
		fmt.Fprintf(file, "    label=\"关键路径 #%d (风险值: %.2f)\";\n", i+1, path.TotalRisk)
		fmt.Fprintln(file, "    style=filled;")
		fmt.Fprintln(file, "    color=lightgrey;")

		// 没有边则跳过
		if len(path.Edges) == 0 {
			fmt.Fprintln(file, "  }")
			continue
		}

		// 获取路径上的所有节点
		nodesInPath := make(map[string]*model.StateNode)
		nodesInPath[path.Edges[0].From.ID] = path.Edges[0].From

		for _, edge := range path.Edges {
			nodesInPath[edge.To.ID] = edge.To
		}

		// 写入节点
		for id, node := range nodesInPath {
			color := "white"
			if node.RiskScore >= 7.0 {
				color = "red"
			} else if node.RiskScore >= 4.0 {
				color = "orange"
			} else if node.RiskScore > 0 {
				color = "yellow"
			}

			label := fmt.Sprintf("%s\\n%s", node.Host, node.Service)
			if node.Vulnerability != nil {
				label += fmt.Sprintf("\\nVulnerability: %s", node.Vulnerability.Name)
			}
			//label += fmt.Sprintf("\\n风险评分: %.1f", node.RiskScore)

			fmt.Fprintf(file, "    \"%s_%d\" [label=\"%s\", fillcolor=\"%s\"];\n", id, i, label, color)
		}

		// 写入边
		for j, edge := range path.Edges {
			penwidth := 1.0 + (1.0-edge.Difficulty)*3.0

			fmt.Fprintf(file, "    \"%s_%d\" -> \"%s_%d\" [label=\"步骤 %d: %s\\n难度: %.1f\", penwidth=%.1f];\n",
				edge.From.ID, i, edge.To.ID, i, j+1, edge.Action, edge.Difficulty, penwidth)
		}

		fmt.Fprintln(file, "  }")
	}

	// 写入DOT文件尾
	fmt.Fprintln(file, "}")

	return nil
}
