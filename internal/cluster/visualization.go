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

	// 写入DOT文件头，添加中文字体支持
	fmt.Fprintln(file, "digraph AttackGraph {")
	fmt.Fprintln(file, "  rankdir=LR;")
	// 添加字体设置，使用支持中文的字体
	fmt.Fprintln(file, "  node [shape=box, style=filled, fontname=\"SimSun\"];") // 使用宋体
	fmt.Fprintln(file, "  edge [fontname=\"SimSun\"];")                          // 边的标签也使用宋体

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

		// 处理漏洞信息
		vulns := node.Vulnerability
		if len(vulns) > 0 {
			label += "\\nVulnerabilities:"
			maxVulns := 3
			if len(vulns) < maxVulns {
				maxVulns = len(vulns)
			}

			for i := 0; i < maxVulns; i++ {
				vuln := vulns[i]
				label += fmt.Sprintf("\\n- %s", vuln.Name)
			}

			// 如果有更多漏洞，显示计数
			if len(vulns) > maxVulns {
				label += fmt.Sprintf("\\n(+%d more...)", len(vulns)-maxVulns)
			}
		}

		// 写入节点定义
		fmt.Fprintf(file, "  \"%s\" [label=\"%s\", fillcolor=\"%s\"];\n", id, label, color)
	}

	// 写入边
	for _, edge := range graph.Edges {
		// 检查边的源节点和目标节点是否存在
		if _, sourceExists := graph.Nodes[edge.From.ID]; !sourceExists {
			continue // 跳过源节点不存在的边
		}
		if _, targetExists := graph.Nodes[edge.To.ID]; !targetExists {
			continue // 跳过目标节点不存在的边
		}

		// 创建边标签，只包含攻击行为
		edgeLabel := edge.Action

		// 添加前置条件信息
		if len(edge.Prerequisites) > 0 {
			edgeLabel += "\\n前置条件:"
			for _, prereq := range edge.Prerequisites {
				edgeLabel += fmt.Sprintf("\\n- %s", prereq)
			}
		}

		// 写入完整的边定义，不使用难度值调整线条粗细
		fmt.Fprintf(file, "  \"%s\" -> \"%s\" [label=\"%s\"];\n",
			edge.From.ID, edge.To.ID, edgeLabel)
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

			// 处理漏洞切片，显示最多2个漏洞
			if len(node.Vulnerability) > 0 {
				label += "\\nVulnerabilities:"
				maxVulns := 2
				if len(node.Vulnerability) < maxVulns {
					maxVulns = len(node.Vulnerability)
				}

				for i := 0; i < maxVulns; i++ {
					vuln := node.Vulnerability[i]
					label += fmt.Sprintf("\\n- %s", vuln.Name)
				}

				// 如果有更多漏洞，显示计数
				if len(node.Vulnerability) > maxVulns {
					label += fmt.Sprintf("\\n(+%d more...)", len(node.Vulnerability)-maxVulns)
				}
			}

			fmt.Fprintf(file, "    \"%s_%d\" [label=\"%s\", fillcolor=\"%s\"];\n", id, i, label, color)
		}

		// 写入边
		for j, edge := range path.Edges {

			fmt.Fprintf(file, "    \"%s_%d\" -> \"%s_%d\" [label=\"步骤 %d: %s;\n",
				edge.From.ID, i, edge.To.ID, i, j+1, edge.Action)
		}

		fmt.Fprintln(file, "  }")
	}

	// 写入DOT文件尾
	fmt.Fprintln(file, "}")

	return nil
}
