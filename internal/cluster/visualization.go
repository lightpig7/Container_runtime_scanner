package cluster

import (
	"Container_runtime_scanner/internal/cluster/model"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// ExportToDOT 将攻击图导出为增强版DOT格式
func ExportToDOT(graph *model.StateAttackGraph, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建DOT文件失败: %v", err)
	}
	defer file.Close()

	// 写入DOT文件头，添加增强的样式和布局设置
	fmt.Fprintln(file, "digraph AttackGraph {")
	// 在ExportToDOT函数中修改图形属性
	fmt.Fprintln(file, "  graph [rankdir=LR, splines=ortho, nodesep=0.8, ranksep=1.2, fontname=\"SimSun\", bgcolor=\"white\", overlap=false, concentrate=true, compound=true];")

	// 增强节点样式，提高可读性
	fmt.Fprintln(file, "  node [shape=box, style=\"rounded,filled\", fontname=\"SimSun\", fontsize=12, margin=\"0.3,0.1\", penwidth=1.5];")
	fmt.Fprintln(file, "  edge [fontname=\"SimSun\", fontsize=10, penwidth=1.2, arrowsize=0.8, color=\"#444444\"];")

	// 节点分组，按照类型分组以提高视觉清晰度
	nodeGroups := map[string][]*model.StateNode{
		"互联网":    {},
		"API服务器": {},
		"节点":     {},
		"Pod":    {},
		"服务":     {},
		"其他":     {},
	}

	// 按类型分组节点
	for _, node := range graph.Nodes {
		prefix := strings.Split(node.ID, "-")[0]
		switch {
		case node.ID == "internet":
			nodeGroups["互联网"] = append(nodeGroups["互联网"], node)
		case node.ID == "api-server":
			nodeGroups["API服务器"] = append(nodeGroups["API服务器"], node)
		case prefix == "node":
			nodeGroups["节点"] = append(nodeGroups["节点"], node)
		case prefix == "pod":
			nodeGroups["Pod"] = append(nodeGroups["Pod"], node)
		case prefix == "svc":
			nodeGroups["服务"] = append(nodeGroups["服务"], node)
		default:
			nodeGroups["其他"] = append(nodeGroups["其他"], node)
		}
	}

	// 为每个分组生成子图
	for groupName, nodes := range nodeGroups {
		if len(nodes) == 0 {
			continue
		}

		fmt.Fprintf(file, "  subgraph cluster_%s {\n", sanitizeGraphvizID(groupName))
		fmt.Fprintf(file, "    label=\"%s\";\n", groupName)
		fmt.Fprintf(file, "    style=filled;\n")
		fmt.Fprintf(file, "    color=lightgrey;\n")
		fmt.Fprintf(file, "    fontname=\"SimSun\";\n")
		fmt.Fprintf(file, "    fontsize=14;\n")

		// 写入分组中的节点
		for _, node := range nodes {
			renderNode(file, node)
		}

		fmt.Fprintln(file, "  }")
	}

	fmt.Fprintln(file, "  // Node和Pod关联约束")
	for id1, node1 := range graph.Nodes {
		for id2, node2 := range graph.Nodes {
			if id1 != id2 && areNodesRelated(node1, node2) {
				// 创建不可见的边，具有较强的权重，拉近相关节点
				fmt.Fprintf(file, "  \"%s\" -> \"%s\" [style=invis, weight=10];\n", id1, id2)
			}
		}
	}
	// 写入边
	for _, edge := range graph.Edges {
		renderEdge(file, edge, graph)
	}

	// 写入DOT文件尾
	fmt.Fprintln(file, "}")

	return nil
}

// 根据风险评分获取颜色
func getRiskColor(score float64) string {
	if score >= 9.0 {
		return "#FF0000" // 深红色 - 严重风险
	} else if score >= 7.0 {
		return "#FF4500" // 红橙色 - 高风险
	} else if score >= 4.0 {
		return "#FFA500" // 橙色 - 中等风险
	} else if score > 0 {
		return "#FFFF00" // 黄色 - 低风险
	}
	return "#FFFFFF" // 白色 - 无风险
}

// 获取节点形状
func getNodeShape(nodeID string) string {
	prefix := strings.Split(nodeID, "-")[0]

	switch {
	case nodeID == "internet":
		return "doubleoctagon" // 互联网节点
	case nodeID == "api-server":
		return "hexagon" // API服务器
	case prefix == "node":
		return "box3d" // 节点
	case prefix == "pod":
		return "cylinder" // Pod
	case prefix == "svc":
		return "ellipse" // 服务
	default:
		return "box" // 默认
	}
}

func renderNode(file *os.File, node *model.StateNode) {
	// 创建HTML标签内容以获得更好的格式控制
	var labelParts []string

	// 添加节点ID和主机信息（标题部分）
	labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"14\"><B>%s</B></FONT>", escapeHTML(node.Host)))
	labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"12\" COLOR=\"#555555\">ID: %s</FONT>", escapeHTML(node.ID)))

	// 添加服务信息
	if node.Service != "" {
		labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"12\">服务: %s</FONT>", escapeHTML(node.Service)))
	}

	// 添加风险评分
	if node.RiskScore > 0 {
		labelParts = append(labelParts, fmt.Sprintf("<FONT COLOR=\"#AA0000\" POINT-SIZE=\"12\">风险评分: %.1f</FONT>", node.RiskScore))
	}

	// 处理漏洞信息 - 显示所有漏洞
	vulns := node.Vulnerability
	if len(vulns) > 0 {
		labelParts = append(labelParts, "<FONT POINT-SIZE=\"12\"><B>漏洞:</B></FONT>")

		// 显示所有漏洞
		for _, vuln := range vulns {
			// 根据CVSS评分确定漏洞颜色
			vulnColor := "#000000"
			if vuln.CvssScore >= 9.0 {
				vulnColor = "#CC0000" // 严重
			} else if vuln.CvssScore >= 7.0 {
				vulnColor = "#FF3300" // 高危
			} else if vuln.CvssScore >= 4.0 {
				vulnColor = "#FF9900" // 中危
			} else {
				vulnColor = "#FFCC00" // 低危
			}

			// 添加漏洞详细信息
			vulnInfo := fmt.Sprintf("<FONT POINT-SIZE=\"10\" COLOR=\"%s\">• %s (ID:%s, CVSS:%.1f, 严重性:%s)</FONT>",
				vulnColor, escapeHTML(vuln.Name), escapeHTML(vuln.ID), vuln.CvssScore, escapeHTML(vuln.Severity))

			// 如果有容器ID，也添加上
			if vuln.ContainerID != "" {
				vulnInfo = fmt.Sprintf("<FONT POINT-SIZE=\"10\" COLOR=\"%s\">• %s (ID:%s, CVSS:%.1f, 严重性:%s, 容器:%s)</FONT>",
					vulnColor, escapeHTML(vuln.Name), escapeHTML(vuln.ID), vuln.CvssScore,
					escapeHTML(vuln.Severity), escapeHTML(vuln.ContainerID))
			}

			labelParts = append(labelParts, vulnInfo)
		}
	}

	// 添加上下文信息 - 显示所有上下文属性
	if node.Context != nil && len(node.Context) > 0 {
		labelParts = append(labelParts, "<FONT POINT-SIZE=\"12\"><B>上下文信息:</B></FONT>")

		// 创建有序的键列表，使得输出更加一致
		keys := make([]string, 0, len(node.Context))
		for k := range node.Context {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// 遍历所有上下文属性并添加到标签中
		for _, key := range keys {
			value := node.Context[key]
			if value != nil {
				// 对于布尔值，采用特殊处理，true用绿色，false用灰色
				if boolVal, isBool := value.(bool); isBool {
					color := "#888888" // 灰色表示false
					if boolVal {
						color = "#008800" // 绿色表示true
					}
					labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"10\" COLOR=\"%s\">%s: %v</FONT>",
						color, escapeHTML(key), value))
				} else {
					// 其他类型值的正常处理
					labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"10\">%s: %v</FONT>",
						escapeHTML(key), escapeHTML(fmt.Sprintf("%v", value))))
				}
			}
		}
	}

	// 合并所有部分为一个HTML标签
	htmlLabel := fmt.Sprintf("<%s>", strings.Join(labelParts, "<BR/>"))

	// 获取节点颜色和形状
	color := getRiskColor(node.RiskScore)
	shape := getNodeShape(node.ID)

	// 写入节点定义，增加大小调整以适应更多内容
	fmt.Fprintf(file, "    \"%s\" [label=%s, shape=%s, fillcolor=\"%s\", style=\"filled,rounded\", width=0, height=0, margin=\"0.3,0.1\"];\n",
		node.ID, htmlLabel, shape, color)
}

// 渲染边到DOT文件
func renderEdge(file *os.File, edge *model.AttackEdge, graph *model.StateAttackGraph) {
	// 检查边的源节点和目标节点是否存在
	if _, sourceExists := graph.Nodes[edge.From.ID]; !sourceExists {
		return // 跳过源节点不存在的边
	}
	if _, targetExists := graph.Nodes[edge.To.ID]; !targetExists {
		return // 跳过目标节点不存在的边
	}

	// 创建HTML格式的边标签
	var labelParts []string

	// 添加攻击行为
	labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"12\"><B>%s</B></FONT>", escapeHTML(edge.Action)))

	// 添加前置条件信息
	if len(edge.Prerequisites) > 0 {
		labelParts = append(labelParts, "<FONT POINT-SIZE=\"10\"><I>前置条件:</I></FONT>")
		for i, prereq := range edge.Prerequisites {
			labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"9\" COLOR=\"#444444\">%d. %s</FONT>",
				i+1, escapeHTML(prereq)))
		}
	}

	// 合并所有部分为一个HTML标签
	htmlLabel := fmt.Sprintf("<%s>", strings.Join(labelParts, "<BR/>"))

	// 设置边的样式 - 攻击边使用红色和实线
	style := "solid"
	// 所有攻击边都使用红色
	edgeColor := "#FF0000" // 红色
	weight := 1.0

	// 如果是同一分组内的节点，增加权重使它们靠得更近
	if areNodesRelated(edge.From, edge.To) {
		weight = 5.0
	}

	// 写入完整的边定义
	fmt.Fprintf(file, "  \"%s\" -> \"%s\" [label=%s, style=%s, color=\"%s\", weight=%.1f, penwidth=1.5];\n",
		edge.From.ID, edge.To.ID, htmlLabel, style, edgeColor, weight)
}

// 为关键路径生成DOT表示的增强版本
func ExportCriticalPathsToDOT(results *model.AnalysisResults, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建DOT文件失败: %v", err)
	}
	defer file.Close()

	// 写入DOT文件头，使用增强的样式设置
	fmt.Fprintln(file, "digraph CriticalPaths {")
	fmt.Fprintln(file, "  graph [rankdir=LR, splines=polyline, nodesep=0.6, ranksep=1.0, fontname=\"SimSun\", bgcolor=\"#FAFAFA\"];")
	fmt.Fprintln(file, "  node [shape=box, style=\"rounded,filled\", fontname=\"SimSun\", fontsize=12, margin=\"0.2,0.1\", penwidth=1.5];")
	fmt.Fprintln(file, "  edge [fontname=\"SimSun\", fontsize=10, penwidth=1.2, arrowsize=0.8];")

	// 为每条关键路径生成子图
	for i, path := range results.CriticalPaths {
		fmt.Fprintf(file, "  subgraph cluster_%d {\n", i)
		fmt.Fprintf(file, "    label=<<FONT POINT-SIZE=\"16\"><B>关键路径 #%d</B></FONT><BR/><FONT POINT-SIZE=\"14\">风险值: %.2f</FONT>>;\n",
			i+1, path.TotalRisk)
		fmt.Fprintln(file, "    style=filled;")
		fmt.Fprintln(file, "    color=lightgrey;")
		fmt.Fprintln(file, "    fontname=\"SimSun\";")
		fmt.Fprintln(file, "    penwidth=2.0;")
		fmt.Fprintln(file, "    margin=20;")

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

		// 为路径上的每个节点创建专用ID
		nodeIDs := make(map[string]string)
		for id, node := range nodesInPath {
			nodeIDs[id] = fmt.Sprintf("%s_%d", id, i)

			// 渲染路径中的节点，使用HTML标签增强显示
			var labelParts []string

			// 添加标题
			labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"14\"><B>%s</B></FONT>", escapeHTML(node.Host)))

			// 添加服务信息
			if node.Service != "" {
				labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"12\">服务: %s</FONT>", escapeHTML(node.Service)))
			}

			// 添加风险评分
			if node.RiskScore > 0 {
				labelParts = append(labelParts, fmt.Sprintf("<FONT COLOR=\"#AA0000\" POINT-SIZE=\"12\">风险评分: %.1f</FONT>", node.RiskScore))
			}

			// 处理漏洞切片，显示最多2个漏洞
			if len(node.Vulnerability) > 0 {
				labelParts = append(labelParts, "<FONT POINT-SIZE=\"12\"><B>漏洞:</B></FONT>")
				maxVulns := 2
				if len(node.Vulnerability) < maxVulns {
					maxVulns = len(node.Vulnerability)
				}

				for i := 0; i < maxVulns; i++ {
					vuln := node.Vulnerability[i]
					labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"10\" COLOR=\"#880000\">• %s (%.1f)</FONT>",
						escapeHTML(vuln.Name), vuln.CvssScore))
				}

				// 如果有更多漏洞，显示计数
				if len(node.Vulnerability) > maxVulns {
					labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"10\">(+%d more...)</FONT>", len(node.Vulnerability)-maxVulns))
				}
			}

			// 合并所有部分为一个HTML标签
			htmlLabel := fmt.Sprintf("<%s>", strings.Join(labelParts, "<BR/>"))

			// 获取节点颜色和形状
			color := getRiskColor(node.RiskScore)
			shape := getNodeShape(node.ID)

			// 写入节点定义
			fmt.Fprintf(file, "    \"%s\" [label=%s, shape=%s, fillcolor=\"%s\", style=\"filled,rounded\"];\n",
				nodeIDs[id], htmlLabel, shape, color)
		}

		// 写入边，使用HTML标签增强显示
		for j, edge := range path.Edges {
			var labelParts []string

			// 添加步骤编号和攻击行为
			labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"12\"><B>步骤 %d</B></FONT>", j+1))
			labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"11\">%s</FONT>", escapeHTML(edge.Action)))

			// 添加前置条件
			if len(edge.Prerequisites) > 0 {
				labelParts = append(labelParts, "<FONT POINT-SIZE=\"10\"><I>前置条件:</I></FONT>")
				for _, prereq := range edge.Prerequisites {
					labelParts = append(labelParts, fmt.Sprintf("<FONT POINT-SIZE=\"9\">• %s</FONT>", escapeHTML(prereq)))
				}
			}

			// 合并所有部分为一个HTML标签
			htmlLabel := fmt.Sprintf("<%s>", strings.Join(labelParts, "<BR/>"))

			// 设置边的颜色，使用渐变色从绿到红表示路径进展
			edgeColor := fmt.Sprintf("#%02X%02X00",
				int(float64(j+1)/float64(len(path.Edges))*255.0),
				int(255.0-float64(j+1)/float64(len(path.Edges))*255.0))

			fmt.Fprintf(file, "    \"%s\" -> \"%s\" [label=%s, color=\"%s\", penwidth=1.5];\n",
				nodeIDs[edge.From.ID], nodeIDs[edge.To.ID], htmlLabel, edgeColor)
		}

		fmt.Fprintln(file, "  }")
	}

	// 写入DOT文件尾
	fmt.Fprintln(file, "}")

	return nil
}

// GenerateAttackGraphImage 生成攻击图图片，支持多种格式和参数
func GenerateAttackGraphImage(dotFilePath, imageFilePath string, format string, dpi int) error {
	// 检查是否安装了Graphviz
	_, err := exec.LookPath("dot")
	if err != nil {
		return fmt.Errorf("未找到Graphviz的dot命令，请安装Graphviz: %v", err)
	}

	// 如果未指定格式，默认使用PNG
	if format == "" {
		format = "png"
	}

	// 如果未指定DPI，默认使用300
	if dpi <= 0 {
		dpi = 300
	}

	// 使用dot命令生成图片，添加DPI设置以提高图像质量
	cmd := exec.Command("dot", fmt.Sprintf("-T%s", format),
		fmt.Sprintf("-Gdpi=%d", dpi), dotFilePath, "-o", imageFilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("生成图片失败: %v, 输出: %s", err, string(output))
	}

	return nil
}

// 工具函数：清理GraphViz ID中的特殊字符
func sanitizeGraphvizID(id string) string {
	// 将非字母数字字符替换为下划线
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, id)
}

// 工具函数：HTML转义
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
func areNodesRelated(node1, node2 *model.StateNode) bool {
	// 检查是否是Pod和它所在的Node
	if strings.HasPrefix(node1.ID, "pod-") && strings.HasPrefix(node2.ID, "node-") {
		if nodeName, exists := node1.Context["nodeName"]; exists && nodeName != nil {
			nodeParts := strings.Split(node2.ID, "-")
			if len(nodeParts) > 1 && nodeParts[1] == fmt.Sprintf("%v", nodeName) {
				return true
			}
		}
	} else if strings.HasPrefix(node2.ID, "pod-") && strings.HasPrefix(node1.ID, "node-") {
		if nodeName, exists := node2.Context["nodeName"]; exists && nodeName != nil {
			nodeParts := strings.Split(node1.ID, "-")
			if len(nodeParts) > 1 && nodeParts[1] == fmt.Sprintf("%v", nodeName) {
				return true
			}
		}
	}
	return false
}
