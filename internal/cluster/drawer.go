package cluster

import (
	"context"
	"fmt"
	"github.com/goccy/go-graphviz"
	"io/ioutil"
)

func GenerateGraphImageWithGoGraphviz(dotFilePath, imageFilePath string) error {
	// 创建新的graphviz实例
	ctx := context.Background()
	g, err := graphviz.New(ctx)
	defer g.Close()

	// 读取DOT文件内容
	dotContent, err := ioutil.ReadFile(dotFilePath)
	if err != nil {
		return fmt.Errorf("读取DOT文件失败: %v", err)
	}
	dotContentStr := string(dotContent)

	// 调试输出
	fmt.Println("DOT文件内容:")
	fmt.Println(dotContentStr)
	// 解析DOT内容
	graph, err := graphviz.ParseBytes(dotContent)
	if err != nil {
		return fmt.Errorf("解析DOT内容失败: %v", err)
	}
	defer graph.Close()

	// 将图形渲染为PNG文件
	if err := g.RenderFilename(ctx, graph, graphviz.PNG, imageFilePath); err != nil {
		return fmt.Errorf("渲染图片失败: %v", err)
	}
	if err := g.RenderFilename(ctx, graph, graphviz.PNG, imageFilePath); err != nil {
		return fmt.Errorf("渲染图片失败: %v", err)
	}

	fmt.Println("成功生成图片:", imageFilePath)
	return nil
}
