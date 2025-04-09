package containerd

import (
	"fmt"
	"time"
)

// 将TestMain函数修改为导出函数（首字母大写），以便从其他包调用
func TestMain() {
	fmt.Println("开始测试 Containerd 接口...")

	// 初始化连接
	sshInit()
	defer sshClose()

	// 等待连接建立
	time.Sleep(2 * time.Second)

	if client == nil {
		fmt.Println("无法连接到 Containerd 服务")
		return
	}

	// 1. 获取 Containerd 信息
	fmt.Println("\n== 系统信息 ==")
	info := GetInfo()
	fmt.Printf("Containerd 版本: %s\n", info.ContainerdVersion)
	fmt.Printf("Runc 版本: %s\n", info.RuncVersion)
	fmt.Printf("内核版本: %s\n", info.KernelVersion)
	fmt.Printf("操作系统版本: %s\n", info.OSVersion)

	// 2. 检查权限
	fmt.Println("\n== 权限检查 ==")
	isPrivileged, err := CheckPrivileged()
	if err != nil {
		fmt.Printf("检查权限失败: %v\n", err)
	} else {
		fmt.Printf("Containerd 以 root 权限运行: %v\n", isPrivileged)
	}

	// 3. 列出容器
	fmt.Println("\n== 容器列表 ==")
	containers := ListRunningContainers()
	fmt.Printf("发现 %d 个运行中的容器\n", len(containers))

	for i, container := range containers {
		fmt.Printf("容器 #%d:\n", i+1)
		fmt.Printf("  - ID: %s\n", container.Id)
		fmt.Printf("  - 名称: %s\n", container.Name)
		fmt.Printf("  - 镜像: %s\n", container.Image)
		fmt.Printf("  - 状态: %s\n", container.Status)
		fmt.Printf("  - 创建时间: %s\n", container.Created)
	}

	// 4. 在第一个容器中执行命令（如果有容器）
	if len(containers) > 0 {
		fmt.Println("\n== 命令执行测试 ==")
		container := containers[0]
		fmt.Printf("在容器 %s 中执行命令...\n", container.Name)

		output, err := ExecuteCommand(container.Id, []string{"ls", "-la", "/"})
		if err != nil {
			fmt.Printf("执行命令失败: %v\n", err)
		} else {
			fmt.Printf("命令输出:\n%s\n", output)
		}
	}

	fmt.Println("\n✅ 测试完成")
}
