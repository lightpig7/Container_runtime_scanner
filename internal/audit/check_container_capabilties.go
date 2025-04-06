package audit

import (
	"Container_runtime_scanner/internal/docker"
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
)

func CheckContainerCapabilities() {
	cli := docker.Cli

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}

	for _, container := range containers {
		info, err := cli.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			fmt.Println("Error inspecting container:", container.ID)
			continue
		}
		hasCapAdd := len(info.HostConfig.CapAdd) > 0
		hasCapDrop := ""
		if len(info.HostConfig.CapDrop) > 0 {
			hasCapDrop = info.HostConfig.CapDrop[0]
		}

		if hasCapAdd && hasCapDrop != "all" {
			fmt.Println("⚠️ 注意：容器可能具有过多权限")
			fmt.Printf("容器：%s\n", container.Names[0])
			fmt.Printf("添加的Capabilities: %v\n", info.HostConfig.CapAdd)
			fmt.Printf("移除的Capabilities: %v\n", info.HostConfig.CapDrop)
			fmt.Println()
		}

	}
}
