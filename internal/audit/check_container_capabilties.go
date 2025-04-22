package audit

import (
	"Container_runtime_scanner/internal/docker"
	"context"
	"github.com/docker/docker/api/types/container"
	"log"
)

func CheckContainerCapabilities(logger *log.Logger) {
	cli := docker.Cli

	containers, err := cli.ContainerList(context.Background(), container.ListOptions{})

	if err != nil {
		logger.Println(err)
	}

	for _, container := range containers {
		info, err := cli.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			logger.Println("Error inspecting container:", container.ID)
			continue
		}
		hasCapAdd := len(info.HostConfig.CapAdd) > 0
		hasCapDrop := ""
		if len(info.HostConfig.CapDrop) > 0 {
			hasCapDrop = info.HostConfig.CapDrop[0]
		}

		if hasCapAdd && hasCapDrop != "all" {
			logger.Println("⚠️ 注意：容器可能具有过多权限")
			logger.Printf("容器：%s\n", container.Names[0])
			logger.Printf("添加的Capabilities: %v\n", info.HostConfig.CapAdd)
			logger.Printf("移除的Capabilities: %v\n", info.HostConfig.CapDrop)
			logger.Println()
		}

	}
}
