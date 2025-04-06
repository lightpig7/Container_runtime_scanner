package audit

import (
	"Container_runtime_scanner/internal/docker"
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"strings"
)

func CheckSensitiveMounts() {
	cli := docker.Cli
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}

	sensitiveDirs := []string{
		"/etc", "/boot", "/dev", "/lib", "/lib64",
		"/proc", "/root", "/run", "/sys", "/usr", "/var",
	}

	for _, container := range containers {
		info, err := cli.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			fmt.Printf("Error inspecting container: %s\n", container.ID)
			continue
		}

		for _, mount := range info.Mounts {
			for _, dir := range sensitiveDirs {
				if strings.HasPrefix(mount.Source, dir) {
					if mount.RW {
						fmt.Println("⚠️ 警告：容器挂载了敏感主机目录并具有读写权限！")
						fmt.Printf("容器: %s\n", container.Names[0])
						fmt.Printf("挂载路径: %s -> %s\n", mount.Source, mount.Destination)
						fmt.Printf("挂载模式: RW\n")
						fmt.Println()
					} else {
						// 可选：提示但不是严重问题
						fmt.Println("⚠️ 提示：容器挂载了敏感目录，但为只读模式")
						fmt.Printf("容器: %s\n", container.Names[0])
						fmt.Printf("挂载路径: %s -> %s\n", mount.Source, mount.Destination)
						fmt.Printf("挂载模式: RO\n")
						fmt.Println()
					}
				}
			}
		}
	}
}
