package audit

import (
	"Container_runtime_scanner/internal/docker"
	"context"
	"github.com/docker/docker/api/types/container"
	"log"
	"strings"
)

func CheckSensitiveMounts(logger *log.Logger) {
	cli := docker.Cli
	containers, err := cli.ContainerList(context.Background(), container.ListOptions{})
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
			logger.Printf("Error inspecting container: %s\n", container.ID)
			continue
		}

		for _, mount := range info.Mounts {
			for _, dir := range sensitiveDirs {
				if strings.HasPrefix(mount.Source, dir) {
					if mount.RW {
						logger.Println("⚠️ 警告：容器挂载了敏感主机目录并具有读写权限！")
						logger.Printf("容器: %s\n", container.Names[0])
						logger.Printf("挂载路径: %s -> %s\n", mount.Source, mount.Destination)
						logger.Printf("挂载模式: RW\n")
						logger.Println()
					} else {
						logger.Println("⚠️ 提示：容器挂载了敏感目录，但为只读模式")
						logger.Printf("容器: %s\n", container.Names[0])
						logger.Printf("挂载路径: %s -> %s\n", mount.Source, mount.Destination)
						logger.Printf("挂载模式: RO\n")
						logger.Println()
					}
				}
			}
		}
	}
}
