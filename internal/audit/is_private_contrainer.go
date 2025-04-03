package audit

import (
	"Container_runtime_scanner/internal/docker"
	"context"
	"github.com/docker/docker/api/types"
	"log"
)

func IsPrivate() []string {
	cli := docker.Cli
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})

	privilegedContainers := []string{}
	if err != nil {
		log.Printf("无法列出容器: %v", err)
	} else {

		for _, container := range containers {
			inspect, err := cli.ContainerInspect(context.Background(), container.ID)
			if err != nil {
				continue
			}

			if inspect.HostConfig.Privileged {
				privilegedContainers = append(privilegedContainers, container.Names[0])
			}
		}

	}
	return privilegedContainers
}
