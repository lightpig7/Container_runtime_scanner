package audit

import (
	"Container_runtime_scanner/internal/docker"
	"fmt"
)

func IsRootDockerDaemon() bool {
	simple, err := docker.CheckDockerRootSimple()
	if err != nil {
		fmt.Println(err)
	}
	return simple
}
