package audit

import (
	"Container_runtime_scanner/internal/docker"
	"regexp"
	"strings"
)

func CheckContainerUserIsRoot() []string {
	containers := docker.ListRunningContainers()
	ContainersRoot := make([]string, 0, len(containers))

	re := regexp.MustCompile(`\D`)
	for _, container := range containers {
		output := strings.TrimSpace(container.Exec("id", "-u"))

		cleanedOutput := re.ReplaceAllString(output, "")
		if cleanedOutput == "0" {
			ContainersRoot = append(ContainersRoot, container.Name)
		}

	}
	return ContainersRoot
}
