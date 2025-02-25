package DockerController

import (
	"Container_runtime_scanner/DataController"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func (s *Container) IsDocker() bool {
	respone := s.Exec("ls /.dockerenv")
	if !DataController.RegexGetBool("No such file or directory", respone) {
		return true
	} else {
		return false
	}
}

func (s *Container) ExecStep(steps []string) string {
	var response string
	var extractedValue string
	NextStepFlag := false
	for _, step := range steps {
		if NextStepFlag {
			step = strings.Replace(step, "_", extractedValue, -1)
		}
		if DataController.RegexGetBool(" --->test1", step) {
			step = strings.Trim(step, " --->test1")

			fmt.Println("执行命令: ", step)
			response = s.Exec("sh", "-c", step)
			fmt.Println(response)

			NextStepFlag = true
			extractedValue = ExtractMaxNumber(response)
		} else {
			fmt.Println("执行命令: ", step)
			response = s.Exec("sh", "-c", step)
			fmt.Println(response)
		}

	}
	return response
}

// 从输出中提取最大数字（例如 sda3 → 3）
func ExtractMaxNumber(output string) string {
	re := regexp.MustCompile(`sda(\d+)`)
	matches := re.FindAllStringSubmatch(output, -1)
	max := -1
	for _, match := range matches {
		if num, err := strconv.Atoi(match[1]); err == nil && num > max {
			max = num
		}
	}
	return strconv.Itoa(max)
}
