package docker

import (
	"Container_runtime_scanner/internal/data"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

func (s *Container) IsDocker() bool {
	respone := s.Exec("ls /.dockerenv")
	if !data.RegexGetBool("No such file or directory", respone) {
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
		if data.RegexGetBool(" --->test1", step) {
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
	max_1 := -1
	for _, match := range matches {
		if num, err := strconv.Atoi(match[1]); err == nil && num > max_1 {
			max_1 = num
		}
	}
	return strconv.Itoa(max_1)
}

func ConvertToString(result []*ContainerInfo) string {
	// 带缩进的美化输出
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("序列化失败: %v", err)
		return ""
	}
	return string(data)
}
