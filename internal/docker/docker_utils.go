package docker

import (
	"Container_runtime_scanner/internal/data"
	"encoding/json"
	"fmt"
	"log"
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
	for _, step := range steps {

		fmt.Println("执行命令: ", step)
		response = s.Exec("sh", "-c", step)
		fmt.Println(response)

	}
	return response
}
func (s *Container) ShExecStep(step string) string {
	response := s.Exec("sh", "-c", step)
	return response
}

// 从输出中提取最大数字（例如 sda3 → 3）

func ConvertToString(result []*Container) string {
	// 带缩进的美化输出
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("序列化失败: %v", err)
		return ""
	}
	return string(data)
}
