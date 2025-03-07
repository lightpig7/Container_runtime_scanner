package docker

import (
	"Container_runtime_scanner/internal/data"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"io"
	"log"
	"os"
	"path/filepath"
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

func (s *Container) CopyFileToContainer(localFilePath, containerPath string) error {

	// 打开源文件
	srcFile, err := os.Open("./internal/data/auxiliary/" + localFilePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// 获取文件信息
	_, err = srcFile.Stat()
	if err != nil {
		return err
	}

	// 创建一个 tar 归档
	// Docker API 接受 tar 格式的文件传输
	ctx := context.Background()

	// 复制到容器
	return cli.CopyToContainer(ctx, s.Id, filepath.Dir(containerPath), io.NopCloser(srcFile), types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true,
		CopyUIDGID:                true,
	})
}
func (s *Container) CopyFileToContainerBase64(localFilePath, containerPath string) error {
	// 读取文件内容
	fileContent, err := os.ReadFile("./internal/data/auxiliary/" + localFilePath)
	if err != nil {
		return err
	}

	// Base64 编码
	encoded := base64.StdEncoding.EncodeToString(fileContent)

	// 确保目标目录存在
	//dirPath := filepath.Dir(containerPath)
	//s.ShExecStep(fmt.Sprintf("mkdir -p %s", dirPath))

	// 在容器中创建文件
	cmd := fmt.Sprintf("echo '%s' | base64 -d > %s", encoded, containerPath)
	s.ShExecStep(cmd)

	// 设置可执行权限（如果需要）
	s.ShExecStep(fmt.Sprintf("chmod +x %s", containerPath))

	return nil
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
