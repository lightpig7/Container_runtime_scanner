package data

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"regexp"
	"time"
)

func RegexGetBool(expected_output string, output string) bool {
	re, err := regexp.Compile(expected_output)
	if err != nil {
		log.Fatal(err)
	}
	found := re.MatchString(output)
	return found
}
func ReadLog(containerName string, mode string) (string, error) {
	var logFilePath string
	if mode == "container" {
		logFilePath = fmt.Sprintf("./internal/data/log/%s_scan.log", containerName)
	}
	if mode == "audit" {
		logFilePath = fmt.Sprintf("./internal/data/log/audit.log")
	}

	// 读取日志文件内容
	data, err := os.ReadFile(logFilePath)
	if err != nil {
		return "", fmt.Errorf("无法读取日志文件: %v", err)
	}

	return string(data), nil
}

func ReadAuxFile(containerName string) (string, error) {
	logFilePath := fmt.Sprintf("./internal/data/auxiliary/%s", containerName)

	data, err := os.ReadFile(logFilePath)
	if err != nil {
		return "", fmt.Errorf("无法读取日志文件: %v", err)
	}

	return string(data), nil
}
func GenerateRandomString(length int) string {
	// 定义可能的字符集
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 创建一个有种子的随机数生成器
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// 创建一个长度为 length 的字节数组
	result := make([]byte, length)

	// 为每个位置随机选择一个字符
	for i := 0; i < length; i++ {
		result[i] = charset[r.Intn(len(charset))]
	}

	return string(result)
}
