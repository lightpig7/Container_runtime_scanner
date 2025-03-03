package data

import (
	"fmt"
	"log"
	"os"
	"regexp"
)

func RegexGetBool(expected_output string, output string) bool {
	re, err := regexp.Compile(expected_output)
	if err != nil {
		log.Fatal(err)
	}
	found := re.MatchString(output)
	return found
}
func ReadLog(containerName string) (string, error) {
	logFilePath := fmt.Sprintf("./internal/data/LOG/%s_scan.log", containerName)

	// 读取日志文件内容
	data, err := os.ReadFile(logFilePath)
	if err != nil {
		return "", fmt.Errorf("无法读取日志文件: %v", err)
	}

	return string(data), nil
}
