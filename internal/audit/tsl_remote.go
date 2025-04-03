package audit

import (
	"Container_runtime_scanner/internal/docker"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

func CheckDockerTCPStatus() (tcpEnabled bool, tlsEnabled bool, err error) {
	// 使用传入的主机名，默认为localhost

	host := "localhost"
	// 检查非TLS端口 (2375)
	tcpConn, err := net.DialTimeout("tcp", host+":2375", 3*time.Second)
	if err == nil {
		tcpEnabled = true
		tcpConn.Close()
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 仅用于测试
	}

	// 检查TLS端口 (2376)
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		host+":2376",
		tlsConfig,
	)
	if err == nil {
		tlsEnabled = true
		tlsConn.Close()
	}

	// 返回结果，不返回错误，因为我们只是在测试连接
	return tcpEnabled, tlsEnabled, nil
}
func CheckDockerTCPStatusViaSSH() (tcpEnabled bool, tlsEnabled bool, err error) {
	sshClient := docker.SSHClient
	if sshClient == nil {
		return false, false, fmt.Errorf("SSH客户端未初始化")
	}
	session1, err := sshClient.NewSession()
	if err != nil {
		return false, false, fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session1.Close()

	// 检查非TLS端口 (2375)
	output1, err := session1.CombinedOutput("nc -z -w3 localhost 2375 && echo 'open' || echo 'closed'")
	if err == nil && strings.Contains(string(output1), "open") {
		tcpEnabled = true
	}

	// 检查TLS端口 (2376)
	session2, err := sshClient.NewSession()
	if err != nil {
		return tcpEnabled, false, fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session2.Close()

	output2, err := session2.CombinedOutput("nc -z -w3 localhost 2376 && echo 'open' || echo 'closed'")
	if err == nil && strings.Contains(string(output2), "open") {
		tlsEnabled = true
	}

	return tcpEnabled, tlsEnabled, nil
}
