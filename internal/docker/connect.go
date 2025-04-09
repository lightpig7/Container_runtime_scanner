package docker

import (
	"context"
	"fmt"
	"github.com/docker/docker/client"
	"net"
	"net/http"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ConnectionType 连接类型
type ConnectionType string

const (
	// LocalConnection 本地连接
	LocalConnection ConnectionType = "local"
	// SSHConnection SSH远程连接
	SSHConnection ConnectionType = "ssh"
)

// DockerConnectionManager Docker连接管理器
type DockerConnectionManager struct {
	currentType  ConnectionType
	dockerClient *client.Client
	sshClient    *ssh.Client
	sshConfig    *ssh.ClientConfig
	sshHost      string
	mu           sync.Mutex
}

// NewDockerConnectionManager 创建新的连接管理器
func NewDockerConnectionManager() *DockerConnectionManager {
	return &DockerConnectionManager{
		currentType: LocalConnection,
	}
}

// ConfigureSSH 配置SSH连接参数
func (m *DockerConnectionManager) ConfigureSSH(host, user, password string) {
	m.sshHost = host
	m.sshConfig = &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 注意：生产环境不应使用此回调
	}
}

// ConfigureSSHWithKey 使用SSH密钥配置连接
func (m *DockerConnectionManager) ConfigureSSHWithKey(host, user string, privateKey []byte) error {
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("解析SSH私钥失败: %v", err)
	}

	m.sshHost = host
	m.sshConfig = &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 注意：生产环境不应使用此回调
	}
	return nil
}

// GetConnectionType 获取当前连接类型
func (m *DockerConnectionManager) GetConnectionType() ConnectionType {
	return m.currentType
}

// UseLocalConnection 切换到本地连接
func (m *DockerConnectionManager) UseLocalConnection() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 如果已经是本地连接，且客户端存在，则直接返回
	if m.currentType == LocalConnection && m.dockerClient != nil {
		return nil
	}

	// 关闭可能存在的SSH连接
	if m.sshClient != nil {
		m.sshClient.Close()
		m.sshClient = nil
	}

	// 关闭可能存在的Docker客户端
	if m.dockerClient != nil {
		m.dockerClient.Close()
		m.dockerClient = nil
	}

	// 创建新的本地Docker客户端
	var err error
	m.dockerClient, err = client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return fmt.Errorf("初始化本地Docker客户端失败: %v", err)
	}

	// 测试连接
	_, err = m.dockerClient.Info(context.Background())
	if err != nil {
		m.dockerClient.Close()
		m.dockerClient = nil
		return fmt.Errorf("本地Docker连接测试失败: %v", err)
	}

	m.currentType = LocalConnection
	fmt.Println("已切换到本地Docker连接")
	return nil
}

// UseSSHConnection 切换到SSH连接
func (m *DockerConnectionManager) UseSSHConnection() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sshConfig == nil || m.sshHost == "" {
		return fmt.Errorf("SSH配置未设置，请先调用ConfigureSSH方法")
	}

	// 如果已经是SSH连接且客户端存在，则直接返回
	if m.currentType == SSHConnection && m.dockerClient != nil && m.sshClient != nil {
		return nil
	}

	// 关闭可能存在的SSH连接
	if m.sshClient != nil {
		m.sshClient.Close()
		m.sshClient = nil
	}

	// 关闭可能存在的Docker客户端
	if m.dockerClient != nil {
		m.dockerClient.Close()
		m.dockerClient = nil
	}

	// 建立新的SSH连接
	var err error
	m.sshClient, err = ssh.Dial("tcp", m.sshHost, m.sshConfig)
	if err != nil {
		return fmt.Errorf("SSH连接失败: %v", err)
	}

	// 创建一个通过SSH转发到Docker socket的代理
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		session, err := m.sshClient.NewSession()
		if err != nil {
			return nil, fmt.Errorf("创建SSH会话失败: %v", err)
		}

		socketPath := "/var/run/docker.sock"
		cmd := fmt.Sprintf("socat UNIX-LISTEN:%s,fork,mode=777 UNIX-CONNECT:%s", socketPath, socketPath)

		if err := session.Start(cmd); err != nil {
			return nil, fmt.Errorf("启动socat命令失败: %v", err)
		}

		return m.sshClient.Dial("unix", socketPath)
	}

	// 创建自定义HTTP客户端
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}

	// 初始化Docker客户端
	m.dockerClient, err = client.NewClientWithOpts(
		client.WithHTTPClient(httpClient),
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		m.sshClient.Close()
		m.sshClient = nil
		return fmt.Errorf("Docker客户端创建失败: %v", err)
	}

	// 测试连接
	_, err = m.dockerClient.Info(context.Background())
	if err != nil {
		m.dockerClient.Close()
		m.dockerClient = nil
		m.sshClient.Close()
		m.sshClient = nil
		return fmt.Errorf("远程Docker连接测试失败: %v", err)
	}

	m.currentType = SSHConnection
	fmt.Println("已切换到SSH Docker连接")
	return nil
}

// GetClient 获取当前Docker客户端
func (m *DockerConnectionManager) GetClient() *client.Client {
	return m.dockerClient
}

// Close 关闭所有连接
func (m *DockerConnectionManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.dockerClient != nil {
		m.dockerClient.Close()
		m.dockerClient = nil
	}

	if m.sshClient != nil {
		m.sshClient.Close()
		m.sshClient = nil
	}
}

// 使用示例
func Test() {
	// 创建连接管理器
	manager := NewDockerConnectionManager()
	defer manager.Close()

	// 使用本地连接
	err := manager.UseLocalConnection()
	if err != nil {
		fmt.Printf("本地连接失败: %v\n", err)
	} else {
		// 使用manager.GetClient()执行Docker操作
		fmt.Println("本地Docker连接成功")
	}

	// 配置并使用SSH连接
	manager.ConfigureSSH("192.168.52.142:22", "ubuntu", "ubuntu")
	err = manager.UseSSHConnection()
	if err != nil {
		fmt.Printf("SSH连接失败: %v\n", err)
	} else {
		// 使用manager.GetClient()执行Docker操作
		fmt.Println("SSH Docker连接成功")
	}

	// 随时可以切换回本地连接
	manager.UseLocalConnection()
}
