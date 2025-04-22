package containerd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"golang.org/x/crypto/ssh"
)

// 全局 containerd 客户端对象
var client *containerd.Client
var Client *containerd.Client
var SSHClient *ssh.Client

type Container struct {
	Id      string
	Name    string
	Image   string
	Status  string
	Labels  map[string]string
	Created string
}

type ContainerdInformation struct {
	ContainerdVersion string
	RuncVersion       string
	APIVersion        string
	KernelVersion     string
	GoVersion         string
	GitVersion        string
	OSVersion         string
}

// init 初始化 containerd 客户端
func init() {
	sshInit()
	Client = client
}

func sshClose() {
	if SSHClient != nil {
		SSHClient.Close()
	}
	if client != nil {
		client.Close()
	}
}

func sshInit() {
	sshConfig := &ssh.ClientConfig{
		User: "ubuntu",
		Auth: []ssh.AuthMethod{
			ssh.Password("ubuntu"), // 也可以使用密钥认证
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 生产环境请勿使用这个
		Timeout:         30 * time.Second,
	}

	// 建立 SSH 连接
	var err error
	SSHClient, err = ssh.Dial("tcp", "192.168.52.150:22", sshConfig)
	if err != nil {
		fmt.Printf("SSH 连接失败: %v\n", err)
		return
	}
	fmt.Printf("SSH 连接成功\n")

	// 建立一个通过SSH转发的Unix socket连接来访问远程containerd socket
	// 首先创建一个本地随机端口的监听器
	// 1. 启动本地监听器
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("创建本地监听器失败: %v\n", err)
		return
	}
	localAddr := localListener.Addr().String()

	// 2. 启动 SSH 到远程 socket 的数据转发
	go func() {
		for {
			localConn, err := localListener.Accept()
			if err != nil {
				fmt.Printf("接受本地连接失败: %v\n", err)
				return
			}

			remoteConn, err := SSHClient.Dial("unix", "/run/containerd/containerd.sock")
			if err != nil {
				fmt.Printf("连接远程containerd socket失败: %v\n", err)
				localConn.Close()
				continue
			}

			go func() {
				defer localConn.Close()
				defer remoteConn.Close()
				io.Copy(localConn, remoteConn)
			}()
			go func() {
				defer localConn.Close()
				defer remoteConn.Close()
				io.Copy(remoteConn, localConn)
			}()
		}
	}()

	// 3. 等待转发就绪
	time.Sleep(1 * time.Second)

	// 4. 正确创建 containerd 客户端
	client, err = containerd.New("tcp://" + localAddr)
	if err != nil {
		fmt.Printf("containerd 客户端创建失败: %v\n", err)
		return
	}

}

// GetInfo 获取containerd信息
func GetInfo() ContainerdInformation {
	var information ContainerdInformation
	ctx := context.Background()

	// 获取版本信息
	version, err := client.Version(ctx)
	if err != nil {
		log.Fatalf("无法获取containerd版本: %v", err)
	}

	// 执行命令获取更详细的信息
	session, err := SSHClient.NewSession()
	if err != nil {
		log.Fatalf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	// 执行命令获取containerd和runc版本
	output, err := session.CombinedOutput("containerd --version && runc --version")
	if err != nil {
		log.Fatalf("执行命令失败: %v", err)
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	information.ContainerdVersion = version.Version
	information.GitVersion = version.Revision

	// 解析输出获取runc版本
	for _, line := range lines {
		if strings.Contains(line, "runc version") {
			parts := strings.Split(line, " ")
			if len(parts) > 2 {
				information.RuncVersion = parts[2]
			}
		}
	}

	// 获取OS版本
	session, err = SSHClient.NewSession()
	if err != nil {
		log.Fatalf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	output, err = session.CombinedOutput("cat /etc/os-release")
	if err != nil {
		log.Fatalf("执行命令失败: %v", err)
	}

	outputStr = string(output)
	lines = strings.Split(outputStr, "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "VERSION=") {
			information.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		}
	}

	// 获取内核版本
	session, err = SSHClient.NewSession()
	if err != nil {
		log.Fatalf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	output, err = session.CombinedOutput("uname -r")
	if err != nil {
		log.Fatalf("执行命令失败: %v", err)
	}

	information.KernelVersion = strings.TrimSpace(string(output))

	return information
}

// ListRunningContainers 获取所有正在运行的容器
func ListRunningContainers() []*Container {
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")
	containers, err := client.Containers(ctx)
	if err != nil {
		log.Fatalf("获取容器列表失败: %v", err)
	}

	result := make([]*Container, 0, len(containers))
	for _, c := range containers {
		info, err := c.Info(ctx)
		if err != nil {
			log.Printf("获取容器 %s 的信息失败: %v", c.ID(), err)
			continue
		}

		// 获取容器状态
		task, err := c.Task(ctx, nil)
		var status string
		if err != nil {
			status = "unknown"
		} else {
			statusResponse, err := task.Status(ctx)
			if err != nil {
				status = "unknown"
			} else {
				status = string(statusResponse.Status)
			}
		}

		result = append(result, &Container{
			Id:      c.ID(),
			Name:    info.Labels["io.kubernetes.container.name"],
			Image:   info.Image,
			Status:  status,
			Labels:  info.Labels,
			Created: info.CreatedAt.Format(time.RFC3339),
		})
	}
	return result
}

// ExecuteCommand 在容器中执行命令
func ExecuteCommand(containerID string, cmd []string) (string, error) {
	// 对于containerd，执行命令需要通过SSH
	session, err := SSHClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	// 使用crictl命令执行 (需要在远程主机上安装crictl)
	cmdStr := fmt.Sprintf("crictl exec %s %s", containerID, strings.Join(cmd, " "))
	output, err := session.CombinedOutput(cmdStr)
	if err != nil {
		return "", fmt.Errorf("执行命令失败: %v", err)
	}

	return string(output), nil
}

// CheckPrivileged 检查containerd是否以root权限运行
func CheckPrivileged() (bool, error) {
	session, err := SSHClient.NewSession()
	if err != nil {
		return false, fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput("ps -ef | grep containerd | grep -v grep")
	if err != nil {
		return false, fmt.Errorf("执行命令失败: %v", err)
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	for _, line := range lines {
		if strings.Contains(line, "containerd") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "root" {
				return true, nil
			}
		}
	}

	return false, nil
}
