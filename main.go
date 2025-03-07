package main

import (
	"context"
	"fmt"
	"github.com/docker/docker/client"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http"
)

func main() {
	//cont, err := DockerController.NewContainerWithLink("my_container", "/var/run/docker.sock", "/var/run/docker.sock")
	//if err != nil {
	//	log.Fatalf("创建容器失败: %v", err)
	//}
	//fmt.Println("容器创建成功，ID:", cont.Id)
	//
	//if err := cont.Run(); err != nil {
	//	log.Fatalf("运行容器失败: %v", err)
	//}
	//fmt.Println("容器正在运行...")
	//
	//VerifyVul(cont)
	//
	//if err := cont.Stop(); err != nil {
	//	log.Printf("停止容器失败: %v", err)
	//} else {
	//	fmt.Println("容器已停止")
	//}
	//
	//if err := cont.Close(); err != nil {
	//	log.Printf("删除容器失败: %v", err)
	//} else {
	//	fmt.Println("容器已删除")
	//}
	//pentest.Run()
	//web.Create()
	// 设置 SSH 连接配置
	sshConfig := &ssh.ClientConfig{
		User: "ubuntu",
		Auth: []ssh.AuthMethod{
			ssh.Password("ubuntu"), // 也可以使用密钥认证
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 生产环境请勿使用这个
	}

	// 建立 SSH 连接
	sshClient, err := ssh.Dial("tcp", "192.168.52.140:22", sshConfig)
	if err != nil {
		fmt.Printf("SSH 连接失败: %v\n", err)
		return
	}
	defer sshClient.Close()

	// 创建一个通过 SSH 转发到 Docker socket 的代理
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return sshClient.Dial(network, "localhost:2375") // Docker 默认 API 端口
	}

	// 创建自定义 HTTP 客户端
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}

	// 初始化 Docker 客户端
	dockerClient, err := client.NewClientWithOpts(
		client.WithHTTPClient(httpClient),
		client.WithHost("http://localhost:2375"),
		client.WithVersion("1.42"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		fmt.Printf("Docker 客户端创建失败: %v\n", err)
		return
	}

	// 测试连接
	info, err := dockerClient.Info(context.Background())
	if err != nil {
		fmt.Printf("Docker 信息获取失败: %v\n", err)
		return
	}

	fmt.Printf("连接成功! Docker 信息: %+v\n", info)
}
