package docker

import (
	"context"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// 全局 Docker 客户端对象
var cli *client.Client
var Cli *client.Client
var SSHClient *ssh.Client

type Container struct {
	Id      string
	Name    string
	Image   string
	Status  string
	Ports   []types.Port
	Mounts  []types.MountPoint
	Created string
}
type DockerInformation struct {
	DockerVersion    string
	RuncVersion      string
	APIVersion       string
	ContainerVersion string
	KernelVersion    string
	GoVersion        string
	GitVersion       string
	OSVersion        string
}

// init 初始化 Docker 客户端
func init() {
	//var err error
	//cli, err = client.NewClientWithOpts(client.WithAPIVersionNegotiation(), client.WithAPIVersionNegotiation())
	//if err != nil {
	//	log.Fatalln("初始化 Docker 客户端失败: " + err.Error())
	//}

}
func sshClose() {
	if SSHClient != nil {
		SSHClient.Close()
	}
}

func SSHInit(ip string) {
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
	SSHClient, err = ssh.Dial("tcp", ip+":22", sshConfig)
	if err != nil {
		fmt.Printf("SSH 连接失败: %v\n", err)
		return
	}
	fmt.Printf("SSH 连接成功\n")

	// 建立一个通过SSH转发的TCP连接来访问远程Docker socket
	// 首先创建一个本地随机端口的监听器
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("创建本地监听器失败: %v\n", err)
		return
	}
	localAddr := localListener.Addr().String()

	// 启动一个goroutine来处理SSH端口转发
	go func() {
		for {
			// 接受本地连接
			localConn, err := localListener.Accept()
			if err != nil {
				fmt.Printf("接受本地连接失败: %v\n", err)
				return
			}

			// 通过SSH连接到远程Docker socket
			remoteConn, err := SSHClient.Dial("unix", "/var/run/docker.sock")
			if err != nil {
				fmt.Printf("连接远程Docker socket失败: %v\n", err)
				localConn.Close()
				continue
			}

			// 启动goroutine双向转发数据
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

	// 等待端口转发准备就绪
	time.Sleep(1 * time.Second)

	// 使用标准Docker客户端连接到本地转发的端口
	dockerHost := fmt.Sprintf("tcp://%s", localAddr)
	cli, err = client.NewClientWithOpts(
		client.WithHost(dockerHost),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		fmt.Printf("Docker 客户端创建失败: %v\n", err)
		return
	}

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = cli.Ping(ctx)
	if err != nil {
		fmt.Printf("Docker 连接测试失败: %v\n", err)
		return
	}

	fmt.Printf("Docker连接成功! \n")
	Cli = cli
}
func GetTemp() string {
	session, err := SSHClient.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %s", err)
	}
	defer session.Close()
	output, err := session.CombinedOutput("echo ${TMPDIR:-/tmp}")
	if err != nil {
		log.Fatalf("Failed to run command: %s", err)
	}

	// 输出结果
	return string(output)
}

func CreatFile(filePath string, Content string) {
	session, err := SSHClient.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %s", err)
	}
	defer session.Close()
	cmd := fmt.Sprintf("echo %s > %s", Content, filePath)
	_, err = session.CombinedOutput(cmd)
	if err != nil {
		log.Println("Command failed:", err)
	}
}
func DeleteFile(filePath string) {
	session, err := SSHClient.NewSession()
	if err != nil {
		log.Fatalf("Failed to delete session: %s", err)
	}
	defer session.Close()
	cmd := fmt.Sprintf("rm -rf %s", filePath)
	_, err = session.CombinedOutput(cmd)
	if err != nil {
		log.Println("Command failed:", err)
	}
}

func getComponent(components []types.ComponentVersion, component string) string {

	for _, value := range components {
		if value.Name == component {
			return value.Version
		}
	}
	return "nil"
}

// Container 结构体，封装了容器的相关操作
func GetInfo() DockerInformation {
	var information DockerInformation
	info, err := cli.Info(context.Background())
	if err != nil {
		log.Fatalf("无法获取Docker信息: %v", err)
	}

	// 获取版本信息以进行漏洞匹配
	version, err := cli.ServerVersion(context.Background())
	if err != nil {
		log.Fatalf("无法获取Docker版本: %v", err)
	}

	information.DockerVersion = version.Version
	information.APIVersion = version.APIVersion
	information.GoVersion = version.GoVersion
	information.GitVersion = version.GitCommit
	information.OSVersion = version.Os
	information.ContainerVersion = getComponent(version.Components, "containerd")
	information.RuncVersion = info.RuncCommit.ID
	information.KernelVersion = info.KernelVersion

	return information
}

// NewContainerWithLink 创建一个 Docker 容器，并挂载主机目录到容器
func NewContainerWithLink(container_name, docker_filepath, host_path string) (*Container, error) {
	resp, err := cli.ContainerCreate(
		context.Background(),
		&container.Config{
			Image:        "ubuntu", // 使用 ubuntu 镜像
			WorkingDir:   "/root",  // 设置容器的工作目录
			Tty:          true,     // 允许 TTY 交互
			AttachStdout: true,     // 附加标准输出
			AttachStderr: true,     // 附加标准错误输出
		},
		&container.HostConfig{
			Privileged: true,
			// 绑定主机目录到容器
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: host_path,       // 宿主机目录路径
					Target: docker_filepath, // 容器内挂载的路径
					BindOptions: &mount.BindOptions{
						CreateMountpoint: true, // 自动创建挂载点
					},
				},
			},
		},
		nil, nil, container_name,
	)

	if err == nil {
		return &Container{Id: resp.ID}, nil
	}
	return nil, err
}

// Stop 停止容器
func (s *Container) Stop() error {
	return cli.ContainerStop(context.Background(), s.Id, container.StopOptions{Signal: "SIGQUIT"})
}

// Close 停止并删除容器
func (s *Container) Close() error {
	err := s.Stop()
	if err == nil {
		err = cli.ContainerRemove(context.Background(), s.Id, container.RemoveOptions{})
	}
	return err
}

// Run 启动容器，并附加标准输出流
func (s *Container) Run() error {
	err := cli.ContainerStart(context.Background(), s.Id, container.StartOptions{})
	if err != nil {
		return err
	}

	// 获取容器的标准输出流，并在主机上显示
	hresp, err := cli.ContainerAttach(context.Background(), s.Id, container.AttachOptions{Stream: true, Stdout: true, Stderr: true})
	if err != nil {
		return err
	}

	// 启动一个 goroutine，将容器输出流复制到主机的标准输出
	go func() {
		_, err2 := io.Copy(os.Stdout, hresp.Conn)
		if err2 != nil {
			fmt.Fprintln(os.Stderr, err2.Error())
		}
	}()

	return nil
}

// Exec 在容器中执行命令
func (s *Container) Exec(cmd string, args ...string) string {
	cmds := append([]string{cmd}, args...) // 构造命令数组

	// 创建 exec 任务
	execResp, err := cli.ContainerExecCreate(
		context.Background(),
		s.Id,
		container.ExecOptions{
			Tty:          false, // 关闭 TTY 以便解析输出
			AttachStdout: true,
			AttachStderr: true,
			Cmd:          cmds, // 需要执行的命令及其参数
		},
	)
	if err != nil {
		log.Fatalf("创建 Exec 失败: %v", err)
		return ""
	}

	// 执行 exec 任务，并获取标准输出
	resp, err := cli.ContainerExecAttach(context.Background(), execResp.ID, container.ExecStartOptions{})
	if err != nil {
		log.Fatalf("创建 Exec 失败: %v", err)
		return ""
	}
	defer resp.Close()

	// 读取 stdout 和 stderr
	output, err := io.ReadAll(resp.Reader)
	if err != nil {
		log.Fatalf("创建 Exec 失败: %v", err)
		return ""
	}

	return string(output)
}

// ListRunningContainers 获取所有正在运行的容器
func ListRunningContainers() []*Container {
	containers, err := cli.ContainerList(context.Background(), container.ListOptions{All: false})
	if err != nil {
		log.Fatalf("获取容器列表失败: %v", err)
	}

	result := make([]*Container, 0, len(containers))
	for _, c := range containers {
		// 获取单个容器的详细信息
		detailedInfo, err := cli.ContainerInspect(context.Background(), c.ID)
		if err != nil {
			log.Printf("获取容器 %s 的详细信息失败: %v", c.ID, err)
			continue
		}
		var portList []types.Port
		for portKey, bindings := range detailedInfo.NetworkSettings.Ports {
			containerPort, _ := nat.ParsePort(portKey.Port())
			for _, binding := range bindings {
				publicPort, _ := strconv.Atoi(binding.HostPort)
				portList = append(portList, types.Port{
					PrivatePort: uint16(containerPort),
					PublicPort:  uint16(publicPort),
					Type:        portKey.Proto(),
				})
			}
		}
		result = append(result, &Container{
			Id:      detailedInfo.ID,
			Name:    strings.Trim(detailedInfo.Name, "/"),
			Image:   detailedInfo.Config.Image,
			Status:  detailedInfo.State.Status,
			Ports:   portList,
			Mounts:  detailedInfo.Mounts,
			Created: detailedInfo.Created,
		})
	}
	return result
}
func CheckDockerRootSimple() (bool, error) {
	if cli == nil {
		return false, fmt.Errorf("Docker客户端未初始化")
	}

	// 获取Docker信息
	info, err := cli.Info(context.Background())
	if err != nil {
		return false, fmt.Errorf("获取Docker信息失败: %v", err)
	}

	isRoot := false
	for _, SecurityOption := range info.SecurityOptions {
		if !strings.Contains(strings.ToLower(SecurityOption), "rootless") {
			isRoot = true
			break
		}
	}

	return isRoot, nil
}
