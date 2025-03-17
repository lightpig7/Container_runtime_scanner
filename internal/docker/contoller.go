package docker

import (
	"bufio"
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
	"net/http"
	"os"
	"strconv"
	"strings"
)

// 全局 Docker 客户端对象
var cli *client.Client
var SSHClient *ssh.Client

// init 初始化 Docker 客户端
func init() {
	//var err error
	//cli, err = client.NewClientWithOpts(client.WithVersion("1.42"), client.WithAPIVersionNegotiation())
	//if err != nil {
	//	log.Fatalln("初始化 Docker 客户端失败: " + err.Error())
	//}
	sshInit()
}
func sshClose() {
	if SSHClient != nil {
		SSHClient.Close()
	}
}
func sshInit() {
	sshConfig := &ssh.ClientConfig{
		User: "ubuntu",
		Auth: []ssh.AuthMethod{
			ssh.Password("ubuntu"), // 也可以使用密钥认证
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 生产环境请勿使用这个
	}

	// 建立 SSH 连接
	var err error
	SSHClient, err = ssh.Dial("tcp", "192.168.52.142:22", sshConfig)
	if err != nil {
		fmt.Printf("SSH 连接失败: %v\n", err)
		return
	}
	fmt.Printf("SSH 连接成功\n")

	// 创建一个通过 SSH 转发到 Docker socket 的代理
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		session, err := SSHClient.NewSession()
		if err != nil {
			return nil, err
		}

		socketPath := "/var/run/docker.sock"
		cmd := fmt.Sprintf("socat UNIX-LISTEN:%s,fork,mode=777 UNIX-CONNECT:%s", socketPath, socketPath)

		if err := session.Start(cmd); err != nil {
			return nil, err
		}

		return SSHClient.Dial("unix", socketPath)
	}

	// 创建自定义 HTTP 客户端
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}

	// 初始化 Docker 客户端
	cli, err = client.NewClientWithOpts(
		client.WithHTTPClient(httpClient),
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		fmt.Printf("Docker 客户端创建失败: %v\n", err)
		return
	}

	_, err = cli.Info(context.Background())
	if err != nil {
		fmt.Printf("Docker 信息获取失败: %v\n", err)
		return
	}

	fmt.Printf("Docker连接成功! \n")
}

// Container 结构体，封装了容器的相关操作
type Container struct {
	Id      string
	Name    string
	Image   string
	Status  string
	Ports   []types.Port
	Mounts  []types.MountPoint
	Created string
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
		err = cli.ContainerRemove(context.Background(), s.Id, types.ContainerRemoveOptions{})
	}
	return err
}

// Run 启动容器，并附加标准输出流
func (s *Container) Run() error {
	err := cli.ContainerStart(context.Background(), s.Id, types.ContainerStartOptions{})
	if err != nil {
		return err
	}

	// 获取容器的标准输出流，并在主机上显示
	hresp, err := cli.ContainerAttach(context.Background(), s.Id, types.ContainerAttachOptions{Stream: true, Stdout: true, Stderr: true})
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
		types.ExecConfig{
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
	resp, err := cli.ContainerExecAttach(context.Background(), execResp.ID, types.ExecStartCheck{})
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
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: false})
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
	fmt.Println(result)
	return result
}

func main() {
	// 1. 创建容器，并挂载主机目录到容器
	cont, err := NewContainerWithLink("my_container", "/docker/path", "/host/path")
	if err != nil {
		log.Fatalf("创建容器失败: %v", err)
	}
	fmt.Println("容器创建成功，ID:", cont.Id)

	// 2. 运行容器
	if err := cont.Run(); err != nil {
		log.Fatalf("运行容器失败: %v", err)
	}
	fmt.Println("容器正在运行...")

	//var str string
	////fmt.Scan(&str)
	////if str == "0" {
	////	break
	////}
	//fmt.Println(str)
	//// 3. 在容器中执行 ls 命令
	//output, err := cont.Exec("sh", "-c", "cat /proc/self/status |grep Cap") //"cat /proc/self/status |grep Cap"
	//if err != nil {
	//	log.Fatalf("执行命令失败: %v", err)
	//}
	//fmt.Println("执行结果:\n", output)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("输入命令: ")
		str, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("读取输入失败: %v", err)
		}

		str = strings.TrimSpace(str) // 移除换行符和多余空格
		if str == "0" {
			break
		}

		fmt.Println("执行命令:", str)

		output := cont.Exec("sh", "-c", str)

		fmt.Println("执行结果:\n", output)
	}

	fmt.Println(ListRunningContainers())
	// 4. 停止容器
	if err := cont.Stop(); err != nil {
		log.Printf("停止容器失败: %v", err)
	} else {
		fmt.Println("容器已停止")
	}
	// 5. 删除容器
	if err := cont.Close(); err != nil {
		log.Printf("删除容器失败: %v", err)
	} else {
		fmt.Println("容器已删除")
	}
}
