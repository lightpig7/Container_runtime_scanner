package cluster

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"os"
)

var K8sClient *kubernetes.Clientset

func TestA() {
	// SSH连接配置
	sshHost := "192.168.52.150"
	sshPort := "22"
	sshUser := "ubuntu"
	sshPassword := "ubuntu" // 使用密码而非密钥

	// 建立SSH连接
	sshClient, err := connectSSHWithPassword(sshHost, sshPort, sshUser, sshPassword)
	if err != nil {
		log.Fatalf("无法建立SSH连接: %v", err)
	}
	defer sshClient.Close()
	fmt.Println("SSH连接成功建立")

	// 从远程获取kubeconfig
	kubeconfig, err := getRemoteKubeconfig(sshClient)
	if err != nil {
		log.Fatalf("无法获取远程kubeconfig: %v", err)
	}

	// 使用获取的kubeconfig连接Kubernetes集群
	clientset, err := connectK8s(kubeconfig)

	if err != nil {
		log.Fatalf("无法连接到Kubernetes集群: %v", err)
	}
	K8sClient = clientset
	// 获取集群信息示例
	version, err := clientset.Discovery().ServerVersion()
	if err != nil {
		log.Fatalf("无法获取Kubernetes版本: %v", err)
	}
	fmt.Printf("成功连接到Kubernetes集群，版本: %s\n", version.String())
}

// 使用密码建立SSH连接
func connectSSHWithPassword(host, port, user, password string) (*ssh.Client, error) {
	// 设置SSH客户端配置
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password), // 使用密码认证
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 生产环境不建议使用
	}

	// 连接到SSH服务器
	addr := fmt.Sprintf("%s:%s", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("SSH拨号失败: %v", err)
	}

	return client, nil
}

// 从远程主机获取kubeconfig文件内容
func getRemoteKubeconfig(client *ssh.Client) ([]byte, error) {
	// 创建新会话
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("无法创建SSH会话: %v", err)
	}
	defer session.Close()

	// 远程kubeconfig路径，通常在~/.kube/config
	remoteKubeconfigPath := "/home/ubuntu/.kube/config"

	// 执行命令获取kubeconfig内容
	var out bytes.Buffer
	session.Stdout = &out
	if err := session.Run(fmt.Sprintf("cat %s", remoteKubeconfigPath)); err != nil {
		return nil, fmt.Errorf("无法执行远程命令: %v", err)
	}

	return out.Bytes(), nil
}

// 使用kubeconfig连接到Kubernetes集群
func connectK8s(kubeconfig []byte) (*kubernetes.Clientset, error) {
	// 创建临时文件存储kubeconfig
	tmpfile, err := ioutil.TempFile("", "kubeconfig-")
	if err != nil {
		return nil, fmt.Errorf("无法创建临时kubeconfig文件: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(kubeconfig); err != nil {
		return nil, fmt.Errorf("无法写入临时kubeconfig文件: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		return nil, fmt.Errorf("无法关闭临时kubeconfig文件: %v", err)
	}

	// 使用kubeconfig创建客户端配置
	config, err := clientcmd.BuildConfigFromFlags("", tmpfile.Name())
	if err != nil {
		return nil, fmt.Errorf("无法构建kubeconfig: %v", err)
	}

	// 创建clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("无法创建Kubernetes客户端: %v", err)
	}

	return clientset, nil
}
