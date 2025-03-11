package main

import "Container_runtime_scanner/internal/web"

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
	web.Create()
	// 设置 SSH 连接配置

}
