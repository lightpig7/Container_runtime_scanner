package main

import (
	"Container_runtime_scanner/DataController"
	"Container_runtime_scanner/DockerController"
	"fmt"
	"log"
)

func VerifyVul(cont *DockerController.Container) {
	if !cont.IsDocker() {
		log.Fatalf("该系统不是容器")
	}
	pocs := DataController.ReadFile("./DataController/database.json")
	for _, poc := range pocs {
		fmt.Println("----------------------")
		fmt.Printf("POC: %s\nCVE ID: %s\n描述: %s\n", poc.PocName, poc.CveID, poc.Description)
		output := cont.Exec("sh", "-c", poc.TestCmd)
		fmt.Println("\npoc.TestCmd:\n", poc.TestCmd)
		fmt.Println("output:\n", output)

		if DataController.RegexGetBool(poc.ExpectedOutput, output) {
			fmt.Println("该漏洞可能存在")
			cont.ExecStep(poc.ExploitationSteps)
			verify_respone := cont.ExecStep(poc.VerifySteps)
			if DataController.RegexGetBool(poc.VerifyOutput, verify_respone) {
				fmt.Println("验证漏洞成功，并成功逃逸·")
			} else {
				fmt.Println("逃逸失败")
			}
			fmt.Println("删除测试记录")
			cont.ExecStep(poc.LastStep)
		} else {
			fmt.Println("该漏洞不存在")
		}

		fmt.Println("----------------------")
	}
}

func main() {
	cont, err := DockerController.NewContainerWithLink("my_container", "/var/run/docker.sock", "/var/run/docker.sock")
	if err != nil {
		log.Fatalf("创建容器失败: %v", err)
	}
	fmt.Println("容器创建成功，ID:", cont.Id)

	if err := cont.Run(); err != nil {
		log.Fatalf("运行容器失败: %v", err)
	}
	fmt.Println("容器正在运行...")

	VerifyVul(cont)

	if err := cont.Stop(); err != nil {
		log.Printf("停止容器失败: %v", err)
	} else {
		fmt.Println("容器已停止")
	}

	if err := cont.Close(); err != nil {
		log.Printf("删除容器失败: %v", err)
	} else {
		fmt.Println("容器已删除")
	}

}
