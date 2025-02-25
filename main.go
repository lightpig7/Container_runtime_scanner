package main

import (
	"Container_runtime_scanner/DataController"
	"Container_runtime_scanner/DockerController"
	"fmt"
	"log"
	"regexp"
)

func VerifyVul(cont *DockerController.Container) {
	pocs, err := DataController.ReadFile("./database.json")
	if err != nil {
		log.Fatalf("读取失败：%v", err)
	}
	for _, poc := range pocs {

		fmt.Println("----------------------")
		fmt.Printf("POC: %s\nCVE ID: %s\n描述: %s\n", poc.PocName, poc.CveID, poc.Description)
		output := cont.Exec("sh", "-c", poc.TestCmd)
		fmt.Println("\npoc.TestCmd:\n", poc.TestCmd)
		re, err := regexp.Compile(poc.ExpectedResult)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("output:\n", output)

		found := re.MatchString(output)
		var respone string
		if found {
			fmt.Println("该漏洞可能存在")
			for _, step := range poc.ExploitationSteps {
				fmt.Println("执行命令: ", step)
				respone = cont.Exec("sh", "-c", step)
				fmt.Println(respone)
			}
			if respone != cont.Exec("sh", "-c", "cat /etc/passwd") {
				fmt.Println(cont.Exec("sh", "-c", "cat /etc/passwd"))
				fmt.Println("成功发现漏洞，并且逃逸成功")
			} else {
				fmt.Println("未发现该漏洞")
			}
		}
		fmt.Println("----------------------")
	}

}
func main() {
	cont, err := DockerController.NewContainerWithLink("my_container", "/docker/path", "/host/path")
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
