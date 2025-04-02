package main

import (
	"Container_runtime_scanner/internal/audit"
	"Container_runtime_scanner/internal/docker"
	"fmt"
)

func main() {
	audit.VersionMatch()
	simple, err := docker.CheckDockerRootSimple()
	if err != nil {
		return
	}
	fmt.Println(simple)
	//web.Create()
	//data.ExtractContainerVersions()
	// 设置 SSH 连接配置
	//docker.Test()
	//docker.GetVersion()
	//docker.GetInfo()
	//data.UpdateData()
	//exp.CheckRrverseShell("8888")
}
