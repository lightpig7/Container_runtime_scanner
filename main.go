package main

import (
	"Container_runtime_scanner/internal/audit"
	"Container_runtime_scanner/internal/data"
	"Container_runtime_scanner/internal/docker"
)

func main() {
	//audit.CheckSensitiveMounts()
	//audit.Audit_start()
	//cluster.Test()
	//containerd.TestMain()
	//data.FetchContainerVulnerabilities()
	//docker.ListRunningContainers()
	//web.Create()
	//containerd.TestMain()
	data.ExtractContainerVulnerabilities()
	docker.SSHInit("192.168.52.150")
	audit.Audit_start()
	//containerd.TestMain()
	//data.ExtractContainerVersions()
	// 设置 SSH 连接配置
	//docker.Test()
	//docker.GetVersion()
	//docker.GetInfo()
	//data.UpdateData()
	//exp.CheckRrverseShell("8888")
}
