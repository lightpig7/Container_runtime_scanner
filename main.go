package main

import "Container_runtime_scanner/internal/pentest/exp"

func main() {

	//web.Create()
	// 设置 SSH 连接配置
	exp.CheckRrverseShell("8888")
}
