package audit

import (
	"fmt"
	"log"
	"os"
)

func Audit_start() {
	logFile, err := os.OpenFile("./internal/data/log/audit.log", os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)
	Permissions := IsRootDockerDaemon()
	if Permissions {
		logger.Println("Docker守护进程以root启动")
		fmt.Println("Docker守护进程以root启动")
	}
	a, b, err := CheckDockerTCPStatusViaSSH()
	if a && b {
		logger.Println("Docker开启TCP端口并开启TSL身份认证")
		fmt.Println("Docker开启TCP端口并开启TSL身份认证")
	} else if a && !b {
		logger.Println("Docker开启TCP端口并未开启TSL身份认证,会造成Docker 远程 API 未授权访问逃逸")
		fmt.Println("Docker开启TCP端口并未开启TSL身份认证,会造成Docker 远程 API 未授权访问逃逸")
	} else {
		logger.Println("Docker未开启TCP端口")
		fmt.Println("Docker未开启TCP端口")
	}
	if err != nil {
		return
	}
	logger.Println("特权容器有: ")
	fmt.Println("特权容器有: ")
	for _, container := range IsPrivate() {
		logger.Println(container)
		fmt.Println(container)
	}
	VersionMatch(logger)
}
