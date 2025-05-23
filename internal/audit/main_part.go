package audit

import (
	"log"
	"os"
)

func Audit_start() {
	logFile, err := os.OpenFile("./internal/data/log/audit.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)
	Permissions := IsRootDockerDaemon()
	if Permissions {
		logger.Println("Docker守护进程以root启动")
	}
	a, b, err := CheckDockerTCPStatusViaSSH()
	if a && b {
		logger.Println("Docker开启TCP端口并开启TSL身份认证")
	} else if a && !b {
		logger.Println("Docker开启TCP端口并未开启TSL身份认证,会造成Docker 远程 API 未授权访问逃逸")
	} else {
		logger.Println("Docker未开启TCP端口")
	}
	if err != nil {
		return
	}
	logger.Println("特权容器有: ")
	for _, container := range IsPrivate() {
		logger.Println(container)
	}
	VersionMatch(logger)
	rootContainers := CheckContainerUserIsRoot()
	if len(rootContainers) == 0 {
		logger.Println("全部容器以非 root 用户运行")

	} else {
		logger.Println("以下容器以 root 用户运行：")
		for _, name := range rootContainers {
			logger.Printf("- %s\n", name)
		}
	}
	CheckSensitiveMounts(logger)
	CheckContainerCapabilities(logger)
}
