package audit

import "fmt"

func Audit_start() {

	Permissions := IsRootDockerDaemon()
	if Permissions {
		fmt.Println("Docker守护进程以root启动")
	}
	a, b, err := CheckDockerTCPStatusViaSSH()
	if a && b {
		fmt.Println("Docker开启TCP端口并开启TSL身份认证")
	} else if a && !b {
		fmt.Println("Docker开启TCP端口并未开启TSL身份认证,会造成Docker 远程 API 未授权访问逃逸")
	} else {
		fmt.Println("Docker未开启TCP端口")
	}
	if err != nil {
		return
	}

	fmt.Println("特权容器有: ")
	for _, a := range IsPrivate() {
		fmt.Println(a)
	}
	VersionMatch()
}
