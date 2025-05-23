package web

import (
	"Container_runtime_scanner/internal/audit"
	"Container_runtime_scanner/internal/data"
	"Container_runtime_scanner/internal/docker"
	"Container_runtime_scanner/internal/pentest"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type SSHConfig struct {
	IP       string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:    200,
		Message: "success",
		Data:    data,
	})
}

func fail(c *gin.Context, code int, message string) {
	c.JSON(code, Response{
		Code:    code,
		Message: message,
		Data:    nil,
	})
}
func Create() {
	r := gin.Default()
	r.Use(gin.Logger()) // 启用日志中间件
	r.Use(gin.Recovery())
	r.Static("/assets", "./internal/web/static/assets")               // 让 Gin 服务器正确加载前端资源
	r.StaticFile("/favicon.ico", "./internal/web/static/favicon.ico") // 让 favicon 正常加载

	r.StaticFS("/static", http.Dir("internal/web/static"))
	r.GET("/", func(c *gin.Context) {
		c.File("internal/web/static/index.html")
	})

	r.POST("/docker/containers", func(c *gin.Context) {
		fmt.Println("docker.ListRunningContainers()")
		ip := c.PostForm("ip")

		docker.SSHInit(ip)
		containers := docker.ListRunningContainers()
		success(c, containers)

	})

	r.POST("/docker/penetrate", func(c *gin.Context) {
		ip := c.PostForm("ip")
		docker.SSHInit(ip)
		fmt.Println("pentest.Run()")
		pentest.Run()
	})
	r.POST("/docker/audit", func(c *gin.Context) {
		ip := c.PostForm("ip")
		docker.SSHInit(ip)
		fmt.Println("audit.Audit_start()")
		audit.Audit_start()
		success(c, "success")
	})
	r.POST("/docker/audit/log", func(c *gin.Context) {
		logContent, err := data.ReadLog("", "audit")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"log": logContent})
	})

	r.POST("/docker/log", func(c *gin.Context) {
		containerName := c.PostForm("container")
		fmt.Println("Received container parameter:", containerName)

		if containerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 container 参数"})
			return
		}

		logContent, err := data.ReadLog(containerName, "container")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 以 JSON 格式返回日志内容
		c.JSON(http.StatusOK, gin.H{"log": logContent})
	})

	r.POST("/cluster/graph", func(c *gin.Context) {
		GraphContent, err := os.ReadFile("internal/cluster/output/graph.json")
		ip := c.PostForm("ip")
		docker.SSHInit(ip)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 以 JSON 格式返回日志内容
		c.JSON(http.StatusOK, gin.H{"graph": GraphContent})
	})

	//SSH
	r.POST("/docker/ssh/containers", func(c *gin.Context) {
		fmt.Println("docker.ListRunningContainers()")

		var sshConfig SSHConfig
		if err := c.ShouldBindJSON(&sshConfig); err != nil {
			c.JSON(400, gin.H{"error": "SSH配置格式错误"})
			return
		}
		docker.SSHInit(sshConfig.IP)
		containers := docker.ListRunningContainers()
		success(c, containers)

	})

	r.POST("/docker/ssh/penetrate", func(c *gin.Context) {
		fmt.Println("docker.ListRunningContainers()")
		var sshConfig SSHConfig
		if err := c.ShouldBindJSON(&sshConfig); err != nil {
			c.JSON(400, gin.H{"error": "SSH配置格式错误"})
			return
		}
		fmt.Println(sshConfig.IP, sshConfig.Port)
		docker.SSHInit(sshConfig.IP)
		fmt.Println("pentest.Run()")
		pentest.Run()
	})
	r.POST("/docker/ssh/audit", func(c *gin.Context) {
		fmt.Println("docker.ListRunningContainers()")
		var sshConfig SSHConfig
		if err := c.ShouldBindJSON(&sshConfig); err != nil {
			c.JSON(400, gin.H{"error": "SSH配置格式错误"})
			return
		}
		docker.SSHInit(sshConfig.IP)
		fmt.Println("audit.Audit_start()")
		audit.Audit_start()
		success(c, "success")
	})
	r.POST("/docker/ssh/audit/log", func(c *gin.Context) {
		logContent, err := data.ReadLog("", "audit")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"log": logContent})
	})

	r.POST("/docker/ssh/log", func(c *gin.Context) {
		containerName := c.PostForm("container")
		fmt.Println("Received container parameter:", containerName)

		if containerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 container 参数"})
			return
		}

		logContent, err := data.ReadLog(containerName, "container")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 以 JSON 格式返回日志内容
		c.JSON(http.StatusOK, gin.H{"log": logContent})
	})

	r.POST("/cluster/ssh/graph", func(c *gin.Context) {
		fmt.Println("docker.ListRunningContainers()")

		//var sshConfig SSHConfig
		//if err := c.ShouldBindJSON(&sshConfig); err != nil {
		//	c.JSON(400, gin.H{"error": "SSH配置格式错误"})
		//	return
		//}
		//docker.SSHInit(sshConfig.IP)

		raw, err := os.ReadFile("internal/cluster/output/graph.json")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var graphData interface{}
		if err := json.Unmarshal(raw, &graphData); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "不是合法的 JSON"})
			return
		}
		// 以 JSON 格式返回日志内容
		c.Data(http.StatusOK, "application/json", raw)
	})
	r.POST("/download/vuldatabase", func(c *gin.Context) {
		data.ExtractContainerVulnerabilities()
	})

	err := r.Run("0.0.0.0:8080")
	if err != nil {
		return
	}
}
