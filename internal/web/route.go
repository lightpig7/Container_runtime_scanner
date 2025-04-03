package web

import (
	"Container_runtime_scanner/internal/audit"
	"Container_runtime_scanner/internal/data"
	"Container_runtime_scanner/internal/docker"
	"Container_runtime_scanner/internal/pentest"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
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
		containers := docker.ListRunningContainers()
		success(c, containers)

	})

	r.POST("/docker/penetrate", func(c *gin.Context) {
		fmt.Println("pentest.Run()")
		pentest.Run()
	})
	r.POST("/docker/audit", func(c *gin.Context) {
		fmt.Println("audit.Audit_start()")
		audit.Audit_start()
	})
	r.POST("/docker/log", func(c *gin.Context) {
		containerName := c.PostForm("container")
		fmt.Println("Received container parameter:", containerName)
		if containerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 container 参数"})
			return
		}

		// 读取日志
		logContent, err := data.ReadLog(containerName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 以 JSON 格式返回日志内容
		c.JSON(http.StatusOK, gin.H{"log": logContent})
	})
	err := r.Run("0.0.0.0:8080")
	if err != nil {
		return
	}
}
