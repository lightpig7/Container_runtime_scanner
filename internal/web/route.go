package web

import (
	"Container_runtime_scanner/internal/docker"
	"Container_runtime_scanner/internal/pentest"
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
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello Gin!"})
	})

	r.POST("/DockerGet", func(c *gin.Context) {
		containers := docker.ListRunningContainersInfo()
		//result := DockerController.ConvertToString(containers)
		success(c, containers)

	})

	r.POST("/Penetrate", func(c *gin.Context) {
		pentest.Run()
	})
	r.POST("/PenetrateLog", func(c *gin.Context) {

	})
	err := r.Run(":8080")
	if err != nil {
		return
	}
}
