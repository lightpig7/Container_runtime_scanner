package WebController

import (
	"Container_runtime_scanner/DockerController"
	"Container_runtime_scanner/PenetrationTestController"
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
		containers := DockerController.ListRunningContainersInfo()
		//result := DockerController.ConvertToString(containers)
		success(c, containers)

	})

	r.POST("/penetrate", func(c *gin.Context) {
		PenetrationTestController.Run()
	})
	err := r.Run(":8080")
	if err != nil {
		return
	}
}
