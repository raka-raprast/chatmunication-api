package routes

import (
	"auth-api/controllers"

	"github.com/gin-gonic/gin"
)

func WebSocketRoutes(r *gin.Engine) {
	r.GET("/ws", func(c *gin.Context) {
		controllers.WebSocketHandler(c.Writer, c.Request)
	})
}
