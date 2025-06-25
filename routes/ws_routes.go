package routes

import (
	"auth-api/controllers"

	"github.com/gin-gonic/gin"
)

func WebSocketRoutes(r *gin.Engine) {
	// WebRTC signaling (for SDP, ICE, etc.)
	r.GET("/ws", func(c *gin.Context) {
		controllers.WebSocketHandler(c.Writer, c.Request)
	})

	// Call invite/response signaling (for UI-level call events)
	r.GET("/user-socket", func(c *gin.Context) {
		controllers.UserSocketHandler(c.Writer, c.Request)
	})
}
