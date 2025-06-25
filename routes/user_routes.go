package routes

import (
	"auth-api/config"
	"auth-api/handlers"

	"github.com/gin-gonic/gin"
)

func UserRoutes(r *gin.Engine) {
	userGroup := r.Group("/api/users")
	{
		userGroup.GET("/", handlers.GetAllUsers(config.DB))
		userGroup.GET("/chat-history", handlers.GetChatHistory(config.DB))
		userGroup.GET("/with-last-message", handlers.GetUsersWithLastMessage(config.DB))
	}
}
