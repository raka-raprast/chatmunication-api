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
		userGroup.POST("/contacts/:id", handlers.AddContact(config.DB))
		userGroup.DELETE("/contacts/:id", handlers.RemoveContact(config.DB))
		userGroup.GET("/search", handlers.SearchUsers(config.DB))
		userGroup.GET("/:id", handlers.GetUserByID(config.DB))
		userGroup.PUT("/:id/fcm-token", handlers.UpdateFCMToken(config.DB))
	}
}
