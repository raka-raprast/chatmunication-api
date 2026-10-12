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
		userGroup.PUT("/messages/read", handlers.MarkMessagesRead(config.DB))
		userGroup.POST("/contacts/:id", handlers.AddContact(config.DB))
		userGroup.POST("/contacts/:id/accept", handlers.AcceptContactRequest(config.DB))
		userGroup.POST("/contacts/:id/decline", handlers.DeclineContactRequest(config.DB))
		userGroup.GET("/contacts/requests", handlers.GetIncomingContactRequests(config.DB))
		userGroup.GET("/contacts/requests/sent", handlers.GetSentContactRequests(config.DB))
		userGroup.DELETE("/contacts/:id", handlers.RemoveContact(config.DB))
		userGroup.GET("/search", handlers.SearchUsers(config.DB))
		userGroup.GET("/:id", handlers.GetUserByID(config.DB))
		userGroup.PUT("/:id/fcm-token", handlers.UpdateFCMToken(config.DB))
	}
}
