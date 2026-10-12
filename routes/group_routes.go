package routes

import (
	"auth-api/config"
	"auth-api/handlers"

	"github.com/gin-gonic/gin"
)

func GroupRoutes(r *gin.Engine) {
	groupRoutes := r.Group("/api/groups")
	{
		groupRoutes.POST("/", handlers.CreateGroup(config.DB))
		groupRoutes.GET("/", handlers.GetUserGroups(config.DB))
		groupRoutes.GET("/:id/messages", handlers.GetGroupMessages(config.DB))
		groupRoutes.GET("/:id/members", handlers.GetGroupMembers(config.DB))
		groupRoutes.GET("/:id/pending-invites", handlers.GetGroupPendingInvites(config.DB))
		groupRoutes.POST("/:id/members", handlers.AddGroupMembers(config.DB))
		groupRoutes.DELETE("/:id/members/:userId", handlers.RemoveGroupMember(config.DB))
		groupRoutes.PUT("/:id/read", handlers.MarkGroupMessagesRead(config.DB))
		groupRoutes.GET("/invites", handlers.GetGroupInvites(config.DB))
		groupRoutes.POST("/invites/:id/accept", handlers.AcceptGroupInvite(config.DB))
		groupRoutes.POST("/invites/:id/decline", handlers.DeclineGroupInvite(config.DB))
	}
}
