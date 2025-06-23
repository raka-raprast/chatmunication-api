package routes

import (
	"auth-api/controllers"
	"auth-api/middleware"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/register", controllers.Register)
		auth.POST("/login", controllers.Login)
		auth.GET("/me", middleware.JWTAuthMiddleware(), controllers.Me)
	}
}
