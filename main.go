package main

import (
	"auth-api/config"
	"auth-api/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadEnv()
	config.InitRedis()
	config.ConnectDB()

	r := gin.Default()
	routes.AuthRoutes(r)
	routes.WebSocketRoutes(r)
	routes.UserRoutes(r)

	r.Run("0.0.0.0:2340")
}
