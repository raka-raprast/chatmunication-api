package main

import (
	"auth-api/config"
	"auth-api/routes"
	"auth-api/signaling"

	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadEnv()
	// The signaling layer used to re-load .env and re-decode the key in its
	// own init(), which ran before LoadEnv and duplicated the startup log.
	// Hand it the already-validated key instead.
	signaling.LoadEncryptionKey(config.EncryptionKey)

	config.InitRedis()
	config.ConnectDB()

	r := gin.Default()
	routes.AuthRoutes(r)
	routes.WebSocketRoutes(r)
	routes.UserRoutes(r)
	routes.GroupRoutes(r)

	r.Run("0.0.0.0:2340")
}
