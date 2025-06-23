package ws

import (
	"auth-api/config"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // TODO: tighten in production
	},
}

func ServeWebSocket(c *gin.Context) {
	tokenString := c.Query("token")
	roomID := c.Query("room")

	// Verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return config.JWT_SECRET, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	userID := claims["user_id"].(string)

	wsConn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	conn := &Connection{ws: wsConn, send: make(chan []byte, 256)}
	client := &Client{ID: userID, Conn: conn, RoomID: roomID}

	H.JoinRoom(roomID, userID, client)

	// Reader
	go conn.ReadPump(client)

	// Writer
	go conn.WritePump()

	// Clean up
	defer func() {
		H.LeaveRoom(roomID, userID)
		conn.Close()
	}()
}
