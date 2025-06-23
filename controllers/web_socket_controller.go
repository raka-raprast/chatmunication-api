package controllers

import (
	"auth-api/signaling"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // allow all origins for dev
	},
}

func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	roomId := r.URL.Query().Get("room")

	if token == "" || roomId == "" {
		http.Error(w, "Missing token or room ID", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade failed:", err)
		return
	}

	client := &signaling.Client{
		Conn:   conn,
		RoomID: roomId,
	}

	signaling.AddClientToRoom(roomId, client)
	log.Printf("Client joined room %s", roomId)

	defer signaling.RemoveClient(client)

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		// Forward message to other clients in the same room
		signaling.BroadcastToRoom(roomId, client, messageType, message)
	}
}
