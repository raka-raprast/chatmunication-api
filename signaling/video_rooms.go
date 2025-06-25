package signaling

import (
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	Conn      *websocket.Conn
	RoomID    string
	IsOfferer bool // New
}

type Room struct {
	Clients map[*Client]bool
	Mu      sync.Mutex
}

var rooms = make(map[string]*Room)
var roomsMu sync.Mutex

func AddClientToRoom(roomId string, client *Client) {
	roomsMu.Lock()
	defer roomsMu.Unlock()

	room, exists := rooms[roomId]
	if !exists {
		room = &Room{Clients: make(map[*Client]bool)}
		rooms[roomId] = room
	}

	room.Mu.Lock()
	room.Clients[client] = true
	room.Mu.Unlock()

	// Send back the number of users in the room
	userCount := len(room.Clients)
	client.Conn.WriteJSON(map[string]interface{}{
		"type":      "join_ack",
		"userCount": userCount,
	})
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func BroadcastToRoom(roomId string, sender *Client, messageType int, data []byte) {
	room := rooms[roomId]
	if room == nil {
		return
	}

	room.Mu.Lock()
	defer room.Mu.Unlock()

	for client := range room.Clients {
		if client != sender {
			client.Conn.WriteMessage(messageType, data)
		}
	}
}

func RemoveClient(client *Client) {
	room := rooms[client.RoomID]
	if room == nil {
		return
	}

	room.Mu.Lock()
	defer room.Mu.Unlock()

	delete(room.Clients, client)

	// Broadcast to others that this client has left
	for otherClient := range room.Clients {
		otherClient.Conn.WriteJSON(map[string]interface{}{
			"type":   "user_left",
			"roomId": client.RoomID,
		})
	}

	client.Conn.Close()

	// Optionally, clean up empty room
	if len(room.Clients) == 0 {
		roomsMu.Lock()
		delete(rooms, client.RoomID)
		roomsMu.Unlock()
	}
}
