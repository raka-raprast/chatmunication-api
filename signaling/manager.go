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
	defer room.Mu.Unlock()

	client.IsOfferer = len(room.Clients) == 0 // First one is offerer
	room.Clients[client] = true

	// Notify the client of their role
	rolePayload := []byte(`{"type":"ready","isOfferer":` + boolToString(client.IsOfferer) + `}`)
	client.Conn.WriteMessage(websocket.TextMessage, rolePayload)
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
	client.Conn.Close()
}
