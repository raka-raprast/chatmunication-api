package ws

import (
	"sync"
)

type Client struct {
	ID     string
	Conn   *Connection
	RoomID string
}

type Hub struct {
	rooms map[string]map[string]*Client
	lock  sync.RWMutex
}

var H = Hub{
	rooms: make(map[string]map[string]*Client),
}

// JoinRoom adds a user to the room
func (h *Hub) JoinRoom(roomID, userID string, client *Client) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.rooms[roomID]; !ok {
		h.rooms[roomID] = make(map[string]*Client)
	}
	h.rooms[roomID][userID] = client
}

// LeaveRoom removes a user
func (h *Hub) LeaveRoom(roomID, userID string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if clients, ok := h.rooms[roomID]; ok {
		delete(clients, userID)
		if len(clients) == 0 {
			delete(h.rooms, roomID)
		}
	}
}

// Broadcast sends message to all other peers in the room
func (h *Hub) Broadcast(roomID, fromUser string, message []byte) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	for uid, client := range h.rooms[roomID] {
		if uid != fromUser {
			client.Conn.Send(message)
		}
	}
}
