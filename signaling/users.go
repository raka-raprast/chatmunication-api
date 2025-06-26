package signaling

import (
	"auth-api/config"
	"auth-api/models"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type UserClient struct {
	UserID string
	Conn   *websocket.Conn
	Send   chan []byte
}

var userClients = make(map[string]*UserClient)
var userClientsMu sync.Mutex
var onlineUsers = make(map[string]bool)

func broadcastOnlineStatus(userID, status string) {
	msg := map[string]interface{}{
		"type":   "online_status",
		"userId": userID,
		"status": status, // "online" or "offline"
	}
	payload, _ := json.Marshal(msg)

	userClientsMu.Lock()
	defer userClientsMu.Unlock()

	for _, client := range userClients {
		client.Send <- payload
	}
}

func RegisterUser(userID string, conn *websocket.Conn) *UserClient {
	client := &UserClient{
		UserID: userID,
		Conn:   conn,
		Send:   make(chan []byte, 256),
	}

	userClientsMu.Lock()
	userClients[userID] = client
	onlineUsers[userID] = true
	userClientsMu.Unlock()

	// Start write loop
	go client.writeLoop()

	// Send initial list of online users to this client only
	go func() {
		msg := map[string]interface{}{
			"type":        "online_users",
			"onlineUsers": GetOnlineUsers(),
		}
		bytes, _ := json.Marshal(msg)
		client.Send <- bytes
	}()

	// Broadcast to others that this user is online
	go broadcastOnlineStatus(userID, "online")

	return client
}

func (c *UserClient) writeLoop() {
	for msg := range c.Send {
		err := c.Conn.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			break
		}
	}
}

func GetUserClient(userID string) *UserClient {
	userClientsMu.Lock()
	defer userClientsMu.Unlock()
	return userClients[userID]
}

func RemoveUserClient(userID string) {
	userClientsMu.Lock()
	if client, ok := userClients[userID]; ok {
		client.Conn.Close()
		delete(userClients, userID)
		delete(onlineUsers, userID)
	}
	userClientsMu.Unlock()

	// Broadcast that this user is now offline
	go broadcastOnlineStatus(userID, "offline")
}

func SendIncomingCall(fromUserID, toUserID, fromUsername, profilePicture, callType string) {
	toClient := GetUserClient(toUserID)
	if toClient == nil {
		fmt.Println("📛 Callee not connected")
		return
	}
	roomID := fmt.Sprintf("%s-%s", fromUserID, toUserID)
	msg := map[string]interface{}{
		"type":            "incoming_call",
		"from":            fromUserID,
		"username":        fromUsername,
		"profile_picture": profilePicture,
		"room":            roomID,
		"call_type":       callType,
	}
	bytes, _ := json.Marshal(msg)
	toClient.Send <- bytes
}

func SendCallAccepted(toUserID, roomID string) {
	toClient := GetUserClient(toUserID)
	if toClient == nil {
		fmt.Println("📛 Caller not connected to receive call_accepted")
		return
	}

	msg := map[string]interface{}{
		"type": "call_accepted",
		"room": roomID,
	}
	bytes, _ := json.Marshal(msg)
	toClient.Send <- bytes
}

func SendCallRejected(toUserID string) {
	toClient := GetUserClient(toUserID)
	if toClient == nil {
		fmt.Println("📛 Caller not connected to receive call_rejected")
		return
	}

	msg := map[string]interface{}{
		"type": "call_rejected",
	}
	bytes, _ := json.Marshal(msg)
	toClient.Send <- bytes
}

func SendChatMessage(fromUserID, toUserID, content, timestamp string) {
	// 1. Save to database
	parsedTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		parsedTime = time.Now()
	}

	message := models.Message{
		FromUserID: fromUserID,
		ToUserID:   toUserID,
		Content:    content,
		Timestamp:  parsedTime,
	}

	if err := config.DB.Create(&message).Error; err != nil {
		fmt.Println("❌ Failed to store message in DB:", err)
	}

	// 2. Send via socket
	toClient := GetUserClient(toUserID)
	if toClient == nil {
		fmt.Printf("📛 User %s is not connected. Cannot deliver message.\n", toUserID)
		return
	}

	msg := map[string]interface{}{
		"type":      "chat_message",
		"from":      fromUserID,
		"content":   content,
		"timestamp": parsedTime.Format(time.RFC3339),
	}
	bytes, _ := json.Marshal(msg)
	toClient.Send <- bytes
}

func GetOnlineUsers() []string {
	userClientsMu.Lock()
	defer userClientsMu.Unlock()

	ids := make([]string, 0, len(onlineUsers))
	for id := range onlineUsers {
		ids = append(ids, id)
	}
	return ids
}
