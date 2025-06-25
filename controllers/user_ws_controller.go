package controllers

import (
	"auth-api/config"
	"auth-api/models"
	"auth-api/signaling"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var userSocketUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func UserSocketHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		http.Error(w, "Missing userId", http.StatusBadRequest)
		return
	}

	conn, err := userSocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}

	// Fetch user from DB
	var user models.User
	if err := config.DB.First(&user, "id = ?", userID).Error; err != nil {
		log.Println("User not found:", err)
		conn.Close()
		return
	}

	client := signaling.RegisterUser(userID, conn)
	log.Printf("Client %s", client.UserID)
	log.Printf("🔌 Registered client: %s (%s)", user.Username, user.ID)

	defer signaling.RemoveUserClient(userID)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error for user", userID, ":", err)
			break
		}

		var data map[string]interface{}
		if err := json.Unmarshal(msg, &data); err != nil {
			continue
		}

		switch data["type"] {
		case "call_user": // sent by caller
			to := data["to"].(string)
			room := data["room"].(string)
			callType, ok := data["call_type"].(string)
			if !ok {
				callType = "video" // default to video if not provided
			}

			log.Println("🔔 Received room ID:", room)
			log.Printf("📞 %s (%s) is calling %s [%s]", user.Username, user.ID, to, callType)

			signaling.SendIncomingCall(
				user.ID.String(),
				to,
				user.Username,
				user.ProfilePicture,
				callType, // 👈 pass callType here
			)

		case "call_accepted": // sent by callee
			from := data["from"].(string)
			room := data["room"].(string)
			log.Printf("✅ %s accepted call, joining room %s", user.Username, room)
			signaling.SendCallAccepted(from, room)

		case "call_rejected": // sent by callee
			to := data["to"].(string) // ✅ this is the caller
			log.Printf("❌ %s rejected the call", user.Username)
			signaling.SendCallRejected(to)

		case "chat_message":
			to := data["to"].(string)
			content := data["content"].(string)
			timestamp := data["timestamp"].(string) // optional but recommended

			log.Printf("💬 Message from %s to %s: %s", userID, to, content)

			signaling.SendChatMessage(userID, to, content, timestamp)

		}

	}
}
