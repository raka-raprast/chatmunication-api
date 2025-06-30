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
				callType = "video"
			}

			log.Println("🔔 Received room ID:", room)
			log.Printf("📞 %s (%s) is calling %s [%s]", user.Username, user.ID, to, callType)

			calleeOnline := signaling.SendIncomingCall(
				user.ID.String(),
				to,
				user.Username,
				user.ProfilePicture,
				callType,
			)

			if !calleeOnline {
				// 🔍 Fetch callee FCM token
				var callee models.User
				if err := config.DB.First(&callee, "id = ?", to).Error; err != nil {
					log.Println("❌ Failed to fetch callee for FCM:", err)
					return
				}
				if callee.FCMToken != "" {
					go func() {
						data := map[string]string{
							"type":            "incoming_call",
							"caller_id":       user.ID.String(),
							"username":        user.Username,
							"profile_picture": user.ProfilePicture,
							"room":            room,
							"call_type":       callType,
						}
						err := signaling.SendFCMNotification(
							callee.FCMToken,
							"Incoming "+callType+" call",
							user.Username+" is calling you",
							data,
						)
						if err != nil {
							log.Println("❌ Failed to send FCM call notification:", err)
						} else {
							log.Println("📲 FCM call notification sent to", callee.Username)
						}
					}()
				}
			}

		case "call_accepted": // sent by callee
			from := data["from"].(string)
			room := data["room"].(string)
			log.Printf("✅ %s accepted call, joining room %s", user.Username, room)
			signaling.SendCallAccepted(from, room)

		case "call_rejected": // sent by callee
			to := data["to"].(string)
			log.Printf("❌ %s rejected the call", user.Username)
			signaling.SendCallRejected(to)

		case "call_cancelled": // sent by caller
			to := data["to"].(string)
			log.Printf("🚫 %s cancelled the call to %s", user.Username, to)
			signaling.SendCallCancelled(to)

		case "chat_message":
			to := data["to"].(string)
			content := data["content"].(string)
			log.Printf("💬 Message from %s to %s: %s", userID, to, content)
			signaling.SendChatMessage(userID, to, content)
		}

	}
}
