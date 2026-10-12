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

// frame is a decoded inbound message. Every field is optional; handlers
// validate what they need. Decoding into a struct (rather than
// map[string]interface{} with bare type assertions) removes a whole class
// of panics: a malformed or hostile frame previously crashed the
// connection's goroutine on an unchecked `data["to"].(string)`.
type frame struct {
	Type     string `json:"type"`
	To       string `json:"to"`
	From     string `json:"from"`
	Room     string `json:"room"`
	CallType string `json:"call_type"`
	Content  string `json:"content"`
	GroupID  string `json:"groupId"`
	IsTyping bool   `json:"isTyping"`
}

// UserSocketHandler serves /user-socket: presence, chat, typing and
// call-control events for one user.
func UserSocketHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		http.Error(w, "Missing userId", http.StatusBadRequest)
		return
	}

	// Resolve the user BEFORE upgrading: an unrecognized userId (stale
	// session from a different backend/environment, deleted account, etc.)
	// should fail the handshake outright with a clean HTTP status the
	// client can see — upgrading first and then silently closing the
	// connection right after is indistinguishable from a transient network
	// drop, which drives the client's reconnect-with-backoff logic into
	// retrying forever against a userId that will never work.
	var user models.User
	if err := config.DB.First(&user, "id = ?", userID).Error; err != nil {
		log.Println("User not found:", userID)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	ws, err := userSocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}

	client := signaling.RegisterUser(userID, ws)
	log.Printf("🔌 Registered client: %s (%s)", user.Username, user.ID)

	defer func() {
		signaling.RemoveUserClient(client)
		log.Printf("👋 Unregistered client: %s (%s)", user.Username, user.ID)
	}()

	client.ReadLoop(func(payload []byte) {
		var f frame
		if err := json.Unmarshal(payload, &f); err != nil {
			log.Printf("⚠️ %s sent an undecodable frame: %v", user.Username, err)
			return
		}
		handleUserFrame(client, &user, f)
	})
}

func handleUserFrame(client *signaling.UserClient, user *models.User, f frame) {
	userID := user.ID.String()

	// Every inbound frame is logged: a call that silently does nothing is
	// otherwise indistinguishable from a frame that never arrived.
	log.Printf("📥 %s -> %q (to=%q from=%q room=%q groupId=%q)",
		user.Username, f.Type, f.To, f.From, f.Room, f.GroupID)

	switch f.Type {
	case "call_user":
		if f.To == "" {
			log.Printf("⚠️ %s sent call_user with no \"to\" field", user.Username)
			return
		}
		callType := f.CallType
		if callType == "" {
			callType = "video"
		}

		if !signaling.AreFriends(userID, f.To) {
			log.Printf("🚫 %s tried to call %s without an accepted friend request", user.Username, f.To)
			signaling.SendActionError(client, "Add them as a friend before calling.")
			return
		}

		log.Printf("📞 %s (%s) is calling %s [%s]", user.Username, userID, f.To, callType)

		if signaling.SendIncomingCall(userID, f.To, user.Username, user.ProfilePicture, callType) {
			return
		}

		// Callee offline — ring them through FCM instead.
		var callee models.User
		if err := config.DB.First(&callee, "id = ?", f.To).Error; err != nil {
			log.Println("❌ Failed to fetch callee for FCM:", err)
			return
		}
		if callee.FCMToken == "" {
			return
		}
		room := signaling.CanonicalRoomID(userID + "-" + f.To)
		go func() {
			err := signaling.SendFCMNotification(
				callee.FCMToken,
				"Incoming "+callType+" call",
				user.Username+" is calling you",
				map[string]string{
					"type":            "incoming_call",
					"caller_id":       userID,
					"username":        user.Username,
					"profile_picture": user.ProfilePicture,
					"room":            room,
					"call_type":       callType,
				},
			)
			if err != nil {
				log.Println("❌ Failed to send FCM call notification:", err)
			} else {
				log.Println("📲 FCM call notification sent to", callee.Username)
			}
		}()

	case "call_accepted":
		if f.From == "" {
			log.Printf("⚠️ %s sent call_accepted with no \"from\" field; cannot tell the caller to join", user.Username)
			return
		}
		log.Printf("✅ %s accepted call, joining room %s", user.Username, f.Room)
		signaling.SendCallAccepted(f.From, f.Room)

	case "call_rejected":
		if f.To == "" {
			return
		}
		log.Printf("❌ %s rejected the call", user.Username)
		signaling.SendCallRejected(f.To)

	case "call_cancelled":
		if f.To == "" {
			return
		}
		log.Printf("🚫 %s cancelled the call to %s", user.Username, f.To)
		signaling.SendCallCancelled(f.To)

	case "chat_message":
		if f.To == "" || f.Content == "" {
			return
		}
		if !signaling.AreFriends(userID, f.To) {
			log.Printf("🚫 %s tried to message %s without an accepted friend request", userID, f.To)
			signaling.SendActionError(client, "Add them as a friend before messaging.")
			return
		}
		signaling.SendChatMessage(userID, f.To, f.Content)

	case "typing":
		if f.To == "" {
			return
		}
		signaling.SendTypingStatus(userID, f.To, f.IsTyping)

	case "group_message":
		if f.GroupID == "" || f.Content == "" {
			return
		}
		signaling.SendGroupMessage(userID, f.GroupID, f.Content)

	case "group_typing":
		if f.GroupID == "" {
			return
		}
		signaling.SendGroupTypingStatus(userID, f.GroupID, f.IsTyping)

	default:
		log.Printf("⚠️ %s sent unknown frame type %q", user.Username, f.Type)
	}
}
