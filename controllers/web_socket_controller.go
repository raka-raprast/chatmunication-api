package controllers

import (
	"auth-api/signaling"
	"auth-api/utils"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WebSocketHandler serves /ws: the WebRTC signaling relay. Peers in the
// same room exchange SDP offers/answers and ICE candidates; the server
// never inspects the payloads, it only forwards them.
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	room := r.URL.Query().Get("room")

	if token == "" || room == "" {
		http.Error(w, "Missing token or room ID", http.StatusBadRequest)
		return
	}

	// The relay carries call media negotiation. Without verifying the token
	// anyone who guessed a room id could join a stranger's call and receive
	// their SDP. The client already sends its JWT here, so this costs the
	// frontend nothing.
	claims, err := utils.ParseToken(token)
	if err != nil {
		log.Println("🚫 /ws rejected: invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Both peers must resolve to the same room regardless of the order they
	// concatenated the two user ids in.
	room = signaling.CanonicalRoomID(room)

	if a, b, ok := signaling.RoomParticipants(room); ok {
		if claims.UserID != a && claims.UserID != b {
			log.Printf("🚫 /ws rejected: %s is not a participant of room %s", claims.UserID, room)
			http.Error(w, "Not a participant of this room", http.StatusForbidden)
			return
		}
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade failed:", err)
		return
	}

	peer := signaling.JoinRoom(room, claims.UserID, ws)
	defer signaling.LeaveRoom(peer)

	peer.Serve()
}
