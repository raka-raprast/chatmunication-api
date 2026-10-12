package signaling

import (
	"auth-api/config"
	"auth-api/models"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2/google"
)

type UserClient struct {
	UserID string
	Conn   *websocket.Conn
	Send   chan []byte
}

// SendActionError sends a one-off error frame back to the sender's own
// socket — used when a gated action (message/call) is rejected, so the
// client can surface *why* nothing happened instead of failing silently.
func SendActionError(client *UserClient, message string) {
	if client == nil {
		return
	}
	msg := map[string]interface{}{
		"type":    "action_error",
		"message": message,
	}
	bytes, _ := json.Marshal(msg)
	client.Send <- bytes
}

var userClients = make(map[string]*UserClient)
var userClientsMu sync.Mutex
var onlineUsers = make(map[string]bool)

var encryptionKey []byte

func init() {
	// Load from .env
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️ .env file not found. Skipping...")
	}

	base64Key := os.Getenv("ENCRYPTION_KEY_BASE64")
	if base64Key == "" {
		log.Fatal("❌ ENCRYPTION_KEY_BASE64 not set in environment")
	}

	encryptionKey, err = base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Fatalf("❌ Failed to decode ENCRYPTION_KEY_BASE64: %v", err)
	}

	if len(encryptionKey) != 32 {
		log.Fatalf("❌ ENCRYPTION_KEY must be 32 bytes (AES-256). Got %d bytes", len(encryptionKey))
	}

	fmt.Println("✅ Encryption key loaded. Length:", len(encryptionKey)) // should print 32
}

func encrypt(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	b := []byte(plainText)
	cipherText := make([]byte, aes.BlockSize+len(b))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], b)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}
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

// pongWait/pingPeriod keep the long-lived /user-socket connection alive
// across NAT/firewall idle-connection reaping (common on mobile hotspots,
// which often kill silent TCP connections within 30-60s) — without this,
// the socket dies silently with no app-visible error until the next read
// attempt fails, breaking real-time messages/invites/typing until the
// client reconnects.
const (
	pongWait   = 55 * time.Second
	pingPeriod = 25 * time.Second
)

func RegisterUser(userID string, conn *websocket.Conn) *UserClient {
	client := &UserClient{
		UserID: userID,
		Conn:   conn,
		Send:   make(chan []byte, 256),
	}

	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

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

// writeLoop is the sole writer to c.Conn (gorilla/websocket requires a
// single writer goroutine per connection), so the keepalive ping is sent
// from here too rather than a separate ticker goroutine.
func (c *UserClient) writeLoop() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case msg, ok := <-c.Send:
			if !ok {
				return
			}
			if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func GetUserClient(userID string) *UserClient {
	userClientsMu.Lock()
	defer userClientsMu.Unlock()
	return userClients[userID]
}

// RemoveUserClient tears down one specific connection. If the client has
// already reconnected since this one was registered (userClients[userID]
// now points at a different *UserClient), that newer connection is left
// alone — a blind delete-by-userID here would otherwise let a slow-to-die
// stale connection's cleanup evict (and even forcibly close, if it also
// closed the map's current Conn) a connection that's actively in use,
// intermittently knocking a still-connected client offline for no reason.
func RemoveUserClient(client *UserClient) {
	client.Conn.Close()

	userClientsMu.Lock()
	current, ok := userClients[client.UserID]
	stillCurrent := ok && current == client
	if stillCurrent {
		delete(userClients, client.UserID)
		delete(onlineUsers, client.UserID)
	}
	userClientsMu.Unlock()

	if stillCurrent {
		go broadcastOnlineStatus(client.UserID, "offline")
	}
}

func SendIncomingCall(fromUserID, toUserID, fromUsername, profilePicture, callType string) bool {
	toClient := GetUserClient(toUserID)
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

	if toClient == nil {
		fmt.Println("📛 Callee not connected")
		return false
	}

	toClient.Send <- bytes
	return true
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

// AreFriends reports whether two users have an accepted friend
// relationship — the prerequisite for messaging or calling each other.
// Group chat is unaffected: group membership has its own invite system
// and doesn't require a 1:1 friendship between members.
func AreFriends(userA, userB string) bool {
	var row models.UserContact
	err := config.DB.Where(
		"((user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)) AND status = ?",
		userA, userB, userB, userA, "accepted",
	).First(&row).Error
	return err == nil
}
func SendChatMessage(fromUserID, toUserID, content string) {
	parsedTime := time.Now().UTC()

	// 🔐 Encrypt content
	encryptedContent, err := encrypt(content, encryptionKey)
	if err != nil {
		fmt.Println("❌ Failed to encrypt message content:", err)
		return
	}

	// 📦 Store encrypted in DB
	message := models.Message{
		FromUserID: fromUserID,
		ToUserID:   toUserID,
		Content:    encryptedContent,
		Timestamp:  parsedTime,
		Read:       false,
	}

	if err := config.DB.Create(&message).Error; err != nil {
		fmt.Println("❌ Failed to store message in DB:", err)
		return
	}

	// 📡 Send plaintext content via socket to a connected recipient
	toClient := GetUserClient(toUserID)
	if toClient != nil {
		msg := map[string]interface{}{
			"type":      "chat_message",
			"from":      fromUserID,
			"content":   content, // plaintext; encryption is at-rest only, not E2EE
			"timestamp": parsedTime.Format(time.RFC3339),
		}
		msgBytes, _ := json.Marshal(msg)
		toClient.Send <- msgBytes
		return
	}

	// 📴 Recipient not connected — fall back to a push notification so they
	// still find out, same pattern as the incoming-call FCM fallback.
	fmt.Printf("📛 User %s is not connected. Sending push notification instead.\n", toUserID)

	var sender models.User
	if err := config.DB.First(&sender, "id = ?", fromUserID).Error; err != nil {
		fmt.Println("❌ Failed to fetch sender for push notification:", err)
		return
	}
	var recipient models.User
	if err := config.DB.First(&recipient, "id = ?", toUserID).Error; err != nil {
		fmt.Println("❌ Failed to fetch recipient for push notification:", err)
		return
	}
	if recipient.FCMToken == "" {
		fmt.Printf("📛 User %s has no FCM token on file; cannot push.\n", toUserID)
		return
	}

	go func() {
		err := SendFCMNotification(
			recipient.FCMToken,
			sender.Username,
			content,
			map[string]string{
				"type": "chat_message",
				"from": fromUserID,
			},
		)
		if err != nil {
			fmt.Println("❌ Failed to send chat-message FCM notification:", err)
		} else {
			fmt.Println("📲 FCM chat notification sent to", recipient.Username)
		}
	}()
}

// SendGroupInvite notifies an invited user of a new pending group invite —
// live over their socket if connected, falling back to an FCM push (same
// pattern as SendChatMessage) so invites aren't silently missed while the
// app is backgrounded or closed.
func SendGroupInvite(toUserID, inviteID, groupID, groupName, picture, invitedByUsername string) {
	toClient := GetUserClient(toUserID)
	if toClient != nil {
		msg := map[string]interface{}{
			"type":      "group_invite",
			"inviteId":  inviteID,
			"groupId":   groupID,
			"groupName": groupName,
			"picture":   picture,
			"invitedBy": invitedByUsername,
		}
		msgBytes, _ := json.Marshal(msg)
		toClient.Send <- msgBytes
		return
	}

	var recipient models.User
	if err := config.DB.First(&recipient, "id = ?", toUserID).Error; err != nil {
		fmt.Println("❌ Failed to fetch recipient for group-invite push notification:", err)
		return
	}
	if recipient.FCMToken == "" {
		fmt.Printf("📛 User %s has no FCM token on file; cannot push group invite.\n", toUserID)
		return
	}

	go func() {
		err := SendFCMNotification(
			recipient.FCMToken,
			invitedByUsername,
			fmt.Sprintf("Invited you to %q", groupName),
			map[string]string{
				"type":     "group_invite",
				"inviteId": inviteID,
				"groupId":  groupID,
			},
		)
		if err != nil {
			fmt.Println("❌ Failed to send group-invite FCM notification:", err)
		} else {
			fmt.Println("📲 FCM group-invite notification sent to", recipient.Username)
		}
	}()
}

// SendTypingStatus relays an ephemeral typing indicator to the recipient's
// socket, if they're currently connected. Not persisted — typing state has
// no meaning once the moment has passed.
func SendTypingStatus(fromUserID, toUserID string, isTyping bool) {
	toClient := GetUserClient(toUserID)
	if toClient == nil {
		return
	}

	msg := map[string]interface{}{
		"type":     "typing",
		"from":     fromUserID,
		"isTyping": isTyping,
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

func SendCallCancelled(toUserID string) {
	toClient := GetUserClient(toUserID)
	if toClient == nil {
		fmt.Println("📛 Callee not connected to receive call_cancelled")
		return
	}

	msg := map[string]interface{}{
		"type": "call_cancelled",
	}
	bytes, _ := json.Marshal(msg)
	toClient.Send <- bytes
}

// SendFCMNotification sends a notification using FCM HTTP v1 API
func SendFCMNotification(token, title, body string, data map[string]string) error {

	credentialsFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credentialsFile == "" {
		return fmt.Errorf("GOOGLE_APPLICATION_CREDENTIALS env not set")
	}

	ctx := context.Background()
	credsData, err := os.ReadFile(credentialsFile)
	if err != nil {
		return fmt.Errorf("failed to read service account file: %v", err)
	}

	conf, err := google.JWTConfigFromJSON(credsData, "https://www.googleapis.com/auth/firebase.messaging")
	if err != nil {
		return fmt.Errorf("failed to parse service account: %v", err)
	}
	client := conf.Client(ctx)

	var credStruct struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(credsData, &credStruct); err != nil {
		return fmt.Errorf("failed to extract project_id: %v", err)
	}

	message := map[string]interface{}{
		"message": map[string]interface{}{
			"token": token,
			"notification": map[string]string{
				"title": title,
				"body":  body,
			},
			"data": data,
		},
	}

	jsonBody, _ := json.Marshal(message)
	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", credStruct.ProjectID)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	bodyResp, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FCM error: %s\nResponse: %s", resp.Status, bodyResp)
	}

	return nil
}
