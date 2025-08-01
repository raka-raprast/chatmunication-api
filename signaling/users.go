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
	}

	if err := config.DB.Create(&message).Error; err != nil {
		fmt.Println("❌ Failed to store message in DB:", err)
		return
	}

	// 📡 Send encrypted content via socket
	toClient := GetUserClient(toUserID)
	if toClient == nil {
		fmt.Printf("📛 User %s is not connected. Cannot deliver message.\n", toUserID)
		return
	}

	msg := map[string]interface{}{
		"type":      "chat_message",
		"from":      fromUserID,
		"content":   encryptedContent, // still encrypted; decrypt on client if E2EE
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
