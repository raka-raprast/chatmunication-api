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
	"time"

	"golang.org/x/oauth2/google"
)

var encryptionKey []byte

// LoadEncryptionKey initialises the at-rest message key. Called from
// config.LoadEnv's caller ordering in main, after the environment is loaded.
func LoadEncryptionKey(key []byte) {
	encryptionKey = key
	fmt.Println("✅ Encryption key loaded. Length:", len(encryptionKey))
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

// SendIncomingCall rings the callee. Returns false when they hold no live
// connection, so the caller's handler can fall back to an FCM push.
//
// The room id is canonicalised here so both sides agree on it regardless of
// which direction the call was placed in.
func SendIncomingCall(fromUserID, toUserID, fromUsername, profilePicture, callType string) bool {
	roomID := CanonicalRoomID(fmt.Sprintf("%s-%s", fromUserID, toUserID))

	if !IsOnline(toUserID) {
		fmt.Println("📛 Callee not connected")
		return false
	}
	return deliverJSON(toUserID, map[string]interface{}{
		"type":            "incoming_call",
		"from":            fromUserID,
		"username":        fromUsername,
		"profile_picture": profilePicture,
		"room":            roomID,
		"call_type":       callType,
	})
}

func SendCallAccepted(toUserID, roomID string) {
	if !deliverJSON(toUserID, map[string]interface{}{
		"type": "call_accepted",
		"room": CanonicalRoomID(roomID),
	}) {
		fmt.Println("📛 Caller not connected to receive call_accepted")
	}
}

func SendCallRejected(toUserID string) {
	if !deliverJSON(toUserID, map[string]interface{}{
		"type": "call_rejected",
	}) {
		fmt.Println("📛 Caller not connected to receive call_rejected")
	}
}

func SendCallCancelled(toUserID string) {
	if !deliverJSON(toUserID, map[string]interface{}{
		"type": "call_cancelled",
	}) {
		fmt.Println("📛 Callee not connected to receive call_cancelled")
	}
}

// SendTypingStatus relays an ephemeral typing indicator to the recipient's
// socket, if they're currently connected. Not persisted — typing state has
// no meaning once the moment has passed.
func SendTypingStatus(fromUserID, toUserID string, isTyping bool) {
	deliverJSON(toUserID, map[string]interface{}{
		"type":     "typing",
		"from":     fromUserID,
		"isTyping": isTyping,
	})
}

// SendChatMessage stores a message encrypted at rest and delivers the
// plaintext to the recipient's live connections, falling back to a push
// notification when they are offline.
func SendChatMessage(fromUserID, toUserID, content string) {
	parsedTime := time.Now().UTC()

	encryptedContent, err := encrypt(content, encryptionKey)
	if err != nil {
		fmt.Println("❌ Failed to encrypt message content:", err)
		return
	}

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

	delivered := deliverJSON(toUserID, map[string]interface{}{
		"type":      "chat_message",
		"from":      fromUserID,
		"content":   content, // plaintext; encryption is at-rest only, not E2EE
		"timestamp": parsedTime.Format(time.RFC3339),
	})
	if delivered {
		return
	}

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
// live over their socket if connected, falling back to an FCM push so
// invites aren't silently missed while the app is backgrounded or closed.
func SendGroupInvite(toUserID, inviteID, groupID, groupName, picture, invitedByUsername string) {
	if deliverJSON(toUserID, map[string]interface{}{
		"type":      "group_invite",
		"inviteId":  inviteID,
		"groupId":   groupID,
		"groupName": groupName,
		"picture":   picture,
		"invitedBy": invitedByUsername,
	}) {
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

// SendFCMNotification sends a notification using FCM HTTP v1 API.
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
	if resp.StatusCode >= 300 {
		log.Printf("❌ FCM responded %d: %s", resp.StatusCode, string(bodyResp))
	}
	return nil
}
