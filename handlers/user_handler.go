package handlers

import (
	"auth-api/models"
	"auth-api/utils"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

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

func decrypt(cipherTextBase64 string, key []byte) (string, error) {
	cipherText, _ := base64.StdEncoding.DecodeString(cipherTextBase64)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return string(cipherText), nil
}

func GetAllUsers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := utils.ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userID := claims.UserID

		var users []models.User
		if err := db.Where("id != ?", userID).Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}

		result := []map[string]interface{}{}
		for _, user := range users {
			result = append(result, gin.H{
				"id":              user.ID,
				"username":        user.Username,
				"profile_picture": user.ProfilePicture,
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

func GetChatHistory(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := utils.ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		currentUserID := claims.UserID
		otherUserID := c.Query("to")
		if otherUserID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'to' query parameter"})
			return
		}

		var messages []models.Message
		if err := db.
			Where("(from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)",
				currentUserID, otherUserID, otherUserID, currentUserID).
			Order("timestamp ASC").
			Find(&messages).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
			return
		}

		var decryptedMessages []map[string]interface{}
		for _, msg := range messages {
			decryptedContent, err := decrypt(msg.Content, encryptionKey)
			if err != nil {
				decryptedContent = "[Error decrypting message]"
			}
			decryptedMessages = append(decryptedMessages, map[string]interface{}{
				"FromUserID": msg.FromUserID,
				"ToUserID":   msg.ToUserID,
				"Content":    decryptedContent,
				"Timestamp":  msg.Timestamp,
			})
		}

		c.JSON(http.StatusOK, decryptedMessages)

	}
}

func GetUsersWithLastMessage(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := utils.ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		currentUserID := claims.UserID

		type ContactWithTime struct {
			ID        uuid.UUID
			CreatedAt time.Time
		}

		contactTimeMap := make(map[uuid.UUID]time.Time)

		// Contacts you added
		var added []ContactWithTime
		if err := db.Model(&models.UserContact{}).
			Select("contact_id as id, created_at").
			Where("user_id = ? AND status = ?", currentUserID, "accepted").
			Scan(&added).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch added contacts"})
			return
		}
		for _, c := range added {
			contactTimeMap[c.ID] = c.CreatedAt
		}

		// Contacts who added you
		var reverse []ContactWithTime
		if err := db.Model(&models.UserContact{}).
			Select("user_id as id, created_at").
			Where("contact_id = ? AND status = ?", currentUserID, "accepted").
			Scan(&reverse).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch reverse contacts"})
			return
		}
		for _, c := range reverse {
			// keep the earliest time between both sides
			if existing, ok := contactTimeMap[c.ID]; !ok || c.CreatedAt.Before(existing) {
				contactTimeMap[c.ID] = c.CreatedAt
			}
		}

		// Convert to slice
		var contactIDs []uuid.UUID
		for id := range contactTimeMap {
			contactIDs = append(contactIDs, id)
		}

		// Fetch user data
		var users []models.User
		if err := db.Where("id IN ?", contactIDs).Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}

		// Unread counts per sender, computed in one grouped query instead
		// of N+1 per-contact queries.
		type UnreadCount struct {
			FromUserID string
			Count      int64
		}
		var unreadRows []UnreadCount
		if err := db.Model(&models.Message{}).
			Select("from_user_id, count(*) as count").
			Where("to_user_id = ? AND read = ?", currentUserID, false).
			Group("from_user_id").
			Scan(&unreadRows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch unread counts"})
			return
		}
		unreadCountMap := make(map[string]int64, len(unreadRows))
		for _, row := range unreadRows {
			unreadCountMap[row.FromUserID] = row.Count
		}
		result := []map[string]interface{}{}

		for _, user := range users {
			var lastMessage models.Message
			err := db.
				Where("(from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)",
					currentUserID, user.ID, user.ID, currentUserID).
				Order("timestamp DESC").
				First(&lastMessage).Error

			addedAt := contactTimeMap[user.ID]

			msg := map[string]interface{}{
				"id":              user.ID,
				"username":        user.Username,
				"email":           user.Email,
				"profile_picture": user.ProfilePicture,
				"unreadCount":     unreadCountMap[user.ID.String()],
			}
			if err == nil {
				decryptedContent, err := decrypt(lastMessage.Content, encryptionKey)
				if err != nil {
					decryptedContent = "[Error decrypting message]"
				}

				msg["lastMessage"] = map[string]interface{}{
					"content":   decryptedContent,
					"timestamp": lastMessage.Timestamp,
					"isSender":  lastMessage.FromUserID == currentUserID,
				}

				msg["sortTime"] = lastMessage.Timestamp
			} else {
				msg["lastMessage"] = nil
				msg["sortTime"] = addedAt
			}

			result = append(result, msg)
		}

		// Sort by sortTime descending
		sort.Slice(result, func(i, j int) bool {
			t1 := result[i]["sortTime"].(time.Time)
			t2 := result[j]["sortTime"].(time.Time)
			return t1.After(t2)
		})

		// Clean helper field
		for _, r := range result {
			delete(r, "sortTime")
		}

		c.JSON(http.StatusOK, result)
	}
}

// MarkMessagesRead marks every message from the given sender to the
// authenticated user as read. Called when a chat is opened and whenever a
// new message arrives while that chat is actively open on screen.
func MarkMessagesRead(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := utils.ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		fromUserID := c.Query("from")
		if fromUserID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'from' query parameter"})
			return
		}

		if err := db.Model(&models.Message{}).
			Where("from_user_id = ? AND to_user_id = ? AND read = ?", fromUserID, claims.UserID, false).
			Update("read", true).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark messages as read"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Messages marked as read"})
	}
}

// AddContact sends a friend request. If the target already sent *us* a
// pending request, this instead accepts theirs (two people requesting
// each other at the same time just means they're already friends —
// no need to force a redundant accept step).
func AddContact(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}

		userID := claims.UserID
		contactIDStr := c.Param("id")
		contactID, err := uuid.Parse(contactIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
			return
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID in token"})
			return
		}

		if userUUID == contactID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot add yourself as a contact"})
			return
		}

		// Already friends, either direction?
		var existing models.UserContact
		if db.Where(
			"((user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)) AND status = ?",
			userID, contactID, contactID, userID, "accepted",
		).First(&existing).Error == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Already friends"})
			return
		}

		// Did we already send a request?
		if db.Where("user_id = ? AND contact_id = ? AND status = ?", userID, contactID, "pending").
			First(&existing).Error == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Friend request already sent"})
			return
		}

		// Did they already send us one? Mutual request = instant friends.
		var reverseRequest models.UserContact
		if db.Where("user_id = ? AND contact_id = ? AND status = ?", contactID, userID, "pending").
			First(&reverseRequest).Error == nil {
			if err := db.Model(&reverseRequest).Update("status", "accepted").Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept friend request"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "Friend request accepted", "status": "accepted"})
			return
		}

		contact := models.UserContact{
			UserID:    userUUID,
			ContactID: contactID,
			Status:    "pending",
		}
		if err := db.Create(&contact).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send friend request"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "Friend request sent", "status": "pending_sent"})
	}
}

// AcceptContactRequest accepts an incoming friend request from :id.
func AcceptContactRequest(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		fromUserID := c.Param("id")

		result := db.Model(&models.UserContact{}).
			Where("user_id = ? AND contact_id = ? AND status = ?", fromUserID, claims.UserID, "pending").
			Update("status", "accepted")
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept friend request"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "No pending request from this user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Friend request accepted"})
	}
}

// DeclineContactRequest deletes an incoming pending friend request from
// :id without creating a friendship.
func DeclineContactRequest(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		fromUserID := c.Param("id")

		if err := db.Where("user_id = ? AND contact_id = ? AND status = ?", fromUserID, claims.UserID, "pending").
			Delete(&models.UserContact{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decline friend request"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Friend request declined"})
	}
}

// GetIncomingContactRequests lists pending friend requests sent *to* the
// authenticated user, awaiting their decision.
func GetIncomingContactRequests(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}

		var rows []models.UserContact
		if err := db.Where("contact_id = ? AND status = ?", claims.UserID, "pending").
			Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch requests"})
			return
		}

		result := []map[string]interface{}{}
		for _, row := range rows {
			var sender models.User
			if db.First(&sender, "id = ?", row.UserID).Error != nil {
				continue
			}
			result = append(result, map[string]interface{}{
				"id":              sender.ID,
				"username":        sender.Username,
				"profile_picture": sender.ProfilePicture,
				"createdAt":       row.CreatedAt,
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

// GetSentContactRequests lists pending friend requests the authenticated
// user sent, still awaiting the recipient's decision.
func GetSentContactRequests(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}

		var rows []models.UserContact
		if err := db.Where("user_id = ? AND status = ?", claims.UserID, "pending").
			Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch requests"})
			return
		}

		result := []map[string]interface{}{}
		for _, row := range rows {
			var recipient models.User
			if db.First(&recipient, "id = ?", row.ContactID).Error != nil {
				continue
			}
			result = append(result, map[string]interface{}{
				"id":              recipient.ID,
				"username":        recipient.Username,
				"profile_picture": recipient.ProfilePicture,
				"createdAt":       row.CreatedAt,
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

func RemoveContact(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := utils.ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userID := claims.UserID
		contactIDStr := c.Param("id")
		contactID, err := uuid.Parse(contactIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid contact ID"})
			return
		}

		if err := db.Where(
			"(user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)",
			userID, contactID, contactID, userID,
		).Delete(&models.UserContact{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove contact"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Contact removed"})
	}
}

// contactRelationshipStatus resolves the friend-request state between two
// users from [userID]'s point of view: "accepted", "pending_sent" (userID
// requested otherID), "pending_received" (otherID requested userID), or
// "none".
func contactRelationshipStatus(db *gorm.DB, userID, otherID string) string {
	var row models.UserContact
	if db.Where(
		"((user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)) AND status = ?",
		userID, otherID, otherID, userID, "accepted",
	).First(&row).Error == nil {
		return "accepted"
	}
	if db.Where("user_id = ? AND contact_id = ? AND status = ?", userID, otherID, "pending").
		First(&row).Error == nil {
		return "pending_sent"
	}
	if db.Where("user_id = ? AND contact_id = ? AND status = ?", otherID, userID, "pending").
		First(&row).Error == nil {
		return "pending_received"
	}
	return "none"
}

func SearchUsers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Query("q")
		if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Query parameter 'q' is required"})
			return
		}

		claims, ok := authenticate(c)
		if !ok {
			return
		}
		currentUserID := claims.UserID

		// Already-friends users are excluded — they belong in the chat
		// list, not search results. Pending requests (either direction)
		// still show up, with their status, so the profile screen can
		// render "Request Sent" / "Accept" instead of a duplicate "Add".
		var acceptedIDs []uuid.UUID
		db.Model(&models.UserContact{}).
			Where("user_id = ? AND status = ?", currentUserID, "accepted").
			Pluck("contact_id", &acceptedIDs)
		var acceptedReverseIDs []uuid.UUID
		db.Model(&models.UserContact{}).
			Where("contact_id = ? AND status = ?", currentUserID, "accepted").
			Pluck("user_id", &acceptedReverseIDs)

		excludeSet := make(map[uuid.UUID]struct{})
		for _, id := range acceptedIDs {
			excludeSet[id] = struct{}{}
		}
		for _, id := range acceptedReverseIDs {
			excludeSet[id] = struct{}{}
		}
		if currentUserUUID, err := uuid.Parse(currentUserID); err == nil {
			excludeSet[currentUserUUID] = struct{}{}
		}
		var excludeIDs []uuid.UUID
		for id := range excludeSet {
			excludeIDs = append(excludeIDs, id)
		}

		var users []models.User
		pattern := "%" + query + "%"
		if err := db.Where("id NOT IN ? AND (username ILIKE ? OR email ILIKE ?)",
			excludeIDs, pattern, pattern).
			Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Search failed"})
			return
		}

		result := []map[string]interface{}{}
		for _, u := range users {
			result = append(result, map[string]interface{}{
				"id":              u.ID,
				"username":        u.Username,
				"email":           u.Email,
				"profile_picture": u.ProfilePicture,
				"contactStatus":   contactRelationshipStatus(db, currentUserID, u.ID.String()),
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

func GetUserByID(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDParam := c.Param("id")
		targetUserID, err := uuid.Parse(userIDParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		claims, ok := authenticate(c)
		if !ok {
			return
		}
		currentUserID := claims.UserID

		var user models.User
		if err := db.First(&user, "id = ?", targetUserID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":              user.ID,
			"username":        user.Username,
			"email":           user.Email,
			"profile_picture": user.ProfilePicture,
			"contactStatus":   contactRelationshipStatus(db, currentUserID, targetUserID.String()),
		})
	}
}

func UpdateFCMToken(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id") // URL param /:id

		var req struct {
			Token string `json:"token"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" {
			c.JSON(400, gin.H{"error": "Invalid or missing token"})
			return
		}

		if err := db.Model(&models.User{}).Where("id = ?", userID).Update("fcm_token", req.Token).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to update FCM token"})
			return
		}

		c.JSON(200, gin.H{"message": "FCM token updated successfully"})
	}
}
