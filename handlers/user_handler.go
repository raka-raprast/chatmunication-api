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

		var result []map[string]interface{}
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
			Where("user_id = ?", currentUserID).
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
			Where("contact_id = ?", currentUserID).
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

		var result []map[string]interface{}

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

func AddContact(db *gorm.DB) gin.HandlerFunc {
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

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID in token"})
			return
		}

		if userUUID == contactID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot add yourself as a contact"})
			return
		}

		// Check if already added
		var existing models.UserContact
		if err := db.Where("user_id = ? AND contact_id = ?", userID, contactID).First(&existing).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "User already added"})
			return
		}

		contact := models.UserContact{
			UserID:    userUUID,
			ContactID: contactID,
		}

		if err := db.Create(&contact).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add contact"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "Contact added"})
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

		if err := db.Where("user_id = ? AND contact_id = ?", userID, contactID).Delete(&models.UserContact{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove contact"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Contact removed"})
	}
}

func SearchUsers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		query := c.Query("q")
		if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Query parameter 'q' is required"})
			return
		}

		// Extract current user from token
		authHeader := c.GetHeader("Authorization")
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := utils.ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
		currentUserID := claims.UserID

		// Get user_ids already added by current user
		var addedIDs []uuid.UUID
		if err := db.Model(&models.UserContact{}).
			Where("user_id = ?", currentUserID).
			Pluck("contact_id", &addedIDs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch added contacts"})
			return
		}

		// Get users who have already added the current user
		var reverseAddedIDs []uuid.UUID
		if err := db.Model(&models.UserContact{}).
			Where("contact_id = ?", currentUserID).
			Pluck("user_id", &reverseAddedIDs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch reverse contacts"})
			return
		}

		// Combine both into excluded IDs
		excludeSet := make(map[uuid.UUID]struct{})
		for _, id := range addedIDs {
			excludeSet[id] = struct{}{}
		}
		for _, id := range reverseAddedIDs {
			excludeSet[id] = struct{}{}
		}
		currentUserUUID, err := uuid.Parse(currentUserID)
		if err == nil {
			excludeSet[currentUserUUID] = struct{}{}
		}

		// Convert to slice
		var excludeIDs []uuid.UUID
		for id := range excludeSet {
			excludeIDs = append(excludeIDs, id)
		}

		// Step 4: Search users not in the excluded list
		var users []models.User
		pattern := "%" + query + "%"
		if err := db.Where("id NOT IN ? AND (username ILIKE ? OR email ILIKE ?)",
			excludeIDs, pattern, pattern).
			Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Search failed"})
			return
		}

		// Step 5: Return minimal user info
		var result []map[string]interface{}
		for _, u := range users {
			result = append(result, map[string]interface{}{
				"id":              u.ID,
				"username":        u.Username,
				"email":           u.Email,
				"profile_picture": u.ProfilePicture,
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

func GetUserByID(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get target user ID from path param
		userIDParam := c.Param("id")
		targetUserID, err := uuid.Parse(userIDParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Get current user from token
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

		// Fetch target user
		var user models.User
		if err := db.First(&user, "id = ?", targetUserID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Check if current user added them
		var isAdded bool
		db.Model(&models.UserContact{}).
			Where("user_id = ? AND contact_id = ?", currentUserID, targetUserID).
			Select("count(*) > 0").Find(&isAdded)

		// Check if they added current user (reverse)
		var addedYou bool
		db.Model(&models.UserContact{}).
			Where("user_id = ? AND contact_id = ?", targetUserID, currentUserID).
			Select("count(*) > 0").Find(&addedYou)

		// Respond
		c.JSON(http.StatusOK, gin.H{
			"id":              user.ID,
			"username":        user.Username,
			"email":           user.Email,
			"profile_picture": user.ProfilePicture,
			"isAdded":         isAdded,
			"addedYou":        addedYou,
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
