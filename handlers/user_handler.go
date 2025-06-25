package handlers

import (
	"auth-api/models"
	"auth-api/utils" // Assuming you have a helper to parse token claims
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func GetAllUsers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse token to get user ID (you may adjust this if you're using a middleware to attach user to context)
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

		c.JSON(http.StatusOK, messages)
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

		var users []models.User
		if err := db.Where("id != ?", currentUserID).Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}

		type LastMessage struct {
			Content   string    `json:"content"`
			Timestamp time.Time `json:"timestamp"`
		}

		var result []map[string]interface{}

		for _, user := range users {
			var lastMessage models.Message
			err := db.
				Where("(from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)",
					currentUserID, user.ID, user.ID, currentUserID).
				Order("timestamp DESC").
				First(&lastMessage).Error

			msg := map[string]interface{}{
				"id":              user.ID,
				"username":        user.Username,
				"profile_picture": user.ProfilePicture,
			}

			if err == nil {
				msg["lastMessage"] = map[string]interface{}{
					"content":   lastMessage.Content,
					"timestamp": lastMessage.Timestamp,
				}
			} else {
				msg["lastMessage"] = nil
			}

			result = append(result, msg)
		}

		c.JSON(http.StatusOK, result)
	}
}
