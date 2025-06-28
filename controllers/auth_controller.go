package controllers

import (
	"auth-api/config"
	"auth-api/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"fmt"
	"math/rand"
	"net/smtp"
)

func Register(c *gin.Context) {
	var body struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		ProfilePicture string `json:"profile_picture"`
		Email          string `json:"email"` // Add email field
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Check if username exists
	var existingUser models.User
	if err := config.DB.Where("username = ?", body.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already taken"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), 14)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password hashing failed"})
		return
	}

	user := models.User{
		Username:       body.Username,
		Password:       string(hashedPassword),
		ProfilePicture: body.ProfilePicture,
		Email:          body.Email, // make sure this field exists in your model
	}

	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User creation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Registered successfully. OTP sent to your email.",
		"user": gin.H{
			"id":              user.ID,
			"username":        user.Username,
			"profile_picture": user.ProfilePicture,
			"email":           user.Email,
		},
		// "otp": otp, // ⛔️ Only for development — remove in production
	})
}

func Login(c *gin.Context) {
	var body struct {
		Identifier string `json:"identifier"` // can be username or email
		Password   string `json:"password"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user models.User
	if err := config.DB.
		Where("username = ? OR email = ?", body.Identifier, body.Identifier).
		First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		return
	}

	// ✅ Generate OTP
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))

	// ✅ Store OTP in Redis
	key := "login:otp:" + user.Email
	err := config.RedisClient.Set(config.RedisCtx, key, otp, 5*time.Minute).Err()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	// ✅ Send OTP via email
	from := "raprast.raka@gmail.com"
	password := "czzh whyb trik ubbb"
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f4f4f7;
      margin: 0;
      padding: 0;
    }
    .container {
      background: #ffffff;
      max-width: 500px;
      margin: 40px auto;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 0 10px rgba(0,0,0,0.05);
      text-align: center;
    }
    .otp {
      font-size: 32px;
      font-weight: bold;
      color: #333;
      margin: 20px 0;
      letter-spacing: 4px;
    }
    .footer {
      font-size: 12px;
      color: #888;
      margin-top: 20px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>Chatmunition Login OTP</h2>
    <p>Please use the following One-Time Password to complete your login:</p>
    <div class="otp">%s</div>
    <p>This code will expire in 5 minutes.</p>
    <div class="footer">
      If you didn't request this, you can safely ignore this email.
    </div>
  </div>
</body>
</html>
`, otp)

	msg := []byte("Subject: Chatmunition Login OTP\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n" +
		htmlBody)

	auth := smtp.PlainAuth("", from, password, smtpHost)
	if err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{user.Email}, msg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP sent to your email",
	})
}

func Me(c *gin.Context) {
	userIDRaw, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userIDStr, ok := userIDRaw.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
		return
	}

	var user models.User
	if err := config.DB.First(&user, "id = ?", userIDStr).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              user.ID,
		"username":        user.Username,
		"profile_picture": user.ProfilePicture,
		"email":           user.Email,
	})
}

func VerifyLoginOTP(c *gin.Context) {
	var body struct {
		Identifier string `json:"identifier"` // username or email
		OTP        string `json:"otp"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Find user by username OR email
	var user models.User
	if err := config.DB.
		Where("username = ? OR email = ?", body.Identifier, body.Identifier).
		First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Lookup OTP from Redis using user.Email
	key := "login:otp:" + user.Email
	storedOTP, err := config.RedisClient.Get(config.RedisCtx, key).Result()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
		return
	}

	if storedOTP != body.OTP {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}

	// Clean up
	config.RedisClient.Del(config.RedisCtx, key)

	// Generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(72 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(config.JWT_SECRET)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":              user.ID,
			"username":        user.Username,
			"profile_picture": user.ProfilePicture,
			"email":           user.Email,
		},
	})
}
