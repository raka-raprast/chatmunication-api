package config

import (
	"encoding/base64"
	"log"
	"os"

	"github.com/joho/godotenv"
)

var (
	EncryptionKey          []byte
	JWTSecret              []byte
	ServiceAccountFilePath string
)

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ .env file not found. Skipping...")
	}

	// Load and decode AES encryption key
	base64Key := os.Getenv("ENCRYPTION_KEY_BASE64")
	if base64Key == "" {
		log.Fatal("❌ ENCRYPTION_KEY_BASE64 not set")
	}
	var err error
	EncryptionKey, err = base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Fatalf("❌ Failed to decode ENCRYPTION_KEY_BASE64: %v", err)
	}
	if len(EncryptionKey) != 32 {
		log.Fatalf("❌ ENCRYPTION_KEY must be 32 bytes (got %d)", len(EncryptionKey))
	}

	// Load JWT secret
	jwt := os.Getenv("JWT_SECRET")
	if jwt == "" {
		log.Fatal("❌ JWT_SECRET not set")
	}
	JWTSecret = []byte(jwt)

	// Load ServiceAccountFilePath
	ServiceAccountFilePath = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if ServiceAccountFilePath == "" {
		log.Fatal("❌ GOOGLE_APPLICATION_CREDENTIALS not set")
	}

	log.Println("✅ Environment variables loaded")
}
