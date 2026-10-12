package config

import (
	"auth-api/models"
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

// env returns the value of key, or fallback when the variable is unset/empty.
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func ConnectDB() {
	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		log.Fatal("❌ DB_PASSWORD not set")
	}

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		env("DB_HOST", "localhost"),
		env("DB_USER", "chatmunication"),
		password,
		env("DB_NAME", "chatmunication"),
		env("DB_PORT", "5432"),
		env("DB_SSLMODE", "disable"),
		env("DB_TIMEZONE", "Asia/Jakarta"),
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		// Never log dsn: it contains the password.
		log.Fatal("Failed to connect to database:", err)
	}

	fmt.Println("✅ Connected to PostgreSQL")

	DB.AutoMigrate(
		&models.User{},
		&models.UserContact{},
		&models.Message{},
		&models.Group{},
		&models.GroupMember{},
		&models.GroupMessage{},
		&models.GroupInvite{},
	)
}
