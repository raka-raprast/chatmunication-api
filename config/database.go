package config

import (
	"auth-api/models"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

var DB *gorm.DB

func ConnectDB() {
	dsn := "host=localhost user=postgres password=123456 dbname=postgres port=5432 sslmode=disable TimeZone=Asia/Jakarta"
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
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
