package models

import "time"

type Message struct {
	ID         string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	FromUserID string    `gorm:"not null"`
	ToUserID   string    `gorm:"not null"`
	Content    string    `gorm:"type:text;not null"`
	Timestamp  time.Time `gorm:"autoCreateTime"`
}
