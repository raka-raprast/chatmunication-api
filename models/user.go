package models

import (
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type User struct {
    ID             uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
    Username       string    `gorm:"unique;not null" json:"username"`
    Password       string    `gorm:"not null" json:"-"`
    ProfilePicture string    `json:"profile_picture"`
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
    u.ID = uuid.New()
    return
}
