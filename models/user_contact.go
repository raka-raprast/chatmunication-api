package models

import (
	"time"

	"github.com/google/uuid"
)

type UserContact struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"` // who added
	ContactID uuid.UUID `gorm:"type:uuid;not null"` // who was added

	// Optional: timestamps
	CreatedAt time.Time
}
