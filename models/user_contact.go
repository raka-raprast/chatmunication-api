package models

import (
	"time"

	"github.com/google/uuid"
)

// Status lifecycle: "pending" (UserID sent a friend request to ContactID,
// awaiting their decision) -> "accepted" (both sides are friends and can
// message/call each other). Declining a pending request deletes the row
// outright rather than storing a terminal "declined" state.
//
// Default is "accepted" (not "pending") so that AutoMigrate backfills
// every pre-existing row — created back when adding a contact was
// instant — as already-accepted, preserving already-working
// relationships instead of retroactively locking people out of chats
// they already have. New rows explicitly set Status: "pending" in
// AddContact.
type UserContact struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"` // who sent the request
	ContactID uuid.UUID `gorm:"type:uuid;not null"` // who received it
	Status    string    `gorm:"not null;default:'accepted'"`

	// Optional: timestamps
	CreatedAt time.Time
}
