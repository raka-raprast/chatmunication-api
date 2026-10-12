package models

import (
	"time"

	"github.com/google/uuid"
)

// Group is a named conversation with more than two participants.
type Group struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	Name      string    `gorm:"not null" json:"name"`
	Picture   string    `json:"picture"`
	CreatedBy uuid.UUID `gorm:"type:uuid;not null" json:"created_by"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// GroupMember links a user to a group. LastReadAt drives the unread count
// for that member — cheaper than a per-message read-receipt row, and
// sufficient since group messages only need an aggregate "N unread", not
// per-message read state.
type GroupMember struct {
	ID         uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	GroupID    uuid.UUID `gorm:"type:uuid;not null;index"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index"`
	JoinedAt   time.Time `gorm:"autoCreateTime"`
	LastReadAt time.Time `gorm:"not null"`
}

// GroupMessage is a chat message posted to a group. Content is encrypted
// at rest the same way 1:1 Message.Content is (AES-256-CFB) — except for
// IsSystem rows (e.g. "X joined the group"), which carry plaintext since
// there's no per-user secret in them and no benefit to encrypting;
// delivery to members happens over each member's existing /user-socket
// connection, there is no per-group socket room.
type GroupMessage struct {
	ID         string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	GroupID    string    `gorm:"not null;index"`
	FromUserID string    `gorm:"not null"`
	Content    string    `gorm:"type:text;not null"`
	IsSystem   bool      `gorm:"not null;default:false"`
	Timestamp  time.Time `gorm:"autoCreateTime"`
}

// GroupInvite is a pending invitation to join a group. Resolved by
// deleting the row — either into a real GroupMember (accept) or just
// gone (decline) — rather than keeping a terminal status around.
type GroupInvite struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	GroupID   uuid.UUID `gorm:"type:uuid;not null;index" json:"group_id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	InvitedBy uuid.UUID `gorm:"type:uuid;not null" json:"invited_by"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}
