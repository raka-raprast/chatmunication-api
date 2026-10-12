package handlers

import (
	"auth-api/models"
	"auth-api/signaling"
	"auth-api/utils"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// authenticate pulls the bearer token off the request and resolves it to
// claims, writing a JSON error response and returning ok=false on failure.
// Shared by every group handler to avoid repeating the same six lines.
func authenticate(c *gin.Context) (*utils.Claims, bool) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
		return nil, false
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := utils.ParseToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return nil, false
	}
	return claims, true
}

// requireMembership verifies the given user is a member of the given
// group, writing a JSON error response and returning ok=false otherwise.
func requireMembership(db *gorm.DB, groupID, userID string) (*models.GroupMember, bool) {
	var member models.GroupMember
	err := db.Where("group_id = ? AND user_id = ?", groupID, userID).First(&member).Error
	if err != nil {
		return nil, false
	}
	return &member, true
}

func CreateGroup(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}

		var req struct {
			Name      string   `json:"name"`
			MemberIDs []string `json:"member_ids"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Group name is required"})
			return
		}

		creatorID, err := uuid.Parse(claims.UserID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id"})
			return
		}

		group := models.Group{
			Name:      strings.TrimSpace(req.Name),
			CreatedBy: creatorID,
		}
		if err := db.Create(&group).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create group"})
			return
		}

		// The creator joins instantly; everyone else listed gets a
		// pending invite instead of instant membership — nobody ends up
		// in a group they didn't agree to.
		creatorMember := models.GroupMember{
			GroupID:    group.ID,
			UserID:     creatorID,
			LastReadAt: time.Now(),
		}
		if err := db.Create(&creatorMember).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to join own group"})
			return
		}

		invitedSet := map[string]bool{claims.UserID: true}
		var invites []models.GroupInvite
		for _, id := range req.MemberIDs {
			if invitedSet[id] {
				continue
			}
			memberUUID, err := uuid.Parse(id)
			if err != nil {
				continue
			}
			invitedSet[id] = true
			invites = append(invites, models.GroupInvite{
				GroupID:   group.ID,
				UserID:    memberUUID,
				InvitedBy: creatorID,
			})
		}
		if len(invites) > 0 {
			if err := db.Create(&invites).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send group invites"})
				return
			}
			var creator models.User
			db.First(&creator, "id = ?", creatorID)
			for _, inv := range invites {
				go signaling.SendGroupInvite(
					inv.UserID.String(),
					inv.ID.String(),
					group.ID.String(),
					group.Name,
					group.Picture,
					creator.Username,
				)
			}
		}

		c.JSON(http.StatusCreated, gin.H{
			"id":         group.ID,
			"name":       group.Name,
			"picture":    group.Picture,
			"created_by": group.CreatedBy,
			"invited":    len(invites),
		})
	}
}

// GetUserGroups lists every group the authenticated user belongs to, with
// a decrypted last-message preview (including the sender's username, since
// unlike a 1:1 chat a group message's author isn't implied by the
// conversation itself) and an unread count derived from the member's
// LastReadAt. Mirrors GetUsersWithLastMessage's shape/sorting.
func GetUserGroups(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		currentUserID := claims.UserID

		var memberships []models.GroupMember
		if err := db.Where("user_id = ?", currentUserID).Find(&memberships).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups"})
			return
		}
		if len(memberships) == 0 {
			c.JSON(http.StatusOK, []map[string]interface{}{})
			return
		}

		lastReadByGroup := make(map[string]time.Time, len(memberships))
		var groupIDs []string
		for _, m := range memberships {
			gid := m.GroupID.String()
			groupIDs = append(groupIDs, gid)
			lastReadByGroup[gid] = m.LastReadAt
		}

		var groups []models.Group
		if err := db.Where("id IN ?", groupIDs).Find(&groups).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups"})
			return
		}

		// Member counts per group, one grouped query.
		type MemberCount struct {
			GroupID string
			Count   int64
		}
		var memberCounts []MemberCount
		if err := db.Model(&models.GroupMember{}).
			Select("group_id, count(*) as count").
			Where("group_id IN ?", groupIDs).
			Group("group_id").
			Scan(&memberCounts).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch member counts"})
			return
		}
		memberCountMap := make(map[string]int64, len(memberCounts))
		for _, mc := range memberCounts {
			memberCountMap[mc.GroupID] = mc.Count
		}

		result := []map[string]interface{}{}
		for _, group := range groups {
			gid := group.ID.String()

			var lastMessage models.GroupMessage
			err := db.Where("group_id = ?", gid).
				Order("timestamp DESC").
				First(&lastMessage).Error

			var unreadCount int64
			db.Model(&models.GroupMessage{}).
				Where("group_id = ? AND timestamp > ? AND from_user_id != ? AND is_system = ?", gid, lastReadByGroup[gid], currentUserID, false).
				Count(&unreadCount)

			row := map[string]interface{}{
				"id":          group.ID,
				"name":        group.Name,
				"picture":     group.Picture,
				"created_by":  group.CreatedBy,
				"memberCount": memberCountMap[gid],
				"unreadCount": unreadCount,
			}

			if err == nil {
				var content string
				if lastMessage.IsSystem {
					content = lastMessage.Content
				} else {
					decrypted, decErr := decrypt(lastMessage.Content, encryptionKey)
					if decErr != nil {
						decrypted = "[Error decrypting message]"
					}
					content = decrypted
				}
				var sender models.User
				senderName := ""
				if db.First(&sender, "id = ?", lastMessage.FromUserID).Error == nil {
					senderName = sender.Username
				}
				row["lastMessage"] = map[string]interface{}{
					"content":    content,
					"timestamp":  lastMessage.Timestamp,
					"isSender":   lastMessage.FromUserID == currentUserID,
					"senderName": senderName,
					"isSystem":   lastMessage.IsSystem,
				}
				row["sortTime"] = lastMessage.Timestamp
			} else {
				row["lastMessage"] = nil
				row["sortTime"] = group.CreatedAt
			}

			result = append(result, row)
		}

		sort.Slice(result, func(i, j int) bool {
			t1 := result[i]["sortTime"].(time.Time)
			t2 := result[j]["sortTime"].(time.Time)
			return t1.After(t2)
		})
		for _, r := range result {
			delete(r, "sortTime")
		}

		c.JSON(http.StatusOK, result)
	}
}

func GetGroupMessages(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		groupID := c.Param("id")

		if _, isMember := requireMembership(db, groupID, claims.UserID); !isMember {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of this group"})
			return
		}

		var messages []models.GroupMessage
		if err := db.Where("group_id = ?", groupID).
			Order("timestamp ASC").
			Find(&messages).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
			return
		}

		result := []map[string]interface{}{}
		for _, msg := range messages {
			content := msg.Content
			if !msg.IsSystem {
				decrypted, err := decrypt(msg.Content, encryptionKey)
				if err != nil {
					decrypted = "[Error decrypting message]"
				}
				content = decrypted
			}
			result = append(result, map[string]interface{}{
				"FromUserID": msg.FromUserID,
				"Content":    content,
				"Timestamp":  msg.Timestamp,
				"IsSystem":   msg.IsSystem,
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

func GetGroupMembers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		groupID := c.Param("id")

		if _, isMember := requireMembership(db, groupID, claims.UserID); !isMember {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of this group"})
			return
		}

		var group models.Group
		if err := db.First(&group, "id = ?", groupID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
			return
		}

		var memberships []models.GroupMember
		if err := db.Where("group_id = ?", groupID).Find(&memberships).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch members"})
			return
		}

		var userIDs []uuid.UUID
		for _, m := range memberships {
			userIDs = append(userIDs, m.UserID)
		}
		var users []models.User
		if err := db.Where("id IN ?", userIDs).Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch member users"})
			return
		}

		result := []map[string]interface{}{}
		for _, u := range users {
			uidStr := u.ID.String()
			result = append(result, map[string]interface{}{
				"id":              u.ID,
				"username":        u.Username,
				"profile_picture": u.ProfilePicture,
				"isCreator":       u.ID == group.CreatedBy,
				"isContact":       uidStr == claims.UserID || signaling.AreFriends(claims.UserID, uidStr),
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

// GetGroupPendingInvites lists users who've been invited to this specific
// group but haven't accepted yet — visible to any current member, so the
// group info screen can show who's awaiting a response alongside actual
// members (actual membership stays GetGroupMembers-only; pending
// invitees aren't members and shouldn't be countable/removable as one).
func GetGroupPendingInvites(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		groupID := c.Param("id")

		if _, isMember := requireMembership(db, groupID, claims.UserID); !isMember {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of this group"})
			return
		}

		var invites []models.GroupInvite
		if err := db.Where("group_id = ?", groupID).Find(&invites).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch pending invites"})
			return
		}

		var userIDs []uuid.UUID
		for _, inv := range invites {
			userIDs = append(userIDs, inv.UserID)
		}
		result := []map[string]interface{}{}
		if len(userIDs) > 0 {
			var users []models.User
			if err := db.Where("id IN ?", userIDs).Find(&users).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch invited users"})
				return
			}
			for _, u := range users {
				result = append(result, map[string]interface{}{
					"id":              u.ID,
					"username":        u.Username,
					"profile_picture": u.ProfilePicture,
				})
			}
		}

		c.JSON(http.StatusOK, result)
	}
}

// AddGroupMembers lets any existing member invite more people — the app
// has no admin/owner role system anywhere else (1:1 contacts are
// symmetric too), so inviting follows the same "anyone already in can
// invite" model rather than inventing a new permission tier. Invitees
// must accept before they actually join (see AcceptGroupInvite).
func AddGroupMembers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		groupID := c.Param("id")

		if _, isMember := requireMembership(db, groupID, claims.UserID); !isMember {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of this group"})
			return
		}

		var req struct {
			MemberIDs []string `json:"member_ids"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || len(req.MemberIDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "member_ids is required"})
			return
		}

		groupUUID, err := uuid.Parse(groupID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group id"})
			return
		}
		inviterUUID, err := uuid.Parse(claims.UserID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id"})
			return
		}

		var invites []models.GroupInvite
		for _, id := range req.MemberIDs {
			memberUUID, err := uuid.Parse(id)
			if err != nil {
				continue
			}
			var existingMember models.GroupMember
			if db.Where("group_id = ? AND user_id = ?", groupID, id).First(&existingMember).Error == nil {
				continue // already a member
			}
			var existingInvite models.GroupInvite
			if db.Where("group_id = ? AND user_id = ?", groupID, id).First(&existingInvite).Error == nil {
				continue // already invited, awaiting their decision
			}
			invites = append(invites, models.GroupInvite{
				GroupID:   groupUUID,
				UserID:    memberUUID,
				InvitedBy: inviterUUID,
			})
		}

		if len(invites) > 0 {
			if err := db.Create(&invites).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send invites"})
				return
			}
			var group models.Group
			db.First(&group, "id = ?", groupUUID)
			var inviter models.User
			db.First(&inviter, "id = ?", inviterUUID)
			for _, inv := range invites {
				go signaling.SendGroupInvite(
					inv.UserID.String(),
					inv.ID.String(),
					group.ID.String(),
					group.Name,
					group.Picture,
					inviter.Username,
				)
			}
		}

		c.JSON(http.StatusOK, gin.H{"message": "Invites sent", "invited": len(invites)})
	}
}

// RemoveGroupMember removes :userId from the group. Self-removal (leaving
// the group) is always allowed; removing someone else is restricted to
// the group's creator.
func RemoveGroupMember(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		groupID := c.Param("id")
		targetUserID := c.Param("userId")

		if _, isMember := requireMembership(db, groupID, claims.UserID); !isMember {
			c.JSON(http.StatusForbidden, gin.H{"error": "Not a member of this group"})
			return
		}

		if targetUserID != claims.UserID {
			var group models.Group
			if err := db.First(&group, "id = ?", groupID).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
				return
			}
			if group.CreatedBy.String() != claims.UserID {
				c.JSON(http.StatusForbidden, gin.H{"error": "Only the group creator can remove other members"})
				return
			}
		}

		if err := db.Where("group_id = ? AND user_id = ?", groupID, targetUserID).
			Delete(&models.GroupMember{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove member"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Member removed"})
	}
}

func MarkGroupMessagesRead(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		groupID := c.Param("id")

		if err := db.Model(&models.GroupMember{}).
			Where("group_id = ? AND user_id = ?", groupID, claims.UserID).
			Update("last_read_at", time.Now()).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark group read"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Group marked as read"})
	}
}

// GetGroupInvites lists the authenticated user's pending group invites —
// groups they've been invited to but haven't joined yet.
func GetGroupInvites(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}

		var invites []models.GroupInvite
		if err := db.Where("user_id = ?", claims.UserID).Find(&invites).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch invites"})
			return
		}

		result := []map[string]interface{}{}
		for _, invite := range invites {
			var group models.Group
			if db.First(&group, "id = ?", invite.GroupID).Error != nil {
				continue
			}
			var inviter models.User
			inviterName := ""
			if db.First(&inviter, "id = ?", invite.InvitedBy).Error == nil {
				inviterName = inviter.Username
			}
			result = append(result, map[string]interface{}{
				"inviteId":  invite.ID,
				"groupId":   group.ID,
				"groupName": group.Name,
				"picture":   group.Picture,
				"invitedBy": inviterName,
				"createdAt": invite.CreatedAt,
			})
		}

		c.JSON(http.StatusOK, result)
	}
}

// AcceptGroupInvite turns a pending invite into real membership.
func AcceptGroupInvite(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		inviteID := c.Param("id")

		var invite models.GroupInvite
		if err := db.Where("id = ? AND user_id = ?", inviteID, claims.UserID).First(&invite).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
			return
		}

		member := models.GroupMember{
			GroupID:    invite.GroupID,
			UserID:     invite.UserID,
			LastReadAt: time.Now(),
		}
		if err := db.Create(&member).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to join group"})
			return
		}
		db.Delete(&invite)
		go signaling.BroadcastGroupMemberJoined(invite.GroupID.String(), invite.UserID.String())

		c.JSON(http.StatusOK, gin.H{"message": "Joined group", "groupId": invite.GroupID})
	}
}

// DeclineGroupInvite deletes a pending invite without joining.
func DeclineGroupInvite(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := authenticate(c)
		if !ok {
			return
		}
		inviteID := c.Param("id")

		if err := db.Where("id = ? AND user_id = ?", inviteID, claims.UserID).
			Delete(&models.GroupInvite{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decline invite"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Invite declined"})
	}
}
