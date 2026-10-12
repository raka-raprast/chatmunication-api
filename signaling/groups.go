package signaling

import (
	"auth-api/config"
	"auth-api/models"
	"encoding/json"
	"fmt"
	"time"
)

// groupMemberIDs returns the user ids belonging to a group, or nil if the
// group doesn't exist / has no members.
func groupMemberIDs(groupID string) []string {
	var memberships []models.GroupMember
	if err := config.DB.Where("group_id = ?", groupID).Find(&memberships).Error; err != nil {
		fmt.Println("❌ Failed to fetch group members:", err)
		return nil
	}
	ids := make([]string, 0, len(memberships))
	for _, m := range memberships {
		ids = append(ids, m.UserID.String())
	}
	return ids
}

// BroadcastGroupMemberJoined persists a WhatsApp-style "<username> joined
// the group" system message and pushes a dedicated live event to every
// current member (joiner included) so an already-open GroupChatScreen
// can update its member list, header count, and message timeline
// in place — without this, clients only learn about new membership on
// their next full reload (stale member lookups show the sender as
// "Unknown" and the header count never ticks up).
func BroadcastGroupMemberJoined(groupID, joinedUserID string) {
	var joined models.User
	if err := config.DB.First(&joined, "id = ?", joinedUserID).Error; err != nil {
		fmt.Println("❌ Failed to fetch joined user for group-join broadcast:", err)
		return
	}

	parsedTime := time.Now().UTC()
	content := fmt.Sprintf("%s joined the group", joined.Username)

	sysMessage := models.GroupMessage{
		GroupID:    groupID,
		FromUserID: joinedUserID,
		Content:    content,
		IsSystem:   true,
		Timestamp:  parsedTime,
	}
	if err := config.DB.Create(&sysMessage).Error; err != nil {
		fmt.Println("❌ Failed to store group-join system message:", err)
	}

	memberIDs := groupMemberIDs(groupID)
	memberCount := len(memberIDs)

	for _, memberID := range memberIDs {
		client := GetUserClient(memberID)
		if client == nil {
			continue
		}
		msg := map[string]interface{}{
			"type":        "group_member_joined",
			"groupId":     groupID,
			"userId":      joinedUserID,
			"username":    joined.Username,
			"picture":     joined.ProfilePicture,
			"isContact":   memberID == joinedUserID || AreFriends(memberID, joinedUserID),
			"memberCount": memberCount,
			"content":     content,
			"timestamp":   parsedTime.Format(time.RFC3339),
		}
		payload, _ := json.Marshal(msg)
		client.Send <- payload
	}
}

// SendGroupMessage encrypts and stores a group message, then delivers it
// to every other member currently connected over their /user-socket. Any
// member who isn't connected gets the same offline FCM-push fallback that
// 1:1 messages use.
func SendGroupMessage(fromUserID, groupID, content string) {
	parsedTime := time.Now().UTC()

	encryptedContent, err := encrypt(content, encryptionKey)
	if err != nil {
		fmt.Println("❌ Failed to encrypt group message content:", err)
		return
	}

	message := models.GroupMessage{
		GroupID:    groupID,
		FromUserID: fromUserID,
		Content:    encryptedContent,
		Timestamp:  parsedTime,
	}
	if err := config.DB.Create(&message).Error; err != nil {
		fmt.Println("❌ Failed to store group message in DB:", err)
		return
	}

	memberIDs := groupMemberIDs(groupID)
	if memberIDs == nil {
		return
	}

	var sender models.User
	senderName := ""
	if config.DB.First(&sender, "id = ?", fromUserID).Error == nil {
		senderName = sender.Username
	}

	msg := map[string]interface{}{
		"type":      "group_message",
		"groupId":   groupID,
		"from":      fromUserID,
		"content":   content,
		"timestamp": parsedTime.Format(time.RFC3339),
	}
	payload, _ := json.Marshal(msg)

	for _, memberID := range memberIDs {
		if memberID == fromUserID {
			continue
		}

		if client := GetUserClient(memberID); client != nil {
			client.Send <- payload
			continue
		}

		// Offline member — push fallback, same pattern as 1:1 SendChatMessage.
		var recipient models.User
		if config.DB.First(&recipient, "id = ?", memberID).Error != nil || recipient.FCMToken == "" {
			continue
		}
		go func(token, title, body string) {
			if err := SendFCMNotification(token, title, body, map[string]string{
				"type":    "group_message",
				"groupId": groupID,
				"from":    fromUserID,
			}); err != nil {
				fmt.Println("❌ Failed to send group-message FCM notification:", err)
			}
		}(recipient.FCMToken, senderName, content)
	}
}

// SendGroupTypingStatus relays an ephemeral typing indicator to every
// other online member of the group. Not persisted, same as the 1:1
// typing indicator.
func SendGroupTypingStatus(fromUserID, groupID string, isTyping bool) {
	memberIDs := groupMemberIDs(groupID)
	if memberIDs == nil {
		return
	}

	msg := map[string]interface{}{
		"type":     "group_typing",
		"groupId":  groupID,
		"from":     fromUserID,
		"isTyping": isTyping,
	}
	payload, _ := json.Marshal(msg)

	for _, memberID := range memberIDs {
		if memberID == fromUserID {
			continue
		}
		if client := GetUserClient(memberID); client != nil {
			client.Send <- payload
		}
	}
}
