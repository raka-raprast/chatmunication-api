package signaling

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/gorilla/websocket"
)

// UserClient is one live /user-socket connection belonging to a user.
type UserClient struct {
	UserID string
	*conn
}

// userConns maps a user to every connection they currently hold. A set
// (rather than a single pointer) is what makes presence correct:
//
//   - Reconnects overlap. A phone that loses signal leaves a half-dead
//     socket that only errors out at the read deadline, long after the new
//     one registered. With a single slot, the dying connection's cleanup
//     evicted the live one and the user appeared offline while connected.
//   - A user can legitimately be on two devices.
//
// A user is online iff their set is non-empty, so presence can no longer
// get stuck in either direction.
var (
	registryMu sync.RWMutex
	userConns  = make(map[string]map[*UserClient]struct{})
)

// RegisterUser adds a connection and announces presence if this is the
// user's first one.
func RegisterUser(userID string, ws *websocket.Conn) *UserClient {
	client := &UserClient{
		UserID: userID,
		conn:   newConn(ws, "user "+userID),
	}

	registryMu.Lock()
	set, existed := userConns[userID]
	if !existed {
		set = make(map[*UserClient]struct{}, 1)
		userConns[userID] = set
	}
	set[client] = struct{}{}
	firstConnection := !existed
	registryMu.Unlock()

	// Hand the newcomer the current roster. Done after unlocking: enqueue is
	// non-blocking, but taking no lock here keeps the rule absolute.
	if payload, err := json.Marshal(map[string]interface{}{
		"type":        "online_users",
		"onlineUsers": GetOnlineUsers(),
	}); err == nil {
		client.enqueue(payload)
	}

	if firstConnection {
		broadcastOnlineStatus(userID, "online")
	}
	return client
}

// RemoveUserClient tears down one connection and announces offline only
// when the user has no connections left.
func RemoveUserClient(client *UserClient) {
	if client == nil {
		return
	}
	client.close()

	registryMu.Lock()
	set, ok := userConns[client.UserID]
	if ok {
		delete(set, client)
		if len(set) == 0 {
			delete(userConns, client.UserID)
		}
	}
	nowOffline := ok && len(set) == 0
	registryMu.Unlock()

	if nowOffline {
		broadcastOnlineStatus(client.UserID, "offline")
	}
}

// connectionsFor returns a snapshot of a user's connections. Callers send
// using the snapshot *after* the lock is released — holding a lock across a
// send is what previously deadlocked the entire socket layer.
func connectionsFor(userID string) []*UserClient {
	registryMu.RLock()
	defer registryMu.RUnlock()

	set := userConns[userID]
	if len(set) == 0 {
		return nil
	}
	out := make([]*UserClient, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}

// allConnections snapshots every live connection.
func allConnections() []*UserClient {
	registryMu.RLock()
	defer registryMu.RUnlock()

	out := make([]*UserClient, 0, len(userConns))
	for _, set := range userConns {
		for c := range set {
			out = append(out, c)
		}
	}
	return out
}

// IsOnline reports whether the user holds at least one live connection.
func IsOnline(userID string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return len(userConns[userID]) > 0
}

// GetOnlineUsers lists every user with a live connection.
func GetOnlineUsers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	ids := make([]string, 0, len(userConns))
	for id := range userConns {
		ids = append(ids, id)
	}
	return ids
}

// deliver sends a payload to every connection a user holds (all devices).
// Reports whether at least one connection accepted it, which callers use to
// decide between live delivery and an FCM push.
func deliver(userID string, payload []byte) bool {
	delivered := false
	for _, c := range connectionsFor(userID) {
		if c.enqueue(payload) {
			delivered = true
		}
	}
	return delivered
}

// deliverJSON marshals and delivers in one step.
func deliverJSON(userID string, msg map[string]interface{}) bool {
	payload, err := json.Marshal(msg)
	if err != nil {
		log.Printf("❌ failed to marshal %v for %s: %v", msg["type"], userID, err)
		return false
	}
	return deliver(userID, payload)
}

// broadcastOnlineStatus tells everyone else that a user came online or went
// offline. The connection snapshot is taken under the lock; all sends happen
// after it is released.
func broadcastOnlineStatus(userID, status string) {
	payload, err := json.Marshal(map[string]interface{}{
		"type":   "online_status",
		"userId": userID,
		"status": status,
	})
	if err != nil {
		return
	}
	for _, c := range allConnections() {
		c.enqueue(payload)
	}
}

// SendActionError reports a rejected action back to the acting client, so
// the UI can explain why nothing happened instead of failing silently.
func SendActionError(client *UserClient, message string) {
	if client == nil {
		return
	}
	payload, err := json.Marshal(map[string]interface{}{
		"type":    "action_error",
		"message": message,
	})
	if err != nil {
		return
	}
	client.enqueue(payload)
}
