package signaling

import (
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// RoomPeer is one participant in a WebRTC signaling room (/ws).
type RoomPeer struct {
	UserID string
	RoomID string
	*conn
}

// rooms holds every signaling room. A single mutex guards it.
//
// The previous implementation used two levels of locking (a global rooms
// mutex plus a per-room mutex) and acquired them in opposite orders on the
// join and leave paths — a textbook lock-order inversion. A join racing a
// leave could deadlock the global mutex permanently, after which *every*
// subsequent /ws connection hung forever. It also performed blocking socket
// writes while holding those locks, so a single frozen peer achieved the
// same outcome. One mutex, never held across I/O, removes both failure
// modes by construction.
var (
	roomsMu sync.Mutex
	rooms   = make(map[string]map[*RoomPeer]struct{})
)

// CanonicalRoomID makes a room name independent of which peer built it.
//
// Room ids are formed as "<callerID>-<calleeID>". The caller and callee
// derive that string from their own point of view, so the two sides could
// produce "A-B" and "B-A" and land in different rooms — each sitting alone,
// exchanging nothing, one end "accepted" while the other hung forever. That
// is the stuck-call bug. Sorting the pair makes both spellings resolve to
// the same room without the clients having to agree on an order.
//
// Anything that is not a pair of UUIDs is passed through untouched.
func CanonicalRoomID(raw string) string {
	const uuidLen = 36
	if len(raw) != uuidLen*2+1 || raw[uuidLen] != '-' {
		return raw
	}
	a, b := raw[:uuidLen], raw[uuidLen+1:]
	if _, err := uuid.Parse(a); err != nil {
		return raw
	}
	if _, err := uuid.Parse(b); err != nil {
		return raw
	}
	pair := []string{strings.ToLower(a), strings.ToLower(b)}
	sort.Strings(pair)
	return pair[0] + "-" + pair[1]
}

// RoomParticipants returns the two user ids encoded in a canonical room id,
// or ok=false if the room is not a UUID pair.
func RoomParticipants(roomID string) (string, string, bool) {
	const uuidLen = 36
	if len(roomID) != uuidLen*2+1 || roomID[uuidLen] != '-' {
		return "", "", false
	}
	a, b := roomID[:uuidLen], roomID[uuidLen+1:]
	if _, err := uuid.Parse(a); err != nil {
		return "", "", false
	}
	if _, err := uuid.Parse(b); err != nil {
		return "", "", false
	}
	return a, b, true
}

// JoinRoom adds a peer and acknowledges with the current occupancy.
//
// If the same user already has a peer in this room, that older peer is
// evicted: it is a ghost left behind by a killed app or a dropped network,
// and leaving it in place inflates the occupancy count that clients use to
// decide who sends the WebRTC offer — which strands the call.
func JoinRoom(roomID, userID string, ws *websocket.Conn) *RoomPeer {
	peer := &RoomPeer{
		UserID: userID,
		RoomID: roomID,
		conn:   newConn(ws, "room "+roomID+" user "+userID),
	}

	var evicted []*RoomPeer

	roomsMu.Lock()
	set, ok := rooms[roomID]
	if !ok {
		set = make(map[*RoomPeer]struct{}, 2)
		rooms[roomID] = set
	}
	if userID != "" {
		for existing := range set {
			if existing.UserID == userID {
				evicted = append(evicted, existing)
				delete(set, existing)
			}
		}
	}
	set[peer] = struct{}{}
	userCount := len(set)
	roomsMu.Unlock()

	// Tear down ghosts outside the lock; their own read loops will run
	// LeaveRoom, which is now a no-op for the map but still notifies peers.
	for _, ghost := range evicted {
		log.Printf("👻 room %s: evicting stale peer for user %s", roomID, ghost.UserID)
		ghost.close()
	}

	if payload, err := json.Marshal(map[string]interface{}{
		"type":      "join_ack",
		"userCount": userCount,
	}); err == nil {
		peer.enqueue(payload)
	}

	log.Printf("🎥 room %s: user %s joined (%d in room)", roomID, userID, userCount)
	return peer
}

// LeaveRoom removes a peer and tells the remaining occupants.
func LeaveRoom(peer *RoomPeer) {
	if peer == nil {
		return
	}
	peer.close()

	roomsMu.Lock()
	set, ok := rooms[peer.RoomID]
	var remaining []*RoomPeer
	if ok {
		delete(set, peer)
		if len(set) == 0 {
			delete(rooms, peer.RoomID)
		} else {
			remaining = make([]*RoomPeer, 0, len(set))
			for p := range set {
				remaining = append(remaining, p)
			}
		}
	}
	roomsMu.Unlock()

	if len(remaining) == 0 {
		return
	}
	payload, err := json.Marshal(map[string]interface{}{
		"type":   "user_left",
		"roomId": peer.RoomID,
	})
	if err != nil {
		return
	}
	for _, p := range remaining {
		p.enqueue(payload)
	}
}

// Relay forwards a signaling frame (SDP offer/answer, ICE candidate) to
// every other peer in the room. The peer list is snapshotted under the lock
// and delivered after releasing it.
func (peer *RoomPeer) Relay(payload []byte) {
	roomsMu.Lock()
	set := rooms[peer.RoomID]
	others := make([]*RoomPeer, 0, len(set))
	for p := range set {
		if p != peer {
			others = append(others, p)
		}
	}
	roomsMu.Unlock()

	for _, p := range others {
		p.enqueue(payload)
	}
}

// Serve runs the peer's read loop until the connection ends.
func (peer *RoomPeer) Serve() {
	peer.ReadLoop(peer.Relay)
}

// RoomOccupancy reports how many peers are in a room. Used by tests and
// diagnostics.
func RoomOccupancy(roomID string) int {
	roomsMu.Lock()
	defer roomsMu.Unlock()
	return len(rooms[roomID])
}
