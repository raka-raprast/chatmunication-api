package signaling

import (
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// RoomPeer is one participant in a WebRTC signaling room (/ws).
type RoomPeer struct {
	UserID string
	RoomID string
	*conn
}

// Limits on the replay buffer described in room.buffer.
const (
	maxBufferedFrames = 64
	maxBufferedBytes  = 256 * 1024
	bufferTTL         = 90 * time.Second
)

// room holds the peers of one call plus a short replay buffer.
//
// Signaling is not symmetric in time: whichever side is ready first starts
// emitting its SDP offer and ICE candidates immediately. If the other side
// has not joined yet those frames used to be dropped on the floor, and
// since neither side ever retransmits, the call sat in "connecting"
// forever. Buffering them briefly and replaying to the second peer closes
// that race without the clients changing anything.
type room struct {
	peers map[*RoomPeer]struct{}

	buffer      [][]byte
	bufferBytes int
	bufferFrom  string
	bufferedAt  time.Time
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
	rooms   = make(map[string]*room)
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

// JoinRoom adds a peer, acknowledges with the current occupancy, and
// replays any signaling the other side sent before this peer arrived.
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

	var (
		evicted []*RoomPeer
		replay  [][]byte
	)

	roomsMu.Lock()
	r, ok := rooms[roomID]
	if !ok {
		r = &room{peers: make(map[*RoomPeer]struct{}, 2)}
		rooms[roomID] = r
	}
	if userID != "" {
		for existing := range r.peers {
			if existing.UserID == userID {
				evicted = append(evicted, existing)
				delete(r.peers, existing)
			}
		}
	}
	r.peers[peer] = struct{}{}
	userCount := len(r.peers)

	// Replay only what the *other* side buffered, and only while fresh.
	if len(r.buffer) > 0 && r.bufferFrom != userID && time.Since(r.bufferedAt) < bufferTTL {
		replay = r.buffer
		r.buffer, r.bufferBytes, r.bufferFrom = nil, 0, ""
	}
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

	for _, frame := range replay {
		peer.enqueue(frame)
	}
	if len(replay) > 0 {
		log.Printf("↩️ room %s: replayed %d buffered frame(s) to %s", roomID, len(replay), userID)
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
	r, ok := rooms[peer.RoomID]
	var remaining []*RoomPeer
	if ok {
		delete(r.peers, peer)
		if len(r.peers) == 0 {
			delete(rooms, peer.RoomID)
		} else {
			remaining = make([]*RoomPeer, 0, len(r.peers))
			for p := range r.peers {
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
// and delivered after releasing it. When the peer is alone the frame is
// buffered for whoever joins next, rather than discarded.
func (peer *RoomPeer) Relay(payload []byte) {
	var probe struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(payload, &probe)
	if probe.Type == "" {
		probe.Type = "<untyped>"
	}

	roomsMu.Lock()
	r := rooms[peer.RoomID]
	var others []*RoomPeer
	buffered := false
	if r != nil {
		others = make([]*RoomPeer, 0, len(r.peers))
		for p := range r.peers {
			if p != peer {
				others = append(others, p)
			}
		}
		if len(others) == 0 {
			// Alone: hold the frame for the peer that joins next.
			if r.bufferFrom != peer.UserID {
				r.buffer, r.bufferBytes = nil, 0
				r.bufferFrom = peer.UserID
			}
			if len(r.buffer) < maxBufferedFrames && r.bufferBytes+len(payload) <= maxBufferedBytes {
				frame := make([]byte, len(payload))
				copy(frame, payload)
				r.buffer = append(r.buffer, frame)
				r.bufferBytes += len(payload)
				r.bufferedAt = time.Now()
				buffered = true
			}
		}
	}
	roomsMu.Unlock()

	if len(others) == 0 {
		if buffered {
			log.Printf("🗃️ room %s: %s from %s buffered for a late joiner", peer.RoomID, probe.Type, peer.UserID)
		} else {
			log.Printf("⚠️ room %s: dropped %q from %s — nobody else present and buffer full",
				peer.RoomID, probe.Type, peer.UserID)
		}
		return
	}

	log.Printf("📡 room %s: %s from %s -> %d peer(s)", peer.RoomID, probe.Type, peer.UserID, len(others))
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
	if r := rooms[roomID]; r != nil {
		return len(r.peers)
	}
	return 0
}
