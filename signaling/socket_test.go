package signaling

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var testUpgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func wsURL(srv *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + path
}

// userServer serves /user-socket-like connections against the real registry.
func userServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		client := RegisterUser(r.URL.Query().Get("userId"), ws)
		defer RemoveUserClient(client)
		client.ReadLoop(func([]byte) {})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialUser(t *testing.T, srv *httptest.Server, userID string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(wsURL(srv, "/?userId="+userID), nil)
	if err != nil {
		t.Fatalf("dial %s: %v", userID, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// A peer that stops reading must never be able to stall delivery to anyone
// else, or block new connections. This is the production failure: one
// frozen client (app killed mid-call) wedged the entire socket layer until
// the process was restarted.
func TestStuckPeerDoesNotBlockDeliveryOrRegistration(t *testing.T) {
	srv := userServer(t)

	victim := dialUser(t, srv, "victim")
	_ = victim // deliberately never read from

	waitOnline(t, "victim")

	// Flood the unresponsive peer with far more than its queue can hold.
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = 'x'
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2000 {
			deliver("victim", payload)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("delivery to an unresponsive peer blocked the sender")
	}

	// The registry must still be usable: a new user can connect and presence
	// queries must answer promptly.
	registered := make(chan string, 1)
	go func() {
		other := dialUser(t, srv, "bystander")
		_ = other
		registered <- "ok"
	}()

	select {
	case <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("registration blocked while an unresponsive peer was connected")
	}

	waitOnline(t, "bystander")

	done2 := make(chan []string, 1)
	go func() { done2 <- GetOnlineUsers() }()
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("GetOnlineUsers blocked: the registry lock is held across a send")
	}
}

func waitOnline(t *testing.T, userID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if IsOnline(userID) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("user %s never came online", userID)
}

// Presence must survive an overlapping reconnect: the dying socket's
// cleanup must not evict the fresh one, and the user only goes offline once
// the last connection is gone.
func TestPresenceSurvivesOverlappingReconnect(t *testing.T) {
	srv := userServer(t)

	first := dialUser(t, srv, "rejoiner")
	waitOnline(t, "rejoiner")

	second := dialUser(t, srv, "rejoiner")
	waitForConnCount(t, "rejoiner", 2)

	// The older connection dies after the newer one registered.
	first.Close()
	waitForConnCount(t, "rejoiner", 1)

	if !IsOnline("rejoiner") {
		t.Fatal("stale connection's cleanup knocked a live connection offline")
	}

	second.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !IsOnline("rejoiner") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("user stayed online after their last connection closed")
}

func waitForConnCount(t *testing.T, userID string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		registryMu.RLock()
		got := len(userConns[userID])
		registryMu.RUnlock()
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	registryMu.RLock()
	got := len(userConns[userID])
	registryMu.RUnlock()
	t.Fatalf("connection count for %s = %d, want %d", userID, got, want)
}

// The two call participants build the room id from their own perspective,
// producing "A-B" and "B-A". Both must land in the same room, otherwise one
// side accepts a call the other never sees.
func TestCanonicalRoomIDIsOrderIndependent(t *testing.T) {
	a := "ea9b927b-92c7-42e9-b570-e2e18bb4dac8"
	b := "c983d651-9da5-4ab8-a598-a292bc9bdff6"

	if got, want := CanonicalRoomID(a+"-"+b), CanonicalRoomID(b+"-"+a); got != want {
		t.Fatalf("room ids differ by call direction: %q vs %q", got, want)
	}
	if _, _, ok := RoomParticipants(CanonicalRoomID(a + "-" + b)); !ok {
		t.Fatal("canonical room id no longer parses as a participant pair")
	}
	// Non-pair room names must survive untouched.
	if got := CanonicalRoomID("lobby"); got != "lobby" {
		t.Fatalf("CanonicalRoomID mangled a plain room name: %q", got)
	}
}

// Peers that joined using opposite id orderings must still reach each other.
func TestRelayReachesPeerThatJoinedWithReversedRoomID(t *testing.T) {
	a := "ea9b927b-92c7-42e9-b570-e2e18bb4dac8"
	b := "c983d651-9da5-4ab8-a598-a292bc9bdff6"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		room := CanonicalRoomID(r.URL.Query().Get("room"))
		peer := JoinRoom(room, r.URL.Query().Get("user"), ws)
		defer LeaveRoom(peer)
		peer.Serve()
	}))
	defer srv.Close()

	dial := func(room, user string) *websocket.Conn {
		c, _, err := websocket.DefaultDialer.Dial(wsURL(srv, "/?room="+room+"&user="+user), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	caller := dial(a+"-"+b, a) // caller's spelling
	callee := dial(b+"-"+a, b) // callee's spelling — reversed

	// Drain both join_acks.
	for _, c := range []*websocket.Conn{caller, callee} {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, _, err := c.ReadMessage(); err != nil {
			t.Fatalf("join_ack: %v", err)
		}
	}

	offer := []byte(`{"type":"offer","sdp":"v=0"}`)
	if err := caller.WriteMessage(websocket.TextMessage, offer); err != nil {
		t.Fatalf("write offer: %v", err)
	}

	callee.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, got, err := callee.ReadMessage()
	if err != nil {
		t.Fatalf("callee never received the offer (rooms split by id ordering): %v", err)
	}
	if string(got) != string(offer) {
		t.Fatalf("relayed payload = %q, want %q", got, offer)
	}
}

// A second connection from the same user replaces the first: a ghost peer
// left by a killed app otherwise inflates occupancy and strands the call.
func TestRejoinEvictsGhostPeer(t *testing.T) {
	room := CanonicalRoomID("ghost-room")
	user := "11111111-1111-4111-8111-111111111111"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		peer := JoinRoom(room, user, ws)
		defer LeaveRoom(peer)
		peer.Serve()
	}))
	defer srv.Close()

	first, _, err := websocket.DefaultDialer.Dial(wsURL(srv, "/"), nil)
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer first.Close()
	waitOccupancy(t, room, 1)

	second, _, err := websocket.DefaultDialer.Dial(wsURL(srv, "/"), nil)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()

	// Occupancy must settle back to exactly one: the ghost was evicted.
	waitOccupancy(t, room, 1)

	second.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, payload, err := second.ReadMessage()
	if err != nil {
		t.Fatalf("second peer got no join_ack: %v", err)
	}
	var ack struct {
		Type      string `json:"type"`
		UserCount int    `json:"userCount"`
	}
	if err := json.Unmarshal(payload, &ack); err != nil {
		t.Fatalf("join_ack decode: %v", err)
	}
	if ack.Type != "join_ack" {
		t.Fatalf("first frame = %q, want join_ack", ack.Type)
	}
	if ack.UserCount != 1 {
		t.Fatalf("userCount = %d, want 1 (ghost peer still counted)", ack.UserCount)
	}
}

func waitOccupancy(t *testing.T, room string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if RoomOccupancy(room) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("room %s occupancy = %d, want %d", room, RoomOccupancy(room), want)
}
