package signaling

import (
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Connection tuning. These are the only timing knobs in the socket layer;
// everything else derives from them.
const (
	// writeWait bounds a single frame write. Without it, a peer whose TCP
	// receive window has filled (phone asleep, tunnel dead, app frozen
	// mid-call) blocks the writing goroutine forever.
	writeWait = 10 * time.Second

	// pongWait is how long we tolerate silence from a peer before declaring
	// the connection dead; pingPeriod must be meaningfully smaller so a
	// healthy peer always answers in time.
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10

	// maxMessageSize caps an inbound frame. SDP offers are the largest
	// legitimate payload and sit far below this.
	maxMessageSize = 1 << 20 // 1 MiB

	// sendQueueSize is the per-connection outbound buffer. A peer that falls
	// this far behind is treated as dead rather than allowed to apply
	// backpressure to shared state.
	sendQueueSize = 256
)

// conn is the shared transport half of both socket kinds (/user-socket and
// /ws). It guarantees three invariants that the previous implementation
// violated, each of which could wedge the whole process:
//
//  1. Exactly one goroutine ever writes to the websocket (gorilla requires
//     this), and every write carries a deadline.
//  2. Enqueuing a message NEVER blocks. A slow or dead peer is disconnected
//     instead of stalling the caller — callers frequently hold, or are about
//     to take, shared locks.
//  3. Close is idempotent and immediately unblocks the reader by closing the
//     underlying connection, so a dead peer cannot linger in a registry.
type conn struct {
	ws   *websocket.Conn
	send chan []byte

	closeOnce sync.Once
	done      chan struct{}

	// label identifies the peer in logs ("user <id>" / "room <id>").
	label string
}

func newConn(ws *websocket.Conn, label string) *conn {
	ws.SetReadLimit(maxMessageSize)
	_ = ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(pongWait))
	})

	c := &conn{
		ws:    ws,
		send:  make(chan []byte, sendQueueSize),
		done:  make(chan struct{}),
		label: label,
	}
	go c.writePump()
	return c
}

// enqueue queues a payload for delivery. It never blocks and never panics,
// regardless of connection state. Returns false if the peer is gone.
func (c *conn) enqueue(payload []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}

	select {
	case c.send <- payload:
		return true
	case <-c.done:
		return false
	default:
		// Queue full: the peer is not draining. Dropping just this frame
		// would desync the client silently, so close instead — the client
		// reconnects and resyncs from REST.
		log.Printf("⚠️ %s: send queue full (%d), dropping connection as unresponsive", c.label, sendQueueSize)
		c.close()
		return false
	}
}

// close tears the connection down exactly once. Closing the websocket also
// unblocks any goroutine parked in ReadMessage, which is what lets the read
// loop run its cleanup promptly instead of waiting for a read deadline.
//
// The goodbye frame goes out via WriteControl, not WriteMessage: gorilla
// permits WriteControl and Close to run concurrently with the writer
// goroutine, while WriteMessage from two goroutines is a data race.
func (c *conn) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		// Best-effort polite close; ignore errors, the peer may be gone.
		_ = c.ws.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)
		_ = c.ws.Close()
	})
}

// writePump is the single writer goroutine. It exits only via close(), and
// guarantees the connection is torn down on any write failure.
func (c *conn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.close()
	}()

	for {
		select {
		case <-c.done:
			return

		case payload := <-c.send:
			if err := c.ws.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if err := c.ws.WriteMessage(websocket.TextMessage, payload); err != nil {
				log.Printf("🔌 %s: write failed, closing: %v", c.label, err)
				return
			}

		case <-ticker.C:
			if err := c.ws.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("🔌 %s: ping failed, closing: %v", c.label, err)
				return
			}
		}
	}
}

// ReadLoop consumes frames until the peer goes away, handing each payload to
// handle. It always returns — a closed connection unblocks it immediately.
func (c *conn) ReadLoop(handle func([]byte)) {
	defer c.close()
	for {
		_, payload, err := c.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("🔌 %s: read ended: %v", c.label, err)
			}
			return
		}
		handle(payload)
	}
}
