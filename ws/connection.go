package ws

import (
	"log"

	"github.com/gorilla/websocket"
)

type Connection struct {
	ws   *websocket.Conn
	send chan []byte
}

func (c *Connection) ReadPump(client *Client) {
	for {
		_, msg, err := c.ws.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}
		// Broadcast to room (excluding self)
		H.Broadcast(client.RoomID, client.ID, msg)
	}
}

func (c *Connection) WritePump() {
	for msg := range c.send {
		if err := c.ws.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
}

func (c *Connection) Send(message []byte) {
	c.send <- message
}

func (c *Connection) Close() {
	c.ws.Close()
	close(c.send)
}
