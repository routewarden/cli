package dashboard

import (
	"encoding/json"
	"sync"
)

// Hub is a simple WebSocket broadcast hub.
// All connected clients receive every SecurityEvent in real time.
// Source list updates are also broadcast as a separate message type.
type Hub struct {
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
}

// wsMessage wraps outbound WebSocket payloads with a type discriminator
// so the frontend can route them without additional heuristics.
type wsMessage struct {
	MsgType string      `json:"msg_type"` // "event" | "sources"
	Payload interface{} `json:"payload"`
}

// NewHub creates a Hub ready to accept client registrations.
func NewHub() *Hub {
	return &Hub{clients: make(map[chan []byte]struct{})}
}

// Register adds a new client channel. The caller is responsible for
// draining and closing the channel.
func (h *Hub) Register(ch chan []byte) {
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
}

// Unregister removes a client channel.
func (h *Hub) Unregister(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

// Broadcast sends a SecurityEvent to every connected client.
func (h *Hub) Broadcast(e SecurityEvent) {
	h.broadcast(wsMessage{MsgType: "event", Payload: e})
}

// BroadcastSources sends the current source list to every connected client.
func (h *Hub) BroadcastSources(sources []Source) {
	h.broadcast(wsMessage{MsgType: "sources", Payload: sources})
}

func (h *Hub) broadcast(msg wsMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		// Non-blocking send: if the client is slow we drop the message
		// rather than blocking the entire broadcast loop.
		select {
		case ch <- data:
		default:
		}
	}
}

// ClientCount returns the number of currently connected WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
