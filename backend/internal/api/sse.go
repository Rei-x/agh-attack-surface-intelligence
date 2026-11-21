package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// SSEHub fans out live scan/change/governor events to connected Server-Sent Events clients.
type SSEHub struct {
	mu      sync.RWMutex
	clients map[chan domain.LiveEvent]struct{}
	recent  []domain.LiveEvent
}

func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients: make(map[chan domain.LiveEvent]struct{}),
		recent:  make([]domain.LiveEvent, 0, 50),
	}
}

// Publish broadcasts an event to all subscribed SSE clients without blocking.
func (h *SSEHub) Publish(ev domain.LiveEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	h.mu.Lock()
	h.recent = append(h.recent, ev)
	if len(h.recent) > 50 {
		h.recent = h.recent[len(h.recent)-50:]
	}
	for ch := range h.clients {
		select {
		case ch <- ev:
		default:
			// drop for slow subscriber
		}
	}
	h.mu.Unlock()
}

// Subscribe registers a listener channel.
func (h *SSEHub) Subscribe() chan domain.LiveEvent {
	ch := make(chan domain.LiveEvent, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes a listener channel.
func (h *SSEHub) Unsubscribe(ch chan domain.LiveEvent) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// ServeHTTP handles GET /api/v1/events/stream.
func (h *SSEHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	// Initial hello event
	hello := domain.LiveEvent{
		Type:      "stream.connected",
		Timestamp: time.Now().UTC(),
		Payload:   map[string]any{"status": "connected"},
	}
	writeSSE(w, hello)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			writeSSE(w, ev)
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": keepalive %d\n\n", time.Now().Unix())
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev domain.LiveEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, string(b))
}
