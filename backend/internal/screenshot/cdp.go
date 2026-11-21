package screenshot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// A minimal Chrome DevTools Protocol client over --remote-debugging-pipe: Chromium reads
// commands from fd 3 and writes replies and events to fd 4, each message a JSON object
// terminated by a NUL byte. No websocket and no third-party dependency needed.

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cdpMessage struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *cdpError       `json:"error,omitempty"`
}

type cdpEventHandler func(method string, params json.RawMessage)

type cdpConn struct {
	w   io.Writer
	wmu sync.Mutex

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan cdpMessage
	subs    map[string]cdpEventHandler // by session id ("" = browser)
	err     error
	closed  chan struct{}
}

func newCDPConn(r io.Reader, w io.Writer) *cdpConn {
	c := &cdpConn{
		w:       w,
		pending: make(map[int64]chan cdpMessage),
		subs:    make(map[string]cdpEventHandler),
		closed:  make(chan struct{}),
	}
	go c.readLoop(bufio.NewReaderSize(r, 1<<20))
	return c
}

func (c *cdpConn) readLoop(r *bufio.Reader) {
	var err error
	for {
		var raw []byte
		raw, err = r.ReadBytes(0)
		if err != nil {
			break
		}
		raw = bytes.TrimSuffix(raw, []byte{0})
		var m cdpMessage
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		c.mu.Lock()
		if m.ID != 0 {
			ch := c.pending[m.ID]
			delete(c.pending, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		h := c.subs[m.SessionID]
		c.mu.Unlock()
		if h != nil && m.Method != "" {
			h(m.Method, m.Params)
		}
	}
	c.mu.Lock()
	if err == nil || errors.Is(err, io.EOF) {
		err = errors.New("browser closed the DevTools pipe")
	}
	c.err = err
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	close(c.closed)
}

func (c *cdpConn) alive() bool {
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

func (c *cdpConn) subscribe(session string, h cdpEventHandler) {
	c.mu.Lock()
	c.subs[session] = h
	c.mu.Unlock()
}

func (c *cdpConn) unsubscribe(session string) {
	c.mu.Lock()
	delete(c.subs, session)
	c.mu.Unlock()
}

// call sends one command and waits for its reply. out may be nil.
func (c *cdpConn) call(ctx context.Context, session, method string, params, out any) error {
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		rawParams = b
	}
	ch := make(chan cdpMessage, 1)
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	c.mu.Unlock()

	msg, err := json.Marshal(cdpMessage{ID: id, Method: method, Params: rawParams, SessionID: session})
	if err != nil {
		return err
	}
	c.wmu.Lock()
	_, err = c.w.Write(append(msg, 0))
	c.wmu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("%s: %w", method, err)
	}
	select {
	case m, ok := <-ch:
		if !ok {
			c.mu.Lock()
			err := c.err
			c.mu.Unlock()
			return fmt.Errorf("%s: %w", method, err)
		}
		if m.Error != nil {
			return fmt.Errorf("%s: %s", method, m.Error.Message)
		}
		if out != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, out)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("%s: %w", method, ctx.Err())
	}
}
