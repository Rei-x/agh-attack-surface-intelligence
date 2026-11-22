package remediation

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
)

// SettingTickets is the encrypted settings document that holds all tickets. Tickets are
// few (tens to hundreds), so one document keeps them out of the Store interface while
// still encrypted at rest with the vault like every other entity.
const SettingTickets = "remediation_tickets"

// ErrNotFound is returned for unknown ticket ids.
var ErrNotFound = errors.New("ticket not found")

// Repo loads and saves tickets. All writes go through Update so concurrent requests and
// the verifier never overwrite each other.
type Repo struct {
	store db.Store
	mu    sync.Mutex
}

// NewRepo returns a repository on top of the store's settings documents.
func NewRepo(store db.Store) *Repo { return &Repo{store: store} }

type ticketDoc struct {
	Tickets []Ticket `json:"tickets"`
}

func (r *Repo) settings() (db.SettingsStore, error) {
	ss, ok := r.store.(db.SettingsStore)
	if !ok {
		return nil, errors.New("store does not support settings documents")
	}
	return ss, nil
}

func (r *Repo) load(ctx context.Context) ([]Ticket, error) {
	ss, err := r.settings()
	if err != nil {
		return nil, err
	}
	var doc ticketDoc
	if _, err := ss.GetSetting(ctx, SettingTickets, &doc); err != nil {
		return nil, err
	}
	migrate(doc.Tickets)
	return doc.Tickets, nil
}

// migrate fills, in memory, what tickets of older versions did not store (saved with the
// next update): the outcome of a fix, read back from its verification note. Due dates are
// left alone; locale.DueDay reads their day the way it was meant.
func migrate(ts []Ticket) {
	for i := range ts {
		t := &ts[i]
		if t.Status != StatusFixed || t.FixedReason != "" {
			continue
		}
		if !t.Verified {
			t.FixedReason = FixedManual
			continue
		}
		note := t.LastCheckNote
		for j := len(t.History) - 1; j >= 0; j-- {
			if h := t.History[j]; h.To == StatusFixed {
				note = nonEmpty(h.Note, note)
				break
			}
		}
		t.FixedReason, t.FixedDetail = inferFixedReason(note)
	}
}

// List returns all tickets, newest first.
func (r *Repo) List(ctx context.Context) ([]Ticket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts, err := r.load(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(ts, func(i, j int) bool { return ts[i].CreatedAt.After(ts[j].CreatedAt) })
	return ts, nil
}

// Get returns one ticket.
func (r *Repo) Get(ctx context.Context, id string) (*Ticket, error) {
	ts, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range ts {
		if ts[i].ID == id {
			return &ts[i], nil
		}
	}
	return nil, ErrNotFound
}

// Update loads all tickets, lets fn change the slice (append, edit in place) and saves
// the result when fn returns nil.
func (r *Repo) Update(ctx context.Context, fn func(ts []Ticket) ([]Ticket, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts, err := r.load(ctx)
	if err != nil {
		return err
	}
	ts, err = fn(ts)
	if err != nil {
		return err
	}
	ss, err := r.settings()
	if err != nil {
		return err
	}
	return ss.SaveSetting(ctx, SettingTickets, &ticketDoc{Tickets: ts})
}
