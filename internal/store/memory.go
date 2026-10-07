package store

import (
	"sort"
	"sync"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/model"
)

// Store is the incident and recent-signal record. MemoryStore is the default
// and is safe for a single analyzer replica. A Postgres implementation can
// satisfy the same interface; the schema lives in deploy/sql/schema.sql.
type Store interface {
	UpsertIncident(model.Incident)
	GetIncident(id string) (model.Incident, bool)
	ListIncidents(status model.IncidentStatus, limit int) []model.Incident
	AddSignals(signals []model.Signal)
	RecentSignals(limit int) []model.Signal
	Stats() Stats
}

type Stats struct {
	Incidents int `json:"incidents"`
	Open      int `json:"open"`
	Signals   int `json:"signals_retained"`
}

// MemoryStore keeps a bounded signal ring and every incident seen this process.
type MemoryStore struct {
	mu        sync.RWMutex
	incidents map[string]model.Incident
	signals   []model.Signal
	maxSig    int
}

func NewMemory(maxSignals int) *MemoryStore {
	if maxSignals < 100 {
		maxSignals = 100
	}
	return &MemoryStore{
		incidents: map[string]model.Incident{},
		maxSig:    maxSignals,
	}
}

func (s *MemoryStore) UpsertIncident(inc model.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents[inc.ID] = inc
}

func (s *MemoryStore) GetIncident(id string) (model.Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	return inc, ok
}

func (s *MemoryStore) ListIncidents(status model.IncidentStatus, limit int) []model.Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Incident, 0, len(s.incidents))
	for _, inc := range s.incidents {
		if status != "" && inc.Status != status {
			continue
		}
		out = append(out, inc)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *MemoryStore) AddSignals(signals []model.Signal) {
	if len(signals) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signals = append(s.signals, signals...)
	if len(s.signals) > s.maxSig {
		s.signals = s.signals[len(s.signals)-s.maxSig:]
	}
}

func (s *MemoryStore) RecentSignals(limit int) []model.Signal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.signals) {
		limit = len(s.signals)
	}
	out := make([]model.Signal, limit)
	copy(out, s.signals[len(s.signals)-limit:])
	return out
}

func (s *MemoryStore) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{Incidents: len(s.incidents), Signals: len(s.signals)}
	for _, inc := range s.incidents {
		if inc.Status == model.StatusOpen {
			st.Open++
		}
	}
	return st
}

// Age of the newest incident, useful in tests.
func Newest(list []model.Incident) time.Time {
	var t time.Time
	for _, inc := range list {
		if inc.LastSeen.After(t) {
			t = inc.LastSeen
		}
	}
	return t
}
