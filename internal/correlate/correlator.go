package correlate

import (
	"crypto/sha1"
	"encoding/hex"
	"sync"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/diagnose"
	"github.com/sivaangayarkanni/kardia/internal/model"
)

// Correlator turns per-window fault hypotheses into incidents with a
// lifecycle. State is keyed by entity+fault so a node can have a disk
// incident and a conntrack incident at the same time.
type Correlator struct {
	mu         sync.Mutex
	open       map[string]*model.Incident
	sustain    map[string]int
	clear      map[string]int
	clearAfter int
	seq        uint64
}

func New(clearAfter int) *Correlator {
	if clearAfter < 1 {
		clearAfter = 3
	}
	return &Correlator{
		open:       map[string]*model.Incident{},
		sustain:    map[string]int{},
		clear:      map[string]int{},
		clearAfter: clearAfter,
	}
}

func key(entity, fault string) string { return entity + "#" + fault }

// Apply folds one entity window into incident state. fired is the set of
// faults that matched. Faults that were open and are absent start their
// clear countdown.
func (c *Correlator) Apply(id model.Identity, fired []diagnose.Result, now time.Time, source string) []model.Incident {
	c.mu.Lock()
	defer c.mu.Unlock()

	entity := id.EntityKey()
	seen := map[string]diagnose.Result{}
	for _, r := range fired {
		seen[r.Fault] = r
	}

	var changed []model.Incident

	for fault, r := range seen {
		k := key(entity, fault)
		c.clear[k] = 0
		c.sustain[k]++
		need := r.Sustain
		if need < 1 {
			need = 1
		}
		if inc, ok := c.open[k]; ok {
			inc.LastSeen = now
			inc.Windows++
			inc.Confidence = r.Confidence
			inc.Severity = r.Severity
			inc.Summary = r.Summary
			inc.RootCause = r.RootCause
			inc.Evidence = r.Evidence
			inc.Recommendations = r.Recommendations
			inc.Source = source
			changed = append(changed, *inc)
			continue
		}
		if c.sustain[k] < need {
			continue
		}
		c.seq++
		inc := &model.Incident{
			ID:              newID(entity, fault, now, c.seq),
			Status:          model.StatusOpen,
			Severity:        r.Severity,
			Fault:           fault,
			Title:           r.Title,
			Summary:         r.Summary,
			RootCause:       r.RootCause,
			Recommendations: r.Recommendations,
			Confidence:      r.Confidence,
			Identity:        id,
			Evidence:        r.Evidence,
			FirstSeen:       now,
			LastSeen:        now,
			Windows:         c.sustain[k],
			Source:          source,
		}
		c.open[k] = inc
		changed = append(changed, *inc)
	}

	// Clear faults that did not fire.
	for k, inc := range c.open {
		if inc.Identity.EntityKey() != entity {
			continue
		}
		if _, ok := seen[inc.Fault]; ok {
			continue
		}
		c.sustain[k] = 0
		c.clear[k]++
		if c.clear[k] < c.clearAfter {
			continue
		}
		resolved := now
		inc.Status = model.StatusResolved
		inc.ResolvedAt = &resolved
		inc.LastSeen = now
		changed = append(changed, *inc)
		delete(c.open, k)
		delete(c.clear, k)
		delete(c.sustain, k)
	}
	return changed
}

// Open returns a snapshot of currently open incidents.
func (c *Correlator) Open() []model.Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]model.Incident, 0, len(c.open))
	for _, inc := range c.open {
		out = append(out, *inc)
	}
	return out
}

func newID(entity, fault string, now time.Time, seq uint64) string {
	h := sha1.Sum([]byte(entity + "|" + fault + "|" + now.UTC().Format(time.RFC3339Nano)))
	return "inc_" + hex.EncodeToString(h[:6]) + "_" + hex.EncodeToString([]byte{byte(seq)})
}
