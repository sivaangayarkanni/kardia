package pipeline

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/correlate"
	"github.com/sivaangayarkanni/kardia/internal/diagnose"
	"github.com/sivaangayarkanni/kardia/internal/model"
	"github.com/sivaangayarkanni/kardia/internal/shard"
	"github.com/sivaangayarkanni/kardia/internal/store"
)

// ErrBackpressure is returned when the ingest queue is full. Agents retry
// with jitter; they do not block the eBPF reader.
var ErrBackpressure = errors.New("ingest queue full")

// Pipeline is the analyzer hot path. Batches are hashed onto a worker so one
// node is owned by one goroutine (order preserved, no per-entity lock).
type Pipeline struct {
	engine *diagnose.Engine
	store  store.Store
	ring   *shard.Ring
	self   string

	workers int
	queues  []chan model.Batch
	corrs   []*correlate.Correlator

	accepted atomic.Uint64
	dropped  atomic.Uint64
	incidents atomic.Uint64

	onIncident func(model.Incident)
	stop       chan struct{}
	wg         sync.WaitGroup
}

type Options struct {
	Workers    int
	QueueDepth int
	ClearAfter int
	Self       string
	Replicas   []string
	OnIncident func(model.Incident)
}

func New(engine *diagnose.Engine, st store.Store, opt Options) *Pipeline {
	if opt.Workers < 1 {
		opt.Workers = 4
	}
	if opt.QueueDepth < 1 {
		opt.QueueDepth = 1024
	}
	p := &Pipeline{
		engine:     engine,
		store:      st,
		ring:       shard.New(opt.Replicas),
		self:       opt.Self,
		workers:    opt.Workers,
		queues:     make([]chan model.Batch, opt.Workers),
		corrs:      make([]*correlate.Correlator, opt.Workers),
		onIncident: opt.OnIncident,
		stop:       make(chan struct{}),
	}
	for i := 0; i < opt.Workers; i++ {
		p.queues[i] = make(chan model.Batch, opt.QueueDepth)
		p.corrs[i] = correlate.New(opt.ClearAfter)
		p.wg.Add(1)
		go p.loop(i)
	}
	return p
}

// Ingest enqueues a batch or rejects it. Never blocks.
func (p *Pipeline) Ingest(b model.Batch) error {
	if !p.ring.Mine(p.self, b.ShardKey()) {
		return nil
	}
	idx := workerIndex(b.ShardKey(), p.workers)
	select {
	case p.queues[idx] <- b:
		p.accepted.Add(1)
		return nil
	default:
		p.dropped.Add(1)
		return ErrBackpressure
	}
}

func (p *Pipeline) loop(i int) {
	defer p.wg.Done()
	for {
		select {
		case <-p.stop:
			return
		case b := <-p.queues[i]:
			p.handle(p.corrs[i], b)
		}
	}
}

func (p *Pipeline) handle(corr *correlate.Correlator, b model.Batch) {
	if len(b.Signals) == 0 {
		return
	}
	p.store.AddSignals(b.Signals)
	grouped := map[string][]model.Signal{}
	order := make([]string, 0)
	for _, s := range b.Signals {
		k := s.Identity.EntityKey()
		if _, ok := grouped[k]; !ok {
			order = append(order, k)
		}
		grouped[k] = append(grouped[k], s)
	}
	for _, k := range order {
		sigs := grouped[k]
		snap := diagnose.Snapshot{}
		var id model.Identity
		var ts time.Time
		source := "unknown"
		for _, s := range sigs {
			snap[s.Name] = s.Value
			id = s.Identity
			if s.Timestamp.After(ts) {
				ts = s.Timestamp
			}
			if s.Source != "" {
				source = s.Source
			}
		}
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		fired := p.engine.Evaluate(id, snap)
		changed := corr.Apply(id, fired, ts, source)
		for _, inc := range changed {
			p.store.UpsertIncident(inc)
			p.incidents.Add(1)
			if p.onIncident != nil {
				p.onIncident(inc)
			}
		}
	}
}

// Flush waits until all queued batches are processed. Tests and the demo use it.
func (p *Pipeline) Flush() {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pending := 0
		for _, q := range p.queues {
			pending += len(q)
		}
		if pending == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (p *Pipeline) Close() {
	close(p.stop)
	p.wg.Wait()
}

type Counters struct {
	Accepted  uint64 `json:"accepted_batches"`
	Dropped   uint64 `json:"dropped_batches"`
	Incidents uint64 `json:"incident_updates"`
	Workers   int    `json:"workers"`
}

func (p *Pipeline) Counters() Counters {
	return Counters{
		Accepted:  p.accepted.Load(),
		Dropped:   p.dropped.Load(),
		Incidents: p.incidents.Load(),
		Workers:   p.workers,
	}
}

func workerIndex(key string, n int) int {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return int(h % uint32(n))
}
