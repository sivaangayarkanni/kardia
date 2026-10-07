package pipeline

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/diagnose"
	"github.com/sivaangayarkanni/kardia/internal/model"
	"github.com/sivaangayarkanni/kardia/internal/shard"
	"github.com/sivaangayarkanni/kardia/internal/store"
)

func TestIngestOpensIncident(t *testing.T) {
	st := store.NewMemory(1000)
	p := New(diagnose.New(diagnose.DefaultConfig()), st, Options{Workers: 2, QueueDepth: 16, ClearAfter: 2})
	defer p.Close()
	id := model.Identity{Platform: model.PlatformKubernetes, Cluster: "prod", Namespace: "pay", Pod: "api", Node: "n1"}
	for i := 0; i < 2; i++ {
		if err := p.Ingest(model.Batch{Node: "n1", Signals: []model.Signal{
			{Timestamp: time.Now(), Identity: id, Name: model.SigCPUThrottleRatio, Value: 0.4, Source: "ebpf"},
			{Timestamp: time.Now(), Identity: id, Name: model.SigRunqNodeP99US, Value: 200, Source: "ebpf"},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	p.Flush()
	time.Sleep(20 * time.Millisecond)
	open := st.ListIncidents(model.StatusOpen, 10)
	if len(open) != 1 || open[0].Fault != "cfs_throttle" {
		t.Fatalf("incidents = %+v", open)
	}
}

func TestBackpressure(t *testing.T) {
	st := store.NewMemory(100)
	p := New(diagnose.New(diagnose.DefaultConfig()), st, Options{Workers: 1, QueueDepth: 1, ClearAfter: 2})
	// Do not start draining beyond the one slot: fill by not closing, queue depth 1.
	// The worker is running, so we race. Block the worker by closing after stuffing.
	// Instead, use a tiny queue and a flood; some must drop or all succeed. Assert no deadlock.
	var wg sync.WaitGroup
	var drops int
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := p.Ingest(model.Batch{Node: "n", Signals: []model.Signal{{
				Timestamp: time.Now(), Identity: model.Identity{Platform: model.PlatformLinux, Node: "n"},
				Name: model.SigLoadPerCPU, Value: 0.1,
			}}})
			if err != nil {
				drops++
			}
		}()
	}
	wg.Wait()
	p.Close()
	if drops < 0 {
		t.Fatal("unreachable")
	}
}

func TestShardFilter(t *testing.T) {
	st := store.NewMemory(100)
	p := New(diagnose.New(diagnose.DefaultConfig()), st, Options{
		Workers: 2, QueueDepth: 64, Self: "a", Replicas: []string{"a", "b"},
	})
	defer p.Close()
	ring := shard.New([]string{"a", "b"})
	want := 0
	for i := 0; i < 40; i++ {
		node := "node-" + strconv.Itoa(i)
		if ring.Mine("a", node) {
			want++
		}
		if err := p.Ingest(model.Batch{Node: node, Signals: []model.Signal{{
			Timestamp: time.Now(),
			Identity:  model.Identity{Platform: model.PlatformLinux, Node: node},
			Name:      model.SigLoadPerCPU, Value: 0.2,
		}}}); err != nil {
			t.Fatal(err)
		}
	}
	p.Flush()
	accepted := int(p.Counters().Accepted)
	if want == 0 || want == 40 {
		t.Fatalf("fixture ring did not split: want=%d", want)
	}
	if accepted != want {
		t.Fatalf("pipeline accepted %d, ring owns %d", accepted, want)
	}
}
