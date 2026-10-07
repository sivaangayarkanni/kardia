package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/diagnose"
	"github.com/sivaangayarkanni/kardia/internal/ebpf"
	"github.com/sivaangayarkanni/kardia/internal/model"
	"github.com/sivaangayarkanni/kardia/internal/pipeline"
	"github.com/sivaangayarkanni/kardia/internal/store"
)

func TestIngestAndList(t *testing.T) {
	st := store.NewMemory(1000)
	p := pipeline.New(diagnose.New(diagnose.DefaultConfig()), st, pipeline.Options{Workers: 2, QueueDepth: 32, ClearAfter: 2})
	defer p.Close()
	s := New(st, p, "test", ebpf.Capability{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	id := model.Identity{Platform: model.PlatformKubernetes, Cluster: "prod", Namespace: "checkout", Pod: "api", Node: "n1"}
	for i := 0; i < 2; i++ {
		body, _ := json.Marshal(model.Batch{Node: "n1", Signals: []model.Signal{
			{Timestamp: time.Now(), Identity: id, Name: model.SigAcceptDrops, Value: 12, Source: "ebpf"},
		}})
		resp, err := http.Post(ts.URL+"/api/v1/ingest", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	p.Flush()
	time.Sleep(30 * time.Millisecond)
	resp, err := http.Get(ts.URL + "/api/v1/incidents?status=open")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload struct {
		Incidents []model.Incident `json:"incidents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Incidents) != 1 || payload.Incidents[0].Fault != "accept_queue_overflow" {
		t.Fatalf("%+v", payload.Incidents)
	}
	metrics, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metrics.Body.Close()
	if metrics.StatusCode != 200 {
		t.Fatalf("metrics %d", metrics.StatusCode)
	}
}
