package correlate

import (
	"testing"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/diagnose"
	"github.com/sivaangayarkanni/kardia/internal/model"
)

func TestOpensAfterSustainAndResolves(t *testing.T) {
	c := New(2)
	id := model.Identity{Platform: model.PlatformKubernetes, Cluster: "prod", Namespace: "checkout", Pod: "api", Node: "n1"}
	fired := []diagnose.Result{{
		Fault: "cfs_throttle", Severity: model.SevHigh, Confidence: 0.8, Sustain: 2,
		Title: "throttle", Summary: "s", RootCause: "r", Recommendations: []string{"fix"},
	}}
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	if got := c.Apply(id, fired, now, "ebpf"); len(got) != 0 {
		t.Fatalf("opened too early: %+v", got)
	}
	got := c.Apply(id, fired, now.Add(time.Second), "ebpf")
	if len(got) != 1 || got[0].Status != model.StatusOpen {
		t.Fatalf("expected open, got %+v", got)
	}
	idStr := got[0].ID
	// Still firing: update, same id.
	got = c.Apply(id, fired, now.Add(2*time.Second), "ebpf")
	if len(got) != 1 || got[0].ID != idStr || got[0].Windows < 3 {
		t.Fatalf("expected update, got %+v", got)
	}
	// Two clear windows required.
	if got = c.Apply(id, nil, now.Add(3*time.Second), "ebpf"); len(got) != 0 {
		t.Fatalf("resolved too early: %+v", got)
	}
	got = c.Apply(id, nil, now.Add(4*time.Second), "ebpf")
	if len(got) != 1 || got[0].Status != model.StatusResolved || got[0].ID != idStr {
		t.Fatalf("expected resolve, got %+v", got)
	}
	if len(c.Open()) != 0 {
		t.Fatal("open set not empty")
	}
}

func TestOOMOpensImmediately(t *testing.T) {
	c := New(3)
	id := model.Identity{Platform: model.PlatformVM, VMID: "i-1", Node: "i-1"}
	got := c.Apply(id, []diagnose.Result{{
		Fault: "oom_kill", Severity: model.SevCritical, Confidence: 0.95, Sustain: 1, Title: "oom",
	}}, time.Now(), "ebpf")
	if len(got) != 1 || got[0].Status != model.StatusOpen {
		t.Fatalf("got %+v", got)
	}
}
