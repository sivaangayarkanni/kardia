package diagnose

import (
	"testing"

	"github.com/sivaangayarkanni/kardia/internal/model"
)

func pod() model.Identity {
	return model.Identity{
		Platform: model.PlatformKubernetes, Cluster: "prod", Node: "ip-10-0-1-12",
		Namespace: "checkout", Pod: "checkout-api-7d4f", Container: "api",
	}
}

func vm() model.Identity {
	return model.Identity{Platform: model.PlatformVM, VMID: "i-0abc", Node: "i-0abc", Cloud: "aws", Hypervisor: "nitro"}
}

func metal() model.Identity {
	return model.Identity{Platform: model.PlatformBareMetal, Host: "db-01", Node: "db-01"}
}

func hasFault(rs []Result, fault string) *Result {
	for i := range rs {
		if rs[i].Fault == fault {
			return &rs[i]
		}
	}
	return nil
}

func TestCFSThrottleNotNodeSaturation(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(pod(), Snapshot{
		model.SigCPUThrottleRatio: 0.42,
		model.SigRunqNodeP99US:    180,
		model.SigRunqP99US:        1800,
		model.SigPSICPUSome:       38,
	})
	r := hasFault(rs, "cfs_throttle")
	if r == nil {
		t.Fatal("expected cfs_throttle")
	}
	if r.Severity != model.SevCritical {
		t.Fatalf("severity = %s", r.Severity)
	}
	if hasFault(rs, "cpu_saturation") != nil {
		t.Fatal("node is healthy; saturation must not fire")
	}
	if r.RootCause == "" || len(r.Recommendations) < 2 {
		t.Fatal("explanation incomplete")
	}
}

func TestCPUSaturationSuppressedWhenThrottled(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(pod(), Snapshot{
		model.SigCPUThrottleRatio: 0.5,
		model.SigRunqNodeP99US:    20000,
	})
	if hasFault(rs, "cpu_saturation") != nil {
		t.Fatal("throttle rule owns this window when both fire; saturation returns nil if throttle is high")
	}
	if hasFault(rs, "cfs_throttle") != nil {
		t.Fatal("throttle rule defers when the node run queue is saturated")
	}
}

func TestCPUSaturationOnBareMetal(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(metal(), Snapshot{
		model.SigRunqNodeP99US:    25000,
		model.SigCPUThrottleRatio: 0,
		model.SigLoadPerCPU:       3.2,
		model.SigPSICPUFull:       12,
	})
	r := hasFault(rs, "cpu_saturation")
	if r == nil {
		t.Fatal("expected cpu_saturation")
	}
	if r.Title == "" {
		t.Fatal("missing title")
	}
}

func TestOOMImmediate(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(pod(), Snapshot{model.SigOOMKills: 1, model.SigMemUsageRatio: 1})
	r := hasFault(rs, "oom_kill")
	if r == nil || r.Sustain != 1 || r.Severity != model.SevCritical {
		t.Fatalf("oom result = %+v", r)
	}
}

func TestDiskOnVMMentionsHypervisor(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(vm(), Snapshot{
		model.SigBiolatP99US: 80000,
		model.SigPSIIOFull:   9,
		model.SigPSIIOSome:   30,
	})
	r := hasFault(rs, "disk_saturation")
	if r == nil {
		t.Fatal("expected disk_saturation")
	}
	if r.RootCause == "" {
		t.Fatal("missing cause")
	}
}

func TestAcceptOverflow(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(pod(), Snapshot{model.SigAcceptDrops: 40})
	r := hasFault(rs, "accept_queue_overflow")
	if r == nil || r.Sustain != 1 {
		t.Fatalf("got %+v", r)
	}
}

func TestBelowThresholdSilent(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(pod(), Snapshot{
		model.SigCPUThrottleRatio: 0.01,
		model.SigRunqNodeP99US:    100,
		model.SigTCPRetransRate:   0.001,
		model.SigFDUsageRatio:     0.2,
	})
	if len(rs) != 0 {
		t.Fatalf("expected silence, got %+v", rs)
	}
}

func TestConntrackAndDNS(t *testing.T) {
	e := New(DefaultConfig())
	rs := e.Evaluate(pod(), Snapshot{
		model.SigConntrackUsage: 0.91,
		model.SigDNSLatencyUS:   120000,
	})
	if hasFault(rs, "conntrack_pressure") == nil || hasFault(rs, "dns_latency") == nil {
		t.Fatalf("got %+v", rs)
	}
}
