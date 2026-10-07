package agent

import (
	"time"

	"github.com/sivaangayarkanni/kardia/internal/enrich"
	"github.com/sivaangayarkanni/kardia/internal/model"
)

// Scenario is a scripted production failure. The simulator emits the signals
// an eBPF agent would have aggregated, so the diagnosis path can be exercised
// without CAP_BPF.
type Scenario struct {
	Name     string
	Identity model.Identity
	// At is the window index when the fault starts. For is how many windows it lasts.
	At  int
	For int
	// Signals emitted while the fault is active. Outside the window the
	// simulator emits a healthy baseline for the same identity.
	Active map[model.SignalName]float64
	Source string
}

// DemoScenarios covers Kubernetes, a cloud VM, and bare metal.
func DemoScenarios(host enrich.Host) []Scenario {
	node := host.Node
	if node == "" {
		node = "ip-10-0-1-12"
	}
	return []Scenario{
		{
			Name: "checkout CFS throttle",
			Identity: model.Identity{
				Platform: model.PlatformKubernetes, Cluster: first(host.Cluster, "prod-south"),
				Node: node, Namespace: "checkout", Pod: "checkout-api-7d4f", Container: "api",
				Cloud: host.Cloud, VMID: host.VMID,
			},
			At: 2, For: 6,
			Source: "ebpf",
			Active: map[model.SignalName]float64{
				model.SigCPUThrottleRatio: 0.47,
				model.SigRunqNodeP99US:    220,
				model.SigRunqP99US:        2400,
				model.SigPSICPUSome:       41,
				model.SigCPUUsageRatio:    0.99,
			},
		},
		{
			Name: "payments OOM",
			Identity: model.Identity{
				Platform: model.PlatformKubernetes, Cluster: first(host.Cluster, "prod-south"),
				Node: node, Namespace: "payments", Pod: "ledger-0", Container: "ledger",
			},
			At: 5, For: 1,
			Source: "ebpf",
			Active: map[model.SignalName]float64{
				model.SigOOMKills:      1,
				model.SigMemUsageRatio: 1,
				model.SigPSIMemFull:    8,
			},
		},
		{
			Name: "volume credit exhaustion",
			Identity: model.Identity{
				Platform: model.PlatformVM, VMID: first(host.VMID, "i-0ab12volume"),
				Node: first(host.VMID, "i-0ab12volume"), Cloud: first(host.Cloud, "aws"), Hypervisor: "nitro",
			},
			At: 4, For: 6,
			Source: "ebpf",
			Active: map[model.SignalName]float64{
				model.SigBiolatP99US: 95000,
				model.SigPSIIOFull:   14,
				model.SigPSIIOSome:   40,
			},
		},
		{
			Name: "bare metal accept overflow",
			Identity: model.Identity{
				Platform: model.PlatformBareMetal, Host: "edge-lb-01", Node: "edge-lb-01",
			},
			At: 3, For: 5,
			Source: "ebpf",
			Active: map[model.SignalName]float64{
				model.SigAcceptDrops:    120,
				model.SigTCPRetransRate: 0.004,
				model.SigLoadPerCPU:     0.4,
			},
		},
		{
			Name: "node conntrack pressure",
			Identity: model.Identity{
				Platform: model.PlatformKubernetes, Cluster: first(host.Cluster, "prod-south"),
				Node: node, Host: node,
			},
			At: 7, For: 5,
			Source: "proc",
			Active: map[model.SignalName]float64{
				model.SigConntrackUsage: 0.93,
				model.SigDNSLatencyUS:   180000,
				model.SigSoftnetDropped: 80,
			},
		},
	}
}

func healthy(id model.Identity) map[model.SignalName]float64 {
	return map[model.SignalName]float64{
		model.SigCPUThrottleRatio: 0.01,
		model.SigRunqNodeP99US:    150,
		model.SigRunqP99US:        200,
		model.SigPSICPUSome:       0.2,
		model.SigPSICPUFull:       0,
		model.SigPSIMemSome:       0,
		model.SigPSIMemFull:       0,
		model.SigPSIIOSome:        0.1,
		model.SigPSIIOFull:        0,
		model.SigOOMKills:         0,
		model.SigMemUsageRatio:    0.4,
		model.SigBiolatP99US:      800,
		model.SigTCPRetransRate:   0.001,
		model.SigAcceptDrops:      0,
		model.SigSoftnetDropped:   0,
		model.SigFDUsageRatio:     0.12,
		model.SigDNSLatencyUS:     2000,
		model.SigConntrackUsage:   0.18,
		model.SigLoadPerCPU:       0.3,
	}
}

// Simulate returns the signals for every scenario at this window index.
func Simulate(scenarios []Scenario, window int, now time.Time) []model.Signal {
	var out []model.Signal
	for _, sc := range scenarios {
		vals := healthy(sc.Identity)
		active := window >= sc.At && window < sc.At+sc.For
		if active {
			for k, v := range sc.Active {
				vals[k] = v
			}
		}
		src := sc.Source
		if src == "" {
			src = "sim"
		}
		for name, v := range vals {
			out = append(out, model.Signal{
				Timestamp: now, Identity: sc.Identity, Name: name, Value: v,
				Source: src, WindowSec: 1,
			})
		}
	}
	return out
}

func first(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
