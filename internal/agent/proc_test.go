package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/enrich"
	"github.com/sivaangayarkanni/kardia/internal/model"
)

func TestProcParsers(t *testing.T) {
	dir := t.TempDir()
	must := func(rel, body string) {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("pressure/cpu", "some avg10=1.50 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.25 avg60=0.00 avg300=0.00 total=1\n")
	must("pressure/memory", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	must("pressure/io", "some avg10=12.00 avg60=0.00 avg300=0.00 total=9\nfull avg10=4.00 avg60=0.00 avg300=0.00 total=2\n")
	must("loadavg", "4.00 1.00 1.00 2/100 1\n")
	must("stat", "cpu  1 1 1 1 1 1 1 1 1 1\ncpu0 1 0 0 0 0 0 0 0 0 0\ncpu1 1 0 0 0 0 0 0 0 0 0\n")
	must("sys/fs/file-nr", "900 0 1000\n")
	must("net/snmp", "Tcp: InSegs OutSegs RetransSegs\nTcp: 10 100 1\n")
	must("net/softnet_stat", "00000001 0000000a 00000000\n")

	c := NewProc(enrich.Host{Hostname: "h", Node: "h", Platform: model.PlatformBareMetal}).WithRoot(dir)
	first := c.Collect(time.Unix(1, 0))
	if len(first) == 0 {
		t.Fatal("no signals")
	}
	// Second collect produces tcp rate and softnet delta.
	must("net/snmp", "Tcp: InSegs OutSegs RetransSegs\nTcp: 10 200 5\n")
	must("net/softnet_stat", "00000001 00000014 00000000\n")
	second := c.Collect(time.Unix(2, 0))
	found := map[model.SignalName]float64{}
	for _, s := range second {
		found[s.Name] = s.Value
	}
	if found[model.SigFDUsageRatio] < 0.89 || found[model.SigFDUsageRatio] > 0.91 {
		t.Fatalf("fd ratio = %v", found[model.SigFDUsageRatio])
	}
	if found[model.SigTCPRetransRate] < 0.03 || found[model.SigTCPRetransRate] > 0.05 {
		t.Fatalf("retrans = %v", found[model.SigTCPRetransRate])
	}
	if found[model.SigSoftnetDropped] != 10 {
		t.Fatalf("softnet = %v", found[model.SigSoftnetDropped])
	}
	if found[model.SigLoadPerCPU] != 2 {
		t.Fatalf("load = %v", found[model.SigLoadPerCPU])
	}
}
