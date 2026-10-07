package agent

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/enrich"
	"github.com/sivaangayarkanni/kardia/internal/model"
)

// ProcCollector reads host pressure, TCP, and fd counters. It is the fallback
// when eBPF cannot attach, and the always-on baseline next to eBPF histograms.
type ProcCollector struct {
	Host    enrich.Host
	root    string
	prevTCP tcpSnap
	prevSN  uint64
	haveTCP bool
	haveSN  bool
}

type tcpSnap struct {
	outSegs   float64
	retrans   float64
}

func NewProc(host enrich.Host) *ProcCollector {
	return &ProcCollector{Host: host, root: "/proc"}
}

// WithRoot points the collector at a fixture tree. Tests only.
func (c *ProcCollector) WithRoot(root string) *ProcCollector {
	c.root = root
	return c
}

func (c *ProcCollector) Collect(now time.Time) []model.Signal {
	id := enrich.NodeIdentity(c.Host)
	var out []model.Signal
	add := func(name model.SignalName, v float64, unit string) {
		out = append(out, model.Signal{
			Timestamp: now, Identity: id, Name: name, Value: v, Unit: unit,
			Source: "proc", WindowSec: 1,
		})
	}
	if some, full, err := readPSI(c.root + "/pressure/cpu"); err == nil {
		add(model.SigPSICPUSome, some, "percent")
		add(model.SigPSICPUFull, full, "percent")
	}
	if some, full, err := readPSI(c.root + "/pressure/memory"); err == nil {
		add(model.SigPSIMemSome, some, "percent")
		add(model.SigPSIMemFull, full, "percent")
	}
	if some, full, err := readPSI(c.root + "/pressure/io"); err == nil {
		add(model.SigPSIIOSome, some, "percent")
		add(model.SigPSIIOFull, full, "percent")
	}
	if load, err := readLoadPerCPU(c.root + "/loadavg", c.root + "/stat"); err == nil {
		add(model.SigLoadPerCPU, load, "load")
	}
	if ratio, err := readFDRatio(c.root + "/sys/fs/file-nr"); err == nil {
		add(model.SigFDUsageRatio, ratio, "ratio")
	}
	if rate, ok := c.tcpRetransRate(c.root + "/net/snmp"); ok {
		add(model.SigTCPRetransRate, rate, "ratio")
	}
	if drops, ok := c.softnetDelta(c.root + "/net/softnet_stat"); ok {
		add(model.SigSoftnetDropped, drops, "packets")
	}
	if used, max, err := readConntrack(c.root); err == nil && max > 0 {
		add(model.SigConntrackUsage, used/max, "ratio")
	}
	return out
}

func readPSI(path string) (some, full float64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		avg10 := parseAvg10(fields)
		switch fields[0] {
		case "some":
			some = avg10
		case "full":
			full = avg10
		}
	}
	return some, full, sc.Err()
}

func parseAvg10(fields []string) float64 {
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "avg10=") {
			v, _ := strconv.ParseFloat(strings.TrimPrefix(f, "avg10="), 64)
			return v
		}
	}
	return 0
}

func readLoadPerCPU(loadPath, statPath string) (float64, error) {
	b, err := os.ReadFile(loadPath)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, os.ErrInvalid
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	cpus := float64(countCPUs(statPath))
	if cpus < 1 {
		cpus = 1
	}
	return load / cpus, nil
}

func countCPUs(statPath string) int {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 1
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			n++
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

func readFDRatio(path string) (float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, os.ErrInvalid
	}
	alloc, err1 := strconv.ParseFloat(fields[0], 64)
	max, err2 := strconv.ParseFloat(fields[2], 64)
	if err1 != nil || err2 != nil || max == 0 {
		return 0, os.ErrInvalid
	}
	return alloc / max, nil
}

func (c *ProcCollector) tcpRetransRate(path string) (float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	lines := strings.Split(string(b), "\n")
	var header, values []string
	for i := 0; i < len(lines)-1; i++ {
		if strings.HasPrefix(lines[i], "Tcp:") && strings.HasPrefix(lines[i+1], "Tcp:") {
			header = strings.Fields(lines[i])
			values = strings.Fields(lines[i+1])
		}
	}
	if len(header) == 0 || len(header) != len(values) {
		return 0, false
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	outSegs, _ := strconv.ParseFloat(values[idx["OutSegs"]], 64)
	retrans, _ := strconv.ParseFloat(values[idx["RetransSegs"]], 64)
	if !c.haveTCP {
		c.prevTCP = tcpSnap{outSegs: outSegs, retrans: retrans}
		c.haveTCP = true
		return 0, false
	}
	dOut := outSegs - c.prevTCP.outSegs
	dRe := retrans - c.prevTCP.retrans
	c.prevTCP = tcpSnap{outSegs: outSegs, retrans: retrans}
	if dOut <= 0 {
		return 0, true
	}
	return dRe / dOut, true
}

func (c *ProcCollector) softnetDelta(path string) (float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var dropped uint64
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// column 2 is dropped, hex
		v, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			continue
		}
		dropped += v
	}
	if !c.haveSN {
		c.prevSN = dropped
		c.haveSN = true
		return 0, false
	}
	delta := float64(dropped - c.prevSN)
	c.prevSN = dropped
	if delta < 0 {
		delta = 0
	}
	return delta, true
}

func readConntrack(root string) (used, max float64, err error) {
	ub, err1 := os.ReadFile(root + "/sys/net/netfilter/nf_conntrack_count")
	mb, err2 := os.ReadFile(root + "/sys/net/netfilter/nf_conntrack_max")
	if err1 != nil || err2 != nil {
		return 0, 0, os.ErrNotExist
	}
	used, err = strconv.ParseFloat(strings.TrimSpace(string(ub)), 64)
	if err != nil {
		return 0, 0, err
	}
	max, err = strconv.ParseFloat(strings.TrimSpace(string(mb)), 64)
	return used, max, err
}
