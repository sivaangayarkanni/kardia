package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/agent"
	"github.com/sivaangayarkanni/kardia/internal/api"
	"github.com/sivaangayarkanni/kardia/internal/diagnose"
	"github.com/sivaangayarkanni/kardia/internal/ebpf"
	"github.com/sivaangayarkanni/kardia/internal/enrich"
	"github.com/sivaangayarkanni/kardia/internal/model"
	"github.com/sivaangayarkanni/kardia/internal/pipeline"
	"github.com/sivaangayarkanni/kardia/internal/store"
)

var version = "0.1.0"

func main() {
	mode := flag.String("mode", "all", "all | agent | analyzer")
	listen := flag.String("listen", ":8080", "analyzer listen address")
	ingestURL := flag.String("ingest-url", "", "analyzer ingest URL for agent mode (default http://127.0.0.1:8080/api/v1/ingest)")
	scenario := flag.String("scenario", "demo", "demo | off")
	interval := flag.Duration("interval", time.Second, "aggregation window")
	workers := flag.Int("workers", 4, "analyzer worker goroutines")
	queue := flag.Int("queue", 2048, "per-worker ingest queue depth")
	self := flag.String("replica", "", "this analyzer replica name")
	replicas := flag.String("replicas", "", "comma-separated analyzer replicas for shard ownership")
	bpfDir := flag.String("bpf-dir", "bpf/out", "compiled eBPF object directory")
	flag.Parse()

	host := enrich.Detect()
	log.Printf("kardia %s mode=%s platform=%s node=%s cluster=%s", version, *mode, host.Platform, host.Node, host.Cluster)

	bpf := ebpf.Probe(*bpfDir)
	log.Printf("ebpf: %s", bpf)

	st := store.NewMemory(20000)
	var srv *api.Server
	p := pipeline.New(diagnose.New(diagnose.DefaultConfig()), st, pipeline.Options{
		Workers:    *workers,
		QueueDepth: *queue,
		ClearAfter: 3,
		Self:       *self,
		Replicas:   split(*replicas),
		OnIncident: func(inc model.Incident) {
			if srv != nil {
				srv.Publish(inc)
			}
			verb := "updated"
			if inc.Status == model.StatusOpen && inc.Windows <= 2 {
				verb = "opened"
			}
			if inc.Status == model.StatusResolved {
				verb = "resolved"
			}
			log.Printf("incident %s %s severity=%s fault=%s subject=%s", verb, inc.ID, inc.Severity, inc.Fault, inc.Identity.Subject())
			log.Printf("  %s", inc.Summary)
		},
	})
	defer p.Close()
	srv = api.New(st, p, version, bpf)

	errCh := make(chan error, 1)
	if *mode == "all" || *mode == "analyzer" {
		go func() {
			log.Printf("listening on %s", *listen)
			errCh <- http.ListenAndServe(*listen, srv.Handler())
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	if *mode == "all" || *mode == "agent" {
		go runAgent(host, p, *mode, *ingestURL, *listen, *scenario, *interval)
	}

	select {
	case <-stop:
		log.Printf("shutting down")
	case err := <-errCh:
		log.Fatal(err)
	}
}

func runAgent(host enrich.Host, p *pipeline.Pipeline, mode, ingestURL, listen, scenario string, interval time.Duration) {
	proc := agent.NewProc(host)
	scenarios := agent.DemoScenarios(host)
	url := ingestURL
	if url == "" && mode == "agent" {
		url = "http://127.0.0.1" + listen + "/api/v1/ingest"
		if !strings.Contains(listen, ":") {
			url = "http://" + listen + "/api/v1/ingest"
		}
	}
	window := 0
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for now := range tick.C {
		window++
		var signals []model.Signal
		signals = append(signals, proc.Collect(now)...)
		if scenario == "demo" {
			signals = append(signals, agent.Simulate(scenarios, window, now)...)
		}
		batch := model.Batch{
			AgentID: host.Hostname,
			Node:    host.Node,
			Cluster: host.Cluster,
			SentAt:  now.UTC(),
			Signals: signals,
		}
		if mode == "agent" && url != "" {
			if err := post(url, batch); err != nil {
				log.Printf("export: %v", err)
			}
			continue
		}
		if err := p.Ingest(batch); err != nil {
			log.Printf("ingest backpressure: %v", err)
		}
	}
}

func post(url string, batch model.Batch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ingest status %d", resp.StatusCode)
	}
	return nil
}

func split(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
