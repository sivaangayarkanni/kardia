package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sivaangayarkanni/kardia/internal/ebpf"
	"github.com/sivaangayarkanni/kardia/internal/model"
	"github.com/sivaangayarkanni/kardia/internal/pipeline"
	"github.com/sivaangayarkanni/kardia/internal/store"
)

// Server is the stateless query and ingest front. Replicas share nothing;
// shard ownership is decided by the pipeline ring before a batch is queued.
type Server struct {
	Store    store.Store
	Pipeline *pipeline.Pipeline
	Version  string
	Started  time.Time
	BPF      ebpf.Capability
	hub      *hub
}

func New(st store.Store, p *pipeline.Pipeline, version string, bpf ebpf.Capability) *Server {
	return &Server{Store: st, Pipeline: p, Version: version, Started: time.Now().UTC(), BPF: bpf, hub: newHub()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.health)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/incidents", s.listIncidents)
	mux.HandleFunc("GET /api/v1/incidents/", s.getIncident)
	mux.HandleFunc("GET /api/v1/signals", s.signals)
	mux.HandleFunc("POST /api/v1/ingest", s.ingest)
	mux.HandleFunc("GET /api/v1/stream", s.stream)
	mux.HandleFunc("GET /", s.ui)
	return mux
}

func (s *Server) Publish(inc model.Incident) { s.hub.publish(inc) }

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  s.Version,
		"started":  s.Started,
		"store":    s.Store.Stats(),
		"pipeline": s.Pipeline.Counters(),
		"ebpf":     s.BPF,
		"programs": ebpf.Programs,
	})
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	status := model.IncidentStatus(r.URL.Query().Get("status"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": s.Store.ListIncidents(status, limit)})
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	inc, ok := s.Store.GetIncident(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (s *Server) signals(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	writeJSON(w, http.StatusOK, map[string]any{"signals": s.Store.RecentSignals(limit)})
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var batch model.Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if batch.SentAt.IsZero() {
		batch.SentAt = time.Now().UTC()
	}
	if err := s.Pipeline.Ingest(batch); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(batch.Signals)})
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)
	fmt.Fprintf(w, "event: hello\ndata: {\"status\":\"ok\"}\n\n")
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case inc := <-ch:
			b, _ := json.Marshal(inc)
			fmt.Fprintf(w, "event: incident\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	c := s.Pipeline.Counters()
	st := s.Store.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "kardia_batches_accepted_total %d\n", c.Accepted)
	fmt.Fprintf(w, "kardia_batches_dropped_total %d\n", c.Dropped)
	fmt.Fprintf(w, "kardia_incident_updates_total %d\n", c.Incidents)
	fmt.Fprintf(w, "kardia_incidents %d\n", st.Incidents)
	fmt.Fprintf(w, "kardia_incidents_open %d\n", st.Open)
	fmt.Fprintf(w, "kardia_signals_retained %d\n", st.Signals)
	fmt.Fprintf(w, "kardia_workers %d\n", c.Workers)
}

func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type hub struct {
	mu   sync.Mutex
	subs map[chan model.Incident]struct{}
}

func newHub() *hub { return &hub{subs: map[chan model.Incident]struct{}{}} }

func (h *hub) subscribe() chan model.Incident {
	ch := make(chan model.Incident, 32)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan model.Incident) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *hub) publish(inc model.Incident) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- inc:
		default:
		}
	}
}
