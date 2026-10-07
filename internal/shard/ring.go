package shard

import (
	"hash/fnv"
	"sort"
)

// Ring assigns a node (or entity) to an analyzer replica. Agents and a
// stateless router use the same function, so a replica owns a stable subset
// of nodes and incident state does not hop on every batch.
type Ring struct {
	replicas []string
}

func New(replicas []string) *Ring {
	cp := append([]string(nil), replicas...)
	sort.Strings(cp)
	return &Ring{replicas: cp}
}

func (r *Ring) Owner(key string) string {
	if len(r.replicas) == 0 {
		return ""
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return r.replicas[int(h.Sum32())%len(r.replicas)]
}

func (r *Ring) Mine(self, key string) bool {
	if self == "" || len(r.replicas) == 0 {
		return true
	}
	return r.Owner(key) == self
}

func (r *Ring) Replicas() []string { return append([]string(nil), r.replicas...) }
