package shard

import "testing"

func TestStableOwner(t *testing.T) {
	r := New([]string{"a", "b", "c"})
	if r.Owner("node-1") != r.Owner("node-1") {
		t.Fatal("owner not stable")
	}
	if !r.Mine(r.Owner("node-9"), "node-9") {
		t.Fatal("mine failed")
	}
	if r.Mine("not-a-replica", "node-9") && r.Owner("node-9") != "not-a-replica" {
		t.Fatal("foreign replica claimed key")
	}
}

func TestEmptyRingAcceptsAll(t *testing.T) {
	r := New(nil)
	if !r.Mine("anyone", "node") {
		t.Fatal("empty ring should not drop")
	}
}
