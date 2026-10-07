package enrich

import "testing"

func TestPodIdentityOverridesPlatform(t *testing.T) {
	h := Host{Hostname: "ip-10-0-1-12", Node: "ip-10-0-1-12", Platform: "vm", Cloud: "aws", VMID: "i-1"}
	id := PodIdentity(h, "/kubepods/burstable/podabc/crio-def", "checkout", "api-0", "api")
	if id.Platform != "kubernetes" || id.Pod != "api-0" || id.VMID != "i-1" {
		t.Fatalf("%+v", id)
	}
	if id.EntityKey() == "" {
		t.Fatal("empty key")
	}
}
