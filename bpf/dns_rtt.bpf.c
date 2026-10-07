/* SPDX-License-Identifier: GPL-2.0 */
/* DNS RTT for UDP/53. Matches an egress datagram to the ingress reply on a
 * small flow key. Userspace reads the histogram as dns_latency_p99_us.
 * Attached to the cgroup skb of the workload, not the host, so CoreDNS and
 * the application are distinguishable. */
#include "common.h"

struct dns_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct dns_key);
	__type(value, __u64);
} dns_start SEC(".maps");

SEC("cgroup_skb/egress")
int kardia_dns_out(struct __sk_buff *skb)
{
	/* Userspace loader filters UDP dport 53 before this program runs hot.
	 * The timestamp is the send. */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + 42 > data_end)
		return 1;
	struct dns_key key = {};
	key.sport = skb->local_port;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&dns_start, &key, &now, BPF_ANY);
	return 1;
}

SEC("cgroup_skb/ingress")
int kardia_dns_in(struct __sk_buff *skb)
{
	struct dns_key key = {};
	key.sport = skb->local_port;
	__u64 *start = bpf_map_lookup_elem(&dns_start, &key);
	if (!start)
		return 1;
	__u64 us = (bpf_ktime_get_ns() - *start) / 1000;
	bpf_map_delete_elem(&dns_start, &key);
	hist_add(bpf_get_current_cgroup_id(), us);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
