/* SPDX-License-Identifier: GPL-2.0 */
/* TCP retransmits and listen overflows. Retransmits increment a per-cgroup
 * counter; userspace divides by segments out (from the TCP SNMP counter or
 * from a paired tcp_sendmsg probe) to produce tcp_retrans_rate. */
#include "common.h"

struct tcp_retransmit_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u64 key)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &key);
	if (!v) {
		__u64 zero = 1;
		bpf_map_update_elem(&counters, &key, &zero, BPF_NOEXIST);
		return;
	}
	__sync_fetch_and_add(v, 1);
}

SEC("tp/tcp/tcp_retransmit_skb")
int kardia_retrans(struct tcp_retransmit_args *ctx)
{
	__u64 cg = bpf_get_current_cgroup_id();
	bump(cg);
	bump(0);
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->cgroup_id = cg;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->kind = 2;
	e->value = ctx->dport;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
