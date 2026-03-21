#include <linux/bpf.h>
#include "bpf_helpers.h"

// sock_map stores socket file descriptors for kernel-level redirection.
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 65535);
	__type(key, __u32);
	__type(value, __u32);
} sock_map SEC(".maps");

// cookie_to_peer_index maps a socket's unique kernel cookie to its peer's index in sock_map.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65535);
	__type(key, __u64);
	__type(value, __u32);
} cookie_to_peer_index SEC(".maps");

// stats provides per-CPU counters for global throughput and packet metrics.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2); // 0: total_bytes, 1: total_packets
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// bpfcat_verdict intercepts stream traffic and redirects it to the mapped peer socket.
SEC("sk_skb/stream_verdict")
int bpfcat_verdict(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	if (!cookie) {
		return SK_PASS;
	}

	__u32 *peer_idx = bpf_map_lookup_elem(&cookie_to_peer_index, &cookie);
	if (!peer_idx) {
		return SK_PASS;
	}

	__u32 bytes_key = 0;
	__u32 pkts_key = 1;
	__u64 *bytes_val = bpf_map_lookup_elem(&stats, &bytes_key);
	__u64 *pkts_val = bpf_map_lookup_elem(&stats, &pkts_key);

	if (bytes_val && pkts_val) {
		*bytes_val += skb->len;
		*pkts_val += 1;
	}

	return bpf_sk_redirect_map(skb, &sock_map, *peer_idx, 0);
}

char _license[] SEC("license") = "GPL";
