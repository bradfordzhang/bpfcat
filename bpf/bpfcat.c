#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

// Define the LPM Trie key structure for IPv4
struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 data;
};

// Define the ACL map
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct ipv4_lpm_key);
	__type(value, __u8); // 1 for DROP
	__uint(map_flags, BPF_F_NO_PREALLOC);
} acl_map SEC(".maps");

// Define a config map to hold the listening port
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u16);
} bpfcat_config SEC(".maps");

// acl_stats provides per-CPU counters for ACL dropped packets.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1); // 0: acl_drops
	__type(key, __u32);
	__type(value, __u64);
} acl_stats SEC(".maps");

SEC("xdp")
int bpfcat_xdp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// Parse Ethernet header
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	// Parse IPv4 header
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	// Read listening port from config map
	__u32 config_key = 0;
	__u16 *listen_port = bpf_map_lookup_elem(&bpfcat_config, &config_key);
	if (!listen_port || *listen_port == 0) {
		return XDP_PASS; // If port not configured, skip filtering
	}

	// Parse transport header and check destination port
	__u16 dest_port = 0;
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (void *)(iph + 1);
		if ((void *)(tcph + 1) > data_end) return XDP_PASS;
		dest_port = bpf_ntohs(tcph->dest);
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (void *)(iph + 1);
		if ((void *)(udph + 1) > data_end) return XDP_PASS;
		dest_port = bpf_ntohs(udph->dest);
	} else {
		return XDP_PASS; // Not TCP/UDP, ignore
	}

	if (dest_port != *listen_port) {
		return XDP_PASS; // Not destined for bpfcat, ignore
	}

	// Lookup source IP in the LPM Trie
	struct ipv4_lpm_key key = {
		.prefixlen = 32,
		.data = iph->saddr
	};

	__u8 *action = bpf_map_lookup_elem(&acl_map, &key);
	if (action && *action == 1) {
		__u32 drop_key = 0;
		__u64 *drop_val = bpf_map_lookup_elem(&acl_stats, &drop_key);
		if (drop_val) {
			*drop_val += 1;
		}
		return XDP_DROP;
	}

	return XDP_PASS;
}

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

	// Update stats
	__u32 bytes_key = 0;
	__u32 pkts_key = 1;
	__u64 *bytes_val = bpf_map_lookup_elem(&stats, &bytes_key);
	__u64 *pkts_val = bpf_map_lookup_elem(&stats, &pkts_key);

	if (bytes_val && pkts_val) {
		*bytes_val += skb->len;
		*pkts_val += 1;
	}

	// Attempt redirection. If it fails, fallback to user-space (SK_PASS).
	int ret = bpf_sk_redirect_map(skb, &sock_map, *peer_idx, 0);
	return (ret == SK_PASS) ? SK_PASS : SK_PASS; 
	// Note: We always return SK_PASS for now to ensure reliability. 
	// If redirection is successful, the kernel handles it. 
	// If it fails, the packet reaches the user-space socket.
}

char _license[] SEC("license") = "GPL";
