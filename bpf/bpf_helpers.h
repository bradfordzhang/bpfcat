#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* Standard types, providing fallbacks if linux/types.h is problematic */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* BPF helper IDs are stable across architectures in the Linux kernel */
static int (*bpf_sk_redirect_map)(void *skb, void *map, __u32 key, __u64 flags) = (void *) 52;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *) 46;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

/* SK_SKB and SK_MSG return codes */
#define SK_DROP 0
#define SK_PASS 1

#endif
