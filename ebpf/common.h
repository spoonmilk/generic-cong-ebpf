#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

// TCP flows indexed by four-tuple
struct flow_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
} __attribute__((packed));

// Measurements sent to userspace, taken from GenericCongAvoid
struct measurement {
    struct flow_key flow;
    u32 acked;        // bytes acked
    u32 sacked;       // selectively acked packets
    u32 loss;         // lost packets
    u32 rtt;          // microseconds
    u32 inflight;     // packets
    u8 was_timeout;   // reset on timeout
    u8 _pad[3];
} __attribute__((packed));

// Flow events
struct flow_event {
    u8 event_type;  // 1=created, 2=closed
    u8 _pad[3];     // padding to align flow_key to 4-byte boundary
    struct flow_key flow;
    u32 init_cwnd;
    u32 mss;
} __attribute__((packed));

// For updates to cwnd from user CUBIC
struct user_update {
    u32 cwnd_bytes;
    u32 flow_command;
};

// Helper, extracts flow key from socket
static __always_inline void get_flow_key(struct sock *sk, struct flow_key *key) {
    key->saddr = sk->__sk_common.skc_rcv_saddr;
    key->daddr = sk->__sk_common.skc_daddr;
    key->sport = sk->__sk_common.skc_num;
    key->dport = __bpf_ntohs(sk->__sk_common.skc_dport);
}

#endif
