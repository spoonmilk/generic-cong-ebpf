#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
} generic_flow_map SEC(".maps");

struct flow_statistics {
    struct flow_key flow;
    u32 packets_in_flight;
    u32 bytes_in_flight;
    u32 bytes_pending;
    u32 rtt_sample_us;
    u8 was_timeout;
    u32 rate_incoming;
    u32 rate_outgoing;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
} generic_ack_map SEC(".maps");

