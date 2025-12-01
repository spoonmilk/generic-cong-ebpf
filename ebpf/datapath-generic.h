#ifndef __DATAPATH_GENERIC_H
#define __DATAPATH_GENERIC_H

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

struct flow_statistics {
 struct flow_key flow;
    u32 packets_in_flight;
    u32 bytes_in_flight;
    u32 bytes_pending;
    u32 rtt_sample_us;
    u8 was_timeout;
};

struct flow_rates {
    struct flow_key flow;
    u32 rate_incoming;
    u32 rate_outgoing;
};

struct ack_statistics {
    struct flow_key flow;
    u32 packets_acked;
    u32 bytes_acked;
    u32 packets_misordered;
    u32 bytes_misordered;
    u32 ecn_packets;
    u32 ecn_bytes;
    u32 lost_pckts_sample;
    u32 now;
};

#endif
