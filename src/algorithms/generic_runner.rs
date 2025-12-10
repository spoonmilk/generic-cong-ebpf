use std::collections::HashMap;

use crate::bpf::DatapathEvent;
use anyhow::anyhow;
use ebpf_ccp_generic::{FlowKey, GenericAlgorithm, GenericFlow, Report};
use tracing::{debug, info, warn};

use crate::algorithms::{AlgorithmRunner, CwndUpdate};

struct FlowState {
    flow: Box<dyn GenericFlow>,
    last_lost_pkts: u32,
    last_cwnd: u32,
}

pub struct GenericRunner<A: GenericAlgorithm> {
    algorithm: A,
    flows: HashMap<u64, FlowState>,
    init_cwnd: u32,
    mss: u32,
}

impl<A: GenericAlgorithm> GenericRunner<A> {
    pub fn new(algorithm: A, init_cwnd: u32, mss: u32) -> Self {
        Self {
            algorithm,
            flows: HashMap::new(),
            init_cwnd,
            mss,
        }
    }
}

impl<A: GenericAlgorithm> AlgorithmRunner for GenericRunner<A> {
    fn name(&self) -> &str {
        self.algorithm.name()
    }

    fn ebpf_path(&self) -> &str {
        "ebpf/.output/generic.bpf.o"
    }

    fn struct_ops_name(&self) -> &str {
        "ebpf_ccp_gen"
    }

    fn handle_event(
        &mut self,
        event: crate::bpf::DatapathEvent,
    ) -> anyhow::Result<Option<super::CwndUpdate>> {
        match event {
            DatapathEvent::FlowCreated {
                flow_id,
                init_cwnd,
                mss,
            } => {
                info!(
                    "Flow created: {:016x}, init_cwnd={} bytes, mss={} bytes",
                    flow_id, init_cwnd, mss
                );
                let new_flow = self.algorithm.create_flow(init_cwnd, mss);
                let flow_state = FlowState {
                    flow: new_flow,
                    last_lost_pkts: 0,
                    last_cwnd: init_cwnd,
                };
                self.flows.insert(flow_id, flow_state);
                Ok(None)
            }

            DatapathEvent::Measurement {
                flow_id,
                measurement,
            } => {
                let flow_state = self
                    .flows
                    .get_mut(&flow_id)
                    .ok_or_else(|| anyhow!("Unknown flow {}", flow_id))?;

                let flow_key = FlowKey {
                    saddr: measurement.flow.saddr,
                    daddr: measurement.flow.daddr,
                    sport: measurement.flow.sport,
                    dport: measurement.flow.dport,
                };

                // Convert Measurement → Report
                let report = Report {
                    flow_key,

                    // Flow statistics
                    packets_in_flight: measurement.flow_stats.packets_in_flight,
                    bytes_in_flight: measurement.flow_stats.bytes_in_flight,
                    bytes_pending: measurement.flow_stats.bytes_pending,
                    rtt_sample_us: measurement.flow_stats.rtt_sample_us,
                    was_timeout: measurement.flow_stats.was_timeout != 0,

                    // ACK statistics
                    bytes_acked: measurement.ack_stats.bytes_acked,
                    packets_acked: measurement.ack_stats.packets_acked,
                    bytes_misordered: measurement.ack_stats.bytes_misordered,
                    packets_misordered: measurement.ack_stats.packets_misordered,
                    ecn_bytes: measurement.ack_stats.ecn_bytes,
                    ecn_packets: measurement.ack_stats.ecn_packets,
                    lost_pkts_sample: measurement.ack_stats.lost_pkts_sample,

                    // Kernel context
                    snd_cwnd: measurement.snd_cwnd,
                    snd_ssthresh: measurement.snd_ssthresh,
                    pacing_rate: measurement.pacing_rate,
                    ca_state: measurement.ca_state,
                    now: measurement.ack_stats.now,
                    rate_incoming: measurement.rates.rate_incoming,
                    rate_outgoing: measurement.rates.rate_outgoing,
                };

                // lost_pkts_sample is cumulative (tp->lost_out), not incremental
                let new_loss = report.lost_pkts_sample > flow_state.last_lost_pkts;

                let old_cwnd = flow_state.flow.curr_cwnd();

                if report.was_timeout {
                    warn!(
                        "Flow {:016x}: timeout detected, resetting (cwnd: {} bytes)",
                        flow_id, old_cwnd
                    );
                    flow_state.flow.reset();
                    flow_state.last_lost_pkts = 0;
                } else if new_loss {
                    flow_state.flow.reduction(&report);
                    flow_state.last_lost_pkts = report.lost_pkts_sample;
                } else if report.bytes_acked > 0 {
                    flow_state.flow.increase(&report);
                    // Reset loss counter when all losses are recovered
                    if report.lost_pkts_sample == 0 {
                        flow_state.last_lost_pkts = 0;
                    }
                }

                let new_cwnd = flow_state.flow.curr_cwnd();
                let pacing_rate = flow_state.flow.curr_pacing_rate();

                if old_cwnd != new_cwnd {
                    debug!(
                        "Flow {:016x}: cwnd {} -> {} bytes (acked={}, rtt={}us, inflight={})",
                        flow_id,
                        old_cwnd,
                        new_cwnd,
                        report.bytes_acked,
                        report.rtt_sample_us,
                        report.bytes_in_flight
                    );
                }

                // Only send update if cwnd actually changed
                if new_cwnd != flow_state.last_cwnd || pacing_rate.is_some() {
                    flow_state.last_cwnd = new_cwnd;
                    Ok(Some(CwndUpdate {
                        flow_id,
                        cwnd_bytes: new_cwnd,
                        pacing_rate,
                    }))
                } else {
                    Ok(None)
                }
            }

            DatapathEvent::FlowClosed { flow_id } => {
                info!("Flow closed: {:016x}", flow_id);
                self.flows.remove(&flow_id);
                Ok(None)
            }
        }
    }

    fn cleanup(&mut self) {
        info!("Cleaning up {} datapath flows", self.flows.len());
        self.flows.clear();
    }
}
