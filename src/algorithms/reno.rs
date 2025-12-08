use super::{AlgorithmRunner, CwndUpdate};
use crate::bpf::DatapathEvent;
use anyhow::Result;
use ebpf_ccp_generic::{GenericAlgorithm, GenericFlow, Report};
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[derive(Default)]
pub struct Reno {
    mss: u32,
    init_cwnd: f64,
    cwnd: f64,
}

impl GenericFlow for Reno {
    fn curr_cwnd(&self) -> u32 {
        self.cwnd as u32
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = f64::from(cwnd);
    }

    fn increase(&mut self, report: &Report) {
        self.cwnd += f64::from(self.mss) * (f64::from(report.bytes_acked) / self.cwnd);
    }

    fn reduction(&mut self, _report: &Report) {
        self.cwnd /= 2.0;
        if self.cwnd <= self.init_cwnd {
            self.cwnd = self.init_cwnd;
        }
    }

    fn reset(&mut self) {
        self.cwnd = self.init_cwnd;
    }
}

pub struct RenoAlgorithm;

impl GenericAlgorithm for RenoAlgorithm {
    fn name(&self) -> &str {
        "reno"
    }

    fn create_flow(&self, init_cwnd: u32, mss: u32) -> Box<dyn GenericFlow> {
        Box::new(Reno {
            mss,
            init_cwnd: f64::from(init_cwnd),
            cwnd: f64::from(init_cwnd),
        })
    }
}

struct FlowState {
    reno: Reno,
    mss: u32,
}

pub struct RenoRunner {
    reno_alg: Reno,
    flows: HashMap<u64, FlowState>,
}

impl RenoRunner {
    pub fn new(_init_cwnd_pkts: u32, _mss: u32) -> Self {
        Self {
            reno_alg: Reno::default(),
            flows: HashMap::new(),
        }
    }
}

impl AlgorithmRunner for RenoRunner {
    fn name(&self) -> &str {
        "ebpf_ccp_reno"
    }

    fn ebpf_path(&self) -> &str {
        "ebpf/.output/datapath-reno.bpf.o"
    }

    fn struct_ops_name(&self) -> &str {
        "ebpf_ccp_reno"
    }

    fn handle_event(&mut self, event: DatapathEvent) -> Result<Option<CwndUpdate>> {
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

                let reno = Reno {
                    mss,
                    init_cwnd: f64::from(init_cwnd),
                    cwnd: f64::from(init_cwnd),
                };
                self.flows.insert(flow_id, FlowState { reno, mss });
                Ok(None)
            }

            DatapathEvent::FlowClosed { flow_id } => {
                info!("Flow closed: {:016x}", flow_id);
                self.flows.remove(&flow_id);
                Ok(None)
            }

            DatapathEvent::Measurement {
                flow_id,
                measurement,
            } => {
                if let Some(flow) = self.flows.get_mut(&flow_id) {
                    // Handle timeout - reset RENO state
                    if measurement.flow_stats.was_timeout != 0 {
                        warn!("Timeout on flow {:016x} - resetting", flow_id);
                        flow.reno.reset();
                        let fallback_cwnd = flow
                            .reno
                            .curr_cwnd()
                            .max(measurement.flow_stats.bytes_in_flight);
                        flow.reno.set_cwnd(fallback_cwnd);

                        return Ok(Some(CwndUpdate {
                            flow_id,
                            cwnd_bytes: flow.reno.curr_cwnd(),
                            pacing_rate: None,
                        }));
                    }

                    // Convert Measurement to Report for the algorithm
                    let report = Report {
                        flow_key: ebpf_ccp_generic::FlowKey {
                            saddr: measurement.flow.saddr,
                            daddr: measurement.flow.daddr,
                            sport: measurement.flow.sport,
                            dport: measurement.flow.dport,
                        },
                        packets_in_flight: measurement.flow_stats.packets_in_flight,
                        bytes_in_flight: measurement.flow_stats.bytes_in_flight,
                        bytes_pending: measurement.flow_stats.bytes_pending,
                        rtt_sample_us: measurement.flow_stats.rtt_sample_us,
                        was_timeout: measurement.flow_stats.was_timeout != 0,
                        bytes_acked: measurement.ack_stats.bytes_acked,
                        packets_acked: measurement.ack_stats.packets_acked,
                        bytes_misordered: measurement.ack_stats.bytes_misordered,
                        packets_misordered: measurement.ack_stats.packets_misordered,
                        ecn_bytes: measurement.ack_stats.ecn_bytes,
                        ecn_packets: measurement.ack_stats.ecn_packets,
                        lost_pkts_sample: measurement.ack_stats.lost_pkts_sample,
                        rate_incoming: 0,
                        rate_outgoing: 0,
                        snd_cwnd: measurement.snd_cwnd,
                        snd_ssthresh: measurement.snd_ssthresh,
                        pacing_rate: measurement.pacing_rate,
                        ca_state: measurement.ca_state,
                        now: measurement.ack_stats.now,
                    };

                    let old_cwnd = flow.reno.curr_cwnd();
                    if report.lost_pkts_sample > 0 {
                        flow.reno.reduction(&report);
                    } else if report.bytes_acked > 0 {
                        flow.reno.increase(&report);
                    }

                    let new_cwnd = flow.reno.curr_cwnd();
                    if old_cwnd != new_cwnd {
                        debug!(
                            "Flow {:016x}: cwnd {} -> {} bytes",
                            flow_id, old_cwnd, new_cwnd
                        );
                    }

                    // Return cwnd update
                    Ok(Some(CwndUpdate {
                        flow_id,
                        cwnd_bytes: new_cwnd,
                        pacing_rate: None,
                    }))
                } else {
                    warn!("Received measurement for unknown flow: {:016x}", flow_id);
                    Ok(None)
                }
            }
        }
    }

    fn cleanup(&mut self) {
        info!("Cleaning up {} active Reno flows", self.flows.len());
        self.flows.clear();
    }
}
