//! CUBIC congestion control algorithm implementation

use super::{AlgorithmRunner, CwndUpdate};
use crate::bpf::DatapathEvent;
use anyhow::Result;
use ebpf_ccp_cubic::{GenericAlgorithm, GenericFlow, Report};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

#[derive(Default)]
struct Cubic {
    pkt_size: u32,
    init_cwnd: u32,

    cwnd: f64,
    cwnd_cnt: f64,
    tcp_friendliness: bool,
    beta: f64,
    fast_convergence: bool,
    c: f64,
    wlast_max: f64,
    epoch_start: Option<Instant>,
    origin_point: f64,
    d_min: Option<Duration>,
    wtcp: f64,
    k: f64,
    ack_cnt: f64,
    cnt: f64,
}

impl Cubic {
    fn cubic_update(&mut self) {
        self.ack_cnt += 1.0;
        if self.epoch_start.is_none() {
            self.epoch_start = Some(Instant::now());
            if self.cwnd < self.wlast_max {
                let temp = (self.wlast_max - self.cwnd) / self.c;
                self.k = (temp.max(0.0)).powf(1.0 / 3.0);
                self.origin_point = self.wlast_max;
            } else {
                self.k = 0.0;
                self.origin_point = self.cwnd;
            }

            self.ack_cnt = 1.0;
            self.wtcp = self.cwnd
        }

        let d_min = self.d_min.unwrap_or(Duration::from_millis(100));
        let t = (Instant::now() - d_min - self.epoch_start.unwrap()).as_secs_f64();
        let target = self.origin_point + self.c * ((t - self.k) * (t - self.k) * (t - self.k));
        if target > self.cwnd {
            self.cnt = self.cwnd / (target - self.cwnd);
        } else {
            self.cnt = 100.0 * self.cwnd;
        }

        if self.tcp_friendliness {
            self.cubic_tcp_friendliness();
        }
    }

    fn cubic_tcp_friendliness(&mut self) {
        self.wtcp += ((3.0 * self.beta) / (2.0 - self.beta)) * (self.ack_cnt / self.cwnd);
        self.ack_cnt = 0.0;
        if self.wtcp > self.cwnd {
            let max_cnt = self.cwnd / (self.wtcp - self.cwnd);
            if self.cnt > max_cnt {
                self.cnt = max_cnt;
            }
        }
    }

    fn cubic_reset(&mut self) {
        self.wlast_max = 0.0;
        self.epoch_start = None;
        self.origin_point = 0.0;
        self.d_min = None;
        self.wtcp = 0.0;
        self.k = 0.0;
        self.ack_cnt = 0.0;
    }
}

impl GenericFlow for Cubic {
    fn curr_cwnd(&self) -> u32 {
        (self.cwnd * f64::from(self.pkt_size)) as u32
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = f64::from(cwnd) / f64::from(self.pkt_size);
    }

    fn increase(&mut self, report: &Report) {
        let f_rtt = Duration::from_micros(report.rtt_sample_us as _);
        let no_of_acks = ((f64::from(report.bytes_acked)) / (f64::from(self.pkt_size))) as u32;
        for _ in 0..no_of_acks {
            match self.d_min {
                None => self.d_min = Some(f_rtt),
                Some(dmin) if f_rtt < dmin => {
                    self.d_min = Some(f_rtt);
                }
                _ => (),
            }

            self.cubic_update();
            if self.cwnd_cnt > self.cnt {
                self.cwnd += 1.0;
                self.cwnd_cnt = 0.0;
            } else {
                self.cwnd_cnt += 1.0;
            }
        }
    }

    fn reduction(&mut self, _report: &Report) {
        self.epoch_start = None;
        if self.cwnd < self.wlast_max && self.fast_convergence {
            self.wlast_max = self.cwnd * ((2.0 - self.beta) / 2.0);
        } else {
            self.wlast_max = self.cwnd;
        }

        self.cwnd *= 1.0 - self.beta;
        if self.cwnd as u32 <= self.init_cwnd {
            self.cwnd = f64::from(self.init_cwnd);
        }
    }

    fn reset(&mut self) {
        self.cubic_reset();
    }
}

pub struct CubicAlgorithm;

impl GenericAlgorithm for CubicAlgorithm {
    fn name(&self) -> &str {
        "cubic"
    }

    fn create_flow(&self, init_cwnd: u32, mss: u32) -> Box<dyn GenericFlow> {
        Box::new(Cubic {
            pkt_size: mss,
            init_cwnd,
            cwnd: f64::from(init_cwnd),
            cwnd_cnt: 0.0,
            tcp_friendliness: true,
            beta: 0.7,
            fast_convergence: true,
            c: 0.4,
            wlast_max: 0.0,
            epoch_start: None,
            origin_point: 0.0,
            d_min: None,
            wtcp: 0.0,
            k: 0.0,
            ack_cnt: 0.0,
            cnt: 0.0,
        })
    }
}

struct FlowState {
    cubic: Cubic,
    mss: u32,
}

pub struct CubicRunner {
    cubic_alg: Cubic,
    flows: HashMap<u64, FlowState>,
}

impl CubicRunner {
    pub fn new(_init_cwnd_pkts: u32, _mss: u32) -> Self {
        Self {
            cubic_alg: Cubic::default(),
            flows: HashMap::new(),
        }
    }
}

impl AlgorithmRunner for CubicRunner {
    fn name(&self) -> &str {
        "ebpf_ccp_cubic"
    }

    fn ebpf_path(&self) -> &str {
        "ebpf/.output/datapath-cubic.bpf.o"
    }

    fn struct_ops_name(&self) -> &str {
        "ebpf_ccp_cubic"
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

                let cubic = Cubic {
                    pkt_size: mss,
                    init_cwnd: init_cwnd / mss,
                    cwnd: f64::from(init_cwnd / mss),
                    cwnd_cnt: 0.0,
                    tcp_friendliness: true,
                    beta: 0.7,
                    fast_convergence: true,
                    c: 0.4,
                    wlast_max: 0.0,
                    epoch_start: None,
                    origin_point: 0.0,
                    d_min: None,
                    wtcp: 0.0,
                    k: 0.0,
                    ack_cnt: 0.0,
                    cnt: 0.0,
                };
                self.flows.insert(flow_id, FlowState { cubic, mss });
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
                    // Handle timeout - reset CUBIC state
                    if measurement.flow_stats.was_timeout != 0 {
                        warn!("Timeout on flow {:016x} - resetting", flow_id);
                        flow.cubic.reset();
                        let fallback_cwnd =
                            flow.cubic.curr_cwnd().max(measurement.flow_stats.bytes_in_flight);
                        flow.cubic.set_cwnd(fallback_cwnd);

                        return Ok(Some(CwndUpdate {
                            flow_id,
                            cwnd_bytes: flow.cubic.curr_cwnd(),
                        }));
                    }

                    // Convert Measurement to Report for the algorithm
                    let report = Report {
                        flow_key: ebpf_ccp_cubic::FlowKey {
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

                    // Run CUBIC algorithm
                    let old_cwnd = flow.cubic.curr_cwnd();
                    if report.lost_pkts_sample > 0 {
                        // Congestion detected - reduce
                        flow.cubic.reduction(&report);
                    } else if report.bytes_acked > 0 {
                        // ACK received - increase
                        flow.cubic.increase(&report);
                    }

                    let new_cwnd = flow.cubic.curr_cwnd();
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
                    }))
                } else {
                    warn!("Received measurement for unknown flow: {:016x}", flow_id);
                    Ok(None)
                }
            }
        }
    }

    fn cleanup(&mut self) {
        info!("Cleaning up {} active CUBIC flows", self.flows.len());
        self.flows.clear();
    }
}
