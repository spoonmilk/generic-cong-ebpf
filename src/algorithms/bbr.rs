//! BBR congestion control algorithm implementation
//!
//! Linux source: `net/ipv4/tcp_bbr.c`
//!
//! Model of the network path:
//! ```no-run
//!    bottleneck_bandwidth = windowed_max(delivered / elapsed, 10 round trips)
//!    min_rtt = windowed_min(rtt, 10 seconds)
//! ```
//! ```no-run
//! pacing_rate = pacing_gain * bottleneck_bandwidth
//! cwnd = max(cwnd_gain * bottleneck_bandwidth * min_rtt, 4)
//! ```
//!
//! A BBR flow starts in STARTUP, and ramps up its sending rate quickly.
//! When it estimates the pipe is full, it enters DRAIN to drain the queue.
//! In steady state a BBR flow only uses `PROBE_BW` and `PROBE_RTT`.
//!
//! This implementation does `PROBE_BW` and `PROBE_RTT`, but leaves as future work
//! an implementation of the finer points of other BBR implementations
//! (e.g. policing detection, STARTUP/DRAIN modes).

use ebpf_ccp_generic::{GenericAlgorithm, GenericFlow, Report};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// BBR flow state
pub struct Bbr {
    mss: u32,
    init_cwnd: u32,

    // Current congestion window (in bytes)
    cwnd: u32,

    // Current pacing rate (bytes/sec)
    pacing_rate: u64,

    // BBR state
    mode: BbrMode,
    probe_rtt_interval: Duration,

    // Bottleneck bandwidth estimate (bytes/sec)
    bottleneck_bw: f64,
    bottleneck_bw_timeout: Instant,

    // Minimum RTT estimate
    min_rtt_us: u32,
    min_rtt_timeout: Instant,

    // Pacing and probing state
    probe_bw_state: u32, // 0=down, 1=cruise, 2=up
    probe_bw_timer: Instant,
    probe_rtt_done_timestamp: Option<Instant>,
    probe_rtt_inflight_reached: bool,

    start: Instant,
}

#[derive(Clone, Copy, PartialEq)]
enum BbrMode {
    ProbeBw,
    ProbeRtt,
}

pub const PROBE_RTT_INTERVAL_SECONDS: i64 = 10;
const PROBE_RTT_DURATION_MS: u64 = 200;
const MIN_CWND_PACKETS: u32 = 4;

impl Bbr {
    fn new(init_cwnd: u32, mss: u32) -> Self {
        let now = Instant::now();
        let probe_rtt_interval = Duration::from_secs(PROBE_RTT_INTERVAL_SECONDS as u64);
        let initial_bw = 125_000.0; // 1 Mbps in bytes/sec

        Self {
            mss,
            init_cwnd,
            cwnd: init_cwnd,
            pacing_rate: initial_bw as u64,
            mode: BbrMode::ProbeBw,
            probe_rtt_interval,
            bottleneck_bw: initial_bw,
            bottleneck_bw_timeout: now + probe_rtt_interval,
            min_rtt_us: 1_000_000, // Initial estimate: 1 second
            min_rtt_timeout: now + probe_rtt_interval,
            probe_bw_state: 0,
            probe_bw_timer: now,
            probe_rtt_done_timestamp: None,
            probe_rtt_inflight_reached: false,
            start: now,
        }
    }

    /// Calculate target pacing rate based on current BW estimate and gain
    fn calculate_pacing_rate(&self) -> u64 {
        let gain = match self.mode {
            BbrMode::ProbeBw => {
                match self.probe_bw_state {
                    0 => 0.75, // Drain mode
                    1 => 1.0,  // Cruise mode
                    _ => 1.25, // Probe mode
                }
            }
            BbrMode::ProbeRtt => 0.75, // Reduce pacing to drain queue
        };

        (self.bottleneck_bw * gain) as u64
    }

    /// Calculate target cwnd based on BDP estimate
    fn calculate_target_cwnd(&self) -> u32 {
        // cwnd = gain * BDP = gain * bottleneck_bw * min_rtt
        let bdp = self.bottleneck_bw * (f64::from(self.min_rtt_us) / 1_000_000.0);
        let gain = match self.mode {
            BbrMode::ProbeBw => {
                match self.probe_bw_state {
                    0 => 0.75, // Drain mode
                    1 => 1.0,  // Cruise mode
                    _ => 1.25, // Probe mode
                }
            }
            BbrMode::ProbeRtt => 0.5, // Reduce to probe min RTT
        };

        let target = (bdp * gain * 2.0) as u32; // 2x BDP for cwnd
        target.max(MIN_CWND_PACKETS * self.mss)
    }

    /// Update bandwidth estimate from throughput measurement
    fn update_bandwidth(&mut self, report: &Report) {
        if report.bytes_acked == 0 {
            return;
        }

        // Estimate throughput from this ACK
        let rtt_sec = f64::from(report.rtt_sample_us) / 1_000_000.0;
        if rtt_sec > 0.0 {
            let throughput = f64::from(report.bytes_acked) / rtt_sec;

            // Update bottleneck bandwidth estimate (windowed max)
            if throughput > self.bottleneck_bw {
                self.bottleneck_bw = throughput;
                self.bottleneck_bw_timeout = Instant::now() + self.probe_rtt_interval;
                debug!(
                    "Updated bottleneck_bw to {:.2} Mbps",
                    self.bottleneck_bw / 125_000.0
                );
            }
        }
    }

    /// Update min RTT estimate
    fn update_min_rtt(&mut self, rtt_us: u32) {
        let now = Instant::now();

        if rtt_us < self.min_rtt_us {
            self.min_rtt_us = rtt_us;
            self.min_rtt_timeout = now + self.probe_rtt_interval;
            debug!("Updated min_rtt to {} us", self.min_rtt_us);
        }
    }

    /// Handle PROBE_BW state machine
    fn handle_probe_bw(&mut self, report: &Report) {
        let now = Instant::now();
        let min_rtt = Duration::from_micros(self.min_rtt_us as u64);

        // State transitions based on time in current state
        let time_in_state = now.duration_since(self.probe_bw_timer);

        match self.probe_bw_state {
            0 => {
                // Drain state (0.75x) - stay for 1 RTT
                if time_in_state >= min_rtt {
                    self.probe_bw_state = 1;
                    self.probe_bw_timer = now;
                    debug!("PROBE_BW: drain -> cruise");
                }
            }
            1 => {
                // Cruise state (1.0x) - stay for 2 RTTs
                if time_in_state >= min_rtt * 2 {
                    self.probe_bw_state = 2;
                    self.probe_bw_timer = now;
                    debug!("PROBE_BW: cruise -> probe");
                }
            }
            _ => {
                // Probe state (1.25x) - stay for 8 RTTs
                if time_in_state >= min_rtt * 8 {
                    self.probe_bw_state = 0;
                    self.probe_bw_timer = now;
                    debug!("PROBE_BW: probe -> drain");
                }
            }
        }

        // Check if we need to enter PROBE_RTT
        if now > self.min_rtt_timeout {
            self.mode = BbrMode::ProbeRtt;
            self.min_rtt_us = 0x3fff_ffff; // Reset min_rtt
            self.probe_rtt_done_timestamp = None;
            self.probe_rtt_inflight_reached = false;
            info!(min_rtt_us = report.rtt_sample_us, "Entering PROBE_RTT mode");
        }
    }

    /// Handle PROBE_RTT state
    fn handle_probe_rtt(&mut self, report: &Report) {
        let now = Instant::now();

        // Check if we've reached target inflight (4 packets)
        if !self.probe_rtt_inflight_reached && report.packets_in_flight <= MIN_CWND_PACKETS {
            self.probe_rtt_inflight_reached = true;
            self.probe_rtt_done_timestamp = Some(now);
            debug!("PROBE_RTT: reached target inflight");
        }

        // Exit PROBE_RTT after minimum duration
        if let Some(done_time) = self.probe_rtt_done_timestamp {
            let duration = now.duration_since(done_time);
            if duration >= Duration::from_millis(PROBE_RTT_DURATION_MS) {
                self.mode = BbrMode::ProbeBw;
                self.probe_bw_state = 0; // Start in drain
                self.probe_bw_timer = now;
                self.min_rtt_timeout = now + self.probe_rtt_interval;
                info!(min_rtt_us = self.min_rtt_us, "Exiting PROBE_RTT mode");
            }
        }
    }
}

impl GenericFlow for Bbr {
    fn curr_cwnd(&self) -> u32 {
        self.cwnd
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = cwnd;
    }

    fn curr_pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate)
    }

    fn increase(&mut self, report: &Report) {
        // Update bandwidth and RTT estimates
        self.update_bandwidth(report);
        self.update_min_rtt(report.rtt_sample_us);

        // Handle state machine based on current mode
        match self.mode {
            BbrMode::ProbeBw => {
                self.handle_probe_bw(report);
            }
            BbrMode::ProbeRtt => {
                self.handle_probe_rtt(report);
            }
        }

        // Update cwnd and pacing rate based on current state
        let old_cwnd = self.cwnd;
        let old_pacing_rate = self.pacing_rate;
        self.cwnd = self.calculate_target_cwnd();
        self.pacing_rate = self.calculate_pacing_rate();

        if old_cwnd != self.cwnd || old_pacing_rate != self.pacing_rate {
            debug!(
                mode = match self.mode {
                    BbrMode::ProbeBw => "PROBE_BW",
                    BbrMode::ProbeRtt => "PROBE_RTT",
                },
                state = self.probe_bw_state,
                old_cwnd = old_cwnd,
                new_cwnd = self.cwnd,
                old_pacing_Mbps = old_pacing_rate as f64 / 125_000.0,
                new_pacing_Mbps = self.pacing_rate as f64 / 125_000.0,
                bottleneck_bw_Mbps = self.bottleneck_bw / 125_000.0,
                min_rtt_us = self.min_rtt_us,
                "BBR update"
            );
        }
    }

    fn reduction(&mut self, _report: &Report) {
        // BBR doesn't reduce cwnd on loss in the same way as loss-based CCAs
        // It relies on bandwidth and RTT measurements instead
        // We can optionally reduce bottleneck bandwidth estimate slightly
        self.bottleneck_bw *= 0.95;
        self.pacing_rate = self.calculate_pacing_rate();
        debug!(
            "Loss detected, reduced bottleneck_bw to {:.2} Mbps, pacing to {:.2} Mbps",
            self.bottleneck_bw / 125_000.0,
            self.pacing_rate as f64 / 125_000.0
        );
    }

    fn reset(&mut self) {
        // Reset to initial state on timeout
        let now = Instant::now();
        self.cwnd = self.init_cwnd;
        self.mode = BbrMode::ProbeBw;
        self.bottleneck_bw = 125_000.0;
        self.pacing_rate = 125_000;
        self.bottleneck_bw_timeout = now + self.probe_rtt_interval;
        self.min_rtt_us = 1_000_000;
        self.min_rtt_timeout = now + self.probe_rtt_interval;
        self.probe_bw_state = 0;
        self.probe_bw_timer = now;
        self.probe_rtt_done_timestamp = None;
        self.probe_rtt_inflight_reached = false;
        info!("BBR flow reset");
    }
}

pub struct BbrAlgorithm;

impl GenericAlgorithm for BbrAlgorithm {
    fn name(&self) -> &str {
        "bbr"
    }

    fn create_flow(&self, init_cwnd: u32, mss: u32) -> Box<dyn GenericFlow> {
        Box::new(Bbr::new(init_cwnd, mss))
    }
}

// Legacy Portus-based implementation (DEPRECATED - kept for reference)
// This code is no longer used. BBR now uses the GenericRunner with the above GenericFlow impl.
/*
impl<T: Ipc> CongAlg<T> for BbrConfig {
    type Flow = Bbr<T>;

    fn name() -> &'static str {
        "bbr"
    }

    fn datapath_programs(&self) -> HashMap<&'static str, String> {
        vec![
            (
                "init_program",
                String::from(
                    "
                (def
                    (Report 
                        (volatile loss 0)
                        (minrtt +infinity)
                        (volatile rate 0) 
                        (pulseState 0)
                    )
                )
                (when true
                    (:= Report.loss (+ Report.loss Ack.lost_pkts_sample))
                    (:= Report.minrtt (min Report.minrtt Flow.rtt_sample_us))
                    (:= Report.rate (max Report.rate (min Flow.rate_outgoing Flow.rate_incoming)))
                    (:= Report.pulseState 5)
                    (fallthrough)
                )
                (when (> Micros Report.minrtt)
                    (report)
                )
            ",
                ),
            ),
            (
                "probe_rtt",
                String::from(
                    "
		(def 
		    (Report (volatile minrtt +infinity))
		    (volatile target_inflight_reached 0)
		)
		(when true
		    (:= Report.minrtt (min Report.minrtt Flow.rtt_sample_us))
		    (fallthrough)
		)
		(when (&& (== target_inflight_reached 0)
			  (|| (< Flow.packets_in_flight 4) (== Flow.packets_in_flight 4)))
		    (:= target_inflight_reached 1)
		    (:= Micros 0)
		)
		(when (&& (== target_inflight_reached 1) 
		          (&& (> Micros Flow.rtt_sample_us) (> Micros 200000))
                      )
                    (:= Micros 0)
		    (report)
		)
            ",
                ),
            ),
            (
                "probe_bw",
                String::from(
                    "
                (def
                    (Report 
                        (volatile loss 0)
                        (volatile minrtt +infinity)
                        (volatile rate 0) 
                        (pulseState 0)
                    )
                    (pulseState 0)
                    (cwndCap 0)
                    (bottleRate 0)
                    (threeFourthsRate 0)
                    (fiveFourthsRate 0)
                )
                (when true
                    (:= Report.loss (+ Report.loss Ack.lost_pkts_sample))
                    (:= Report.minrtt (min Report.minrtt Flow.rtt_sample_us))
                    (:= Report.pulseState pulseState)
                    (:= Report.rate (max Report.rate (min Flow.rate_outgoing Flow.rate_incoming)))
                    (fallthrough)
                )
                (when (&& (> Micros Report.minrtt) (== pulseState 0))
                    (:= Rate threeFourthsRate)
                    (:= pulseState 1)
                    (report)
                )
                (when (&& (> Micros (* Report.minrtt 2)) (== pulseState 1))
                    (:= Rate bottleRate)
                    (:= pulseState 2)
                    (report)
                )
                (when (&& (> Micros (* Report.minrtt 8)) (== pulseState 2))
                    (:= pulseState 0)
                    (:= Cwnd cwndCap)
                    (:= Rate fiveFourthsRate)
                    (:= Micros 0)
                    (report)
                )
	    ",
                ),
            ),
        ]
        .into_iter()
        .collect()
    }

    fn new_flow(&self, control: Datapath<T>, info: DatapathInfo) -> Self::Flow {
        let now = std::time::Instant::now();
        let mut s = Bbr {
            control_channel: control,
            sc: Scope::new(),
            probe_rtt_interval: self.probe_rtt_interval,
            bottle_rate: 125_000.0,
            bottle_rate_timeout: now + self.probe_rtt_interval,
            min_rtt_us: 1_000_000,
            min_rtt_timeout: now + self.probe_rtt_interval,
            curr_mode: BbrMode::ProbeBw,
            mss: info.mss,
            init: true,
            start: now,
        };

        s.sc = s
            .control_channel
            .set_program("init_program", Some(&[("Cwnd", info.init_cwnd)]))
            .unwrap();
        s
    }
}

impl<T: Ipc> portus::Flow for Bbr<T> {
    fn on_report(&mut self, _sock_id: u32, m: Report) {
        // if report is not for the current scope, please return
        if self.sc.program_uid != m.program_uid {
            return;
        }
        let now = std::time::Instant::now();
        match self.curr_mode {
            BbrMode::ProbeRtt => {
                self.min_rtt_us = self.get_probe_minrtt(&m);
                self.min_rtt_timeout = now + self.probe_rtt_interval;

                self.sc = self.install_probe_bw();
                self.curr_mode = BbrMode::ProbeBw;

                info!(min_rtt_us = self.min_rtt_us, "PROBE_RTT");
            }
            BbrMode::ProbeBw => {
                let fields = self.get_probe_bw_fields(&m);
                if fields.is_none() {
                    return;
                }

                let (_loss, minrtt, rate, _state) = fields.unwrap();
                let elapsed = now - self.start;
                info!(
                    elapsed_s = elapsed.as_secs_f32(),
                    rate_Mbps = rate / 125_000.0,
                    bottle_rate_Mbps = self.bottle_rate / 125_000.0,
                    "probe_bw"
                );

                // reset probe rtt counter and update cwnd cap
                if minrtt < self.min_rtt_us {
                    // datapath automatically uses minrtt for when condition (non volatile),
                    // this isn't reset, so no need to install again
                    self.min_rtt_us = minrtt;
                    self.min_rtt_timeout = now + self.probe_rtt_interval;
                    info!(
                        min_rtt_us = self.min_rtt_us,
                        bottle_rate_Mbps = self.bottle_rate / 125_000.0,
                        "new min_rtt"
                    );

                    if !(self.init) {
                        // probe bw program is installed
                        self.install_update(&[
                            (
                                "cwndCap",
                                (self.bottle_rate * 2.0 * f64::from(self.min_rtt_us) / 1e6) as u32,
                            ), // reinstall cwnd cap value
                        ]);
                    }
                }

                if now > self.min_rtt_timeout {
                    self.curr_mode = BbrMode::ProbeRtt;
                    info!(
                        min_rtt_us = self.min_rtt_us,
                        bottle_rate_Mbps = self.bottle_rate / 125_000.0,
                        "switching to PROBE_RTT"
                    );

                    self.min_rtt_us = 0x3fff_ffff;
                    self.sc = self.control_channel.set_program("probe_rtt", None).unwrap();
                    self.install_update(&[("Cwnd", (4 * self.mss) as u32)]);
                    return;
                }

                if self.bottle_rate < rate {
                    self.bottle_rate = rate;
                    self.bottle_rate_timeout = now + self.probe_rtt_interval;
                    // restart the pulse state
                    // here, we must reinstall the program for substitution with the correct values
                    if !(self.init) {
                        self.replace_probe_bw_rate();
                    }
                }

                if self.init {
                    info!("new_flow");
                    self.sc = self.install_probe_bw();
                    self.init = false;
                }
            }
        }
    }
}
*/
