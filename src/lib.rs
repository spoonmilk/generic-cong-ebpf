//! Congestion control traits and types from ccp-project/generic-cong-avoid

pub const DEFAULT_SS_THRESH: u32 = 0x7fff_ffff;

/// Measurements available to congestion control algorithms
#[derive(Debug, Clone, Copy)]
pub struct GenericCongAvoidMeasurements {
    // In bytes
    pub acked: u32,
    pub was_timeout: bool,
    /// In packets
    pub sacked: u32,
    /// In packets
    pub loss: u32,
    /// In microseconds
    pub rtt: u32,
    /// In Packets
    pub inflight: u32,
}

pub trait GenericCongAvoidFlow {
    /// Get current congestion window in bytes
    fn curr_cwnd(&self) -> u32;

    /// Set congestion window in bytes
    fn set_cwnd(&mut self, cwnd: u32);

    /// Increase cwnd on successful ACK without loss
    fn increase(&mut self, m: &GenericCongAvoidMeasurements);

    /// Reduce cwnd on congestion signal
    fn reduction(&mut self, m: &GenericCongAvoidMeasurements);

    /// Reset algorithm state (on timeout)
    fn reset(&mut self) {}
}

pub trait GenericCongAvoidAlg {
    type Flow: GenericCongAvoidFlow;

    /// Create a new flow with given parameters
    fn new_flow(&self, init_cwnd: u32, mss: u32) -> Self::Flow;
}

/// Generic datapath functions

/// Flow key identifying a TCP connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub flow_key: FlowKey,

    // Flow-level statistics
    pub packets_in_flight: u32,
    pub bytes_in_flight: u32,
    pub bytes_pending: u32,
    pub rtt_sample_us: u32,
    pub was_timeout: bool,

    // ACK-level statistics
    pub bytes_acked: u32,
    pub packets_acked: u32,
    pub bytes_misordered: u32,
    pub packets_misordered: u32,
    pub ecn_bytes: u32,
    pub ecn_packets: u32,
    pub lost_pkts_sample: u32,

    // Rate statistics (from flow_rate_map)
    pub rate_incoming: u32,
    pub rate_outgoing: u32,

    // Kernel context
    pub snd_cwnd: u32,
    pub snd_ssthresh: u32,
    pub pacing_rate: u64,
    pub ca_state: u8,
    pub now: u64,
}

impl Report {
    /// Convert from eBPF measurement and optional flow rates
    pub fn from_measurement(
        flow_key: FlowKey,
        flow_stats: &FlowStatistics,
        ack_stats: &AckStatistics,
        snd_cwnd: u32,
        snd_ssthresh: u32,
        pacing_rate: u64,
        ca_state: u8,
        rates: Option<&FlowRates>,
    ) -> Self {
        todo!("Convert eBPF measurement + rates to Report")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowStatistics {
    pub packets_in_flight: u32,
    pub bytes_in_flight: u32,
    pub bytes_pending: u32,
    pub rtt_sample_us: u32,
    pub was_timeout: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct AckStatistics {
    pub bytes_acked: u32,
    pub packets_acked: u32,
    pub bytes_misordered: u32,
    pub packets_misordered: u32,
    pub ecn_bytes: u32,
    pub ecn_packets: u32,
    pub lost_pkts_sample: u32,
    pub now: u64,
}

/// Rate statistics computed by userspace
#[derive(Debug, Clone, Copy)]
pub struct FlowRates {
    pub rate_incoming: u32,
    pub rate_outgoing: u32,
    pub last_updated: u64,
}

// Update agent -> datapath
#[derive(Debug, Clone, Copy, Default)]
pub struct CwndUpdate {
    pub cwnd_bytes: Option<u32>,
    pub pacing_rate: Option<u64>,
    pub ssthresh: Option<u32>,
}

impl CwndUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cwnd(mut self, cwnd_bytes: u32) -> Self {
        self.cwnd_bytes = Some(cwnd_bytes);
        self
    }

    pub fn with_pacing_rate(mut self, pacing_rate: u64) -> Self {
        self.pacing_rate = Some(pacing_rate);
        self
    }

    pub fn with_ssthresh(mut self, ssthresh: u32) -> Self {
        self.ssthresh = Some(ssthresh);
        self
    }
}

/// Generic algorithm interface using Report instead of measurements
pub trait GenericAlgorithm {
    fn name(&self) -> &str;
    fn create_flow(&self, init_cwnd: u32, mss: u32) -> Box<dyn GenericFlow>;
}

/// Generic flow interface for algorithms using complete Report
pub trait GenericFlow {
    /// Handle ACK event
    fn on_ack(&mut self, report: &Report) -> CwndUpdate;

    /// Handle loss event
    fn on_loss(&mut self, report: &Report) -> CwndUpdate;

    /// Handle timeout event
    fn on_timeout(&mut self, report: &Report) -> CwndUpdate {
        // Default
        self.on_loss(report)
    }
}
