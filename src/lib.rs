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
