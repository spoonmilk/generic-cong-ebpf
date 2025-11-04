//! Minimal Generic Congestion Avoidance traits and types

pub const DEFAULT_SS_THRESH: u32 = 0x7fff_ffff;

/// Measurements available to congestion control algorithms
#[derive(Debug, Clone, Copy)]
pub struct GenericCongAvoidMeasurements {
    /// Bytes acknowledged
    pub acked: u32,
    /// Whether this is a timeout event
    pub was_timeout: bool,
    /// Packets selectively acknowledged (out-of-order)
    pub sacked: u32,
    /// Packets lost
    pub loss: u32,
    /// Round-trip time in microseconds
    pub rtt: u32,
    /// Packets currently in flight
    pub inflight: u32,
}

/// Trait for per-flow congestion control state
pub trait GenericCongAvoidFlow {
    /// Get current congestion window in bytes
    fn curr_cwnd(&self) -> u32;

    /// Set congestion window in bytes (called by framework)
    fn set_cwnd(&mut self, cwnd: u32);

    /// Increase cwnd on successful ACK without loss
    fn increase(&mut self, m: &GenericCongAvoidMeasurements);

    /// Reduce cwnd on congestion signal
    fn reduction(&mut self, m: &GenericCongAvoidMeasurements);

    /// Reset algorithm state (on timeout)
    fn reset(&mut self) {}
}

/// Trait for congestion control algorithm (factory for flows)
pub trait GenericCongAvoidAlg {
    type Flow: GenericCongAvoidFlow;

    /// Create a new flow with given parameters
    fn new_flow(&self, init_cwnd: u32, mss: u32) -> Self::Flow;
}
