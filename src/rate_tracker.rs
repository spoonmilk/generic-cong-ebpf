use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateTracker {
    flow_rates: HashMap<FlowKey, FlowRateState>,
    update_interval: Duration, // e.g., 100ms
    last_update: Instant,
}

struct FlowRateState {
    // Cached counters from last update
    last_bytes_delivered: u64,
    last_bytes_sent: u64,
    last_timestamp: Instant,

    // Computed rates -> write to flow_rate_map
    current_rate_incoming: u32, // bytes/sec
    current_rate_outgoing: u32, // bytes/sec
}

impl RateTracker {
    pub fn new(update_interval: Duration) -> Self {
        Self {
            flow_rates: HashMap::new(),
            update_interval,
            last_update: Instant::now(),
        }
    }

    pub fn update_rates(&mut self, flow_map: &libbpf_rs::Map, rate_map: &libbpf_rs::Map) {
        let now = Instant::now();
        if !(now - self.last_update < self.update_interval) {
            return;
        }

        for flow in self.flow_rates.values_mut() {
            let bytes_delivered_since_last = flow.last_bytes_delivered;
            let bytes_sent_since_last = flow.last_bytes_sent;
            let delta_bytes = bytes_sent_since_last - bytes_delivered_since_last;

            let elapsed_ns = flow.last_timestamp - (now * 1e9);

            let rate = (delta_bytes * 1e9) / elapsed_ns;
            todo!()
        }
    }

    pub fn add_flow(&mut self, flow_key: FlowKey, initial_state: FlowState) {
        todo!();
    }

    pub fn remove_flow(&mut self, flow_key: &FlowKey) {
        todo!();
    }
}
