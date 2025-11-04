mod bpf;
mod cubic;

use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

// Import from the lib target, not as a module
use ebpf_ccp_cubic::{GenericCongAvoidAlg, GenericCongAvoidFlow};

use bpf::{DatapathEvent, EbpfDatapath};
use cubic::Cubic;

#[derive(Parser)]
#[command(name = "ebpf-ccp-cubic")]
#[command(about = "CUBIC congestion control with eBPF datapath")]
struct Args {
    #[arg(long, default_value = "10")]
    init_cwnd_pkts: u32,

    #[arg(long, default_value = "1448")]
    mss: u32,

    #[arg(short, long)]
    verbose: bool,
}

struct FlowState {
    cubic: Cubic,
    mss: u32, // Store MSS per-flow
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_max_level(level.parse::<tracing::Level>().unwrap())
        .init();

    info!("Starting eBPF CUBIC congestion control");
    info!("  init_cwnd: {} packets", args.init_cwnd_pkts);
    info!("  mss: {} bytes", args.mss);

    // Load eBPF datapath
    let mut datapath = EbpfDatapath::new()?;
    info!("eBPF datapath loaded and attached");
    info!("TCP congestion control 'ebpf_cubic' is now available");

    // Create CUBIC algorithm instance (factory)
    let cubic_alg = Cubic::default();

    // Track active flows
    let mut flows: HashMap<u64, FlowState> = HashMap::new();

    info!("Entering event loop...");

    // Main event loop
    loop {
        let events = match datapath.poll(100) {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to poll datapath: {}", e);
                continue;
            }
        };

        for event in events {
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

                    let cubic = cubic_alg.new_flow(init_cwnd, mss);
                    flows.insert(flow_id, FlowState { cubic, mss });
                }

                DatapathEvent::FlowClosed { flow_id } => {
                    info!("Flow closed: {:016x}", flow_id);
                    flows.remove(&flow_id);
                    datapath.cleanup_flow(flow_id);
                }

                DatapathEvent::Measurement {
                    flow_id,
                    measurement,
                } => {
                    if let Some(flow) = flows.get_mut(&flow_id) {
                        // Handle timeout - reset CUBIC state
                        if measurement.was_timeout {
                            warn!("Timeout on flow {:016x} - resetting", flow_id);
                            flow.cubic.reset();
                            let fallback_cwnd =
                                flow.cubic.curr_cwnd().max(measurement.inflight * flow.mss);
                            flow.cubic.set_cwnd(fallback_cwnd);

                            if let Err(e) = datapath.update_cwnd(flow_id, flow.cubic.curr_cwnd()) {
                                error!("Failed to update cwnd: {}", e);
                            }
                            continue;
                        }

                        // Run CUBIC algorithm
                        let old_cwnd = flow.cubic.curr_cwnd();
                        if measurement.loss > 0 || measurement.sacked > 0 {
                            // Congestion detected - reduce
                            flow.cubic.reduction(&measurement);
                        } else if measurement.acked > 0 {
                            // ACK received - increase
                            flow.cubic.increase(&measurement);
                        }

                        let new_cwnd = flow.cubic.curr_cwnd();
                        if old_cwnd != new_cwnd {
                            debug!(
                                "Flow {:016x}: cwnd {} -> {} bytes",
                                flow_id, old_cwnd, new_cwnd
                            );
                        }

                        // Send cwnd update back to eBPF
                        if let Err(e) = datapath.update_cwnd(flow_id, flow.cubic.curr_cwnd()) {
                            error!("Failed to update cwnd for flow {:016x}: {}", flow_id, e);
                        }
                    } else {
                        warn!("Received measurement for unknown flow: {:016x}", flow_id);
                    }
                }
            }
        }
    }
}
