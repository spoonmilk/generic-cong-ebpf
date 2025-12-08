//! Provides a runner for any algorithm

pub mod bbr;
pub mod cubic;
pub mod generic_runner;
pub mod reno;

use crate::bpf::DatapathEvent;
use anyhow::Result;

pub trait AlgorithmRunner: Send {
    fn name(&self) -> &str;
    fn ebpf_path(&self) -> &str;

    #[allow(dead_code)]
    fn struct_ops_name(&self) -> &str;

    fn handle_event(&mut self, event: DatapathEvent) -> Result<Option<CwndUpdate>>;

    fn cleanup(&mut self) {}
}

#[derive(Debug, Clone)]
pub struct CwndUpdate {
    pub flow_id: u64,
    pub cwnd_bytes: u32,
    pub pacing_rate: Option<u64>, // Optional pacing rate (bytes/sec)
}

pub struct AlgorithmRegistry;

impl AlgorithmRegistry {
    pub fn get(name: &str, init_cwnd_pkts: u32, mss: u32) -> Result<Box<dyn AlgorithmRunner>> {
        match name {
            "cubic" => Ok(Box::new(cubic::CubicRunner::new(init_cwnd_pkts, mss))),
            "reno" => Ok(Box::new(reno::RenoRunner::new(init_cwnd_pkts, mss))),
            "generic-cubic" => Ok(Box::new(generic_runner::GenericRunner::new(
                cubic::CubicAlgorithm,
                init_cwnd_pkts * mss, // Convert packets to bytes
                mss,
            ))),
            "generic-reno" => Ok(Box::new(generic_runner::GenericRunner::new(
                reno::RenoAlgorithm,
                init_cwnd_pkts * mss, // Convert packets to bytes
                mss,
            ))),
            "generic-bbr" => Ok(Box::new(generic_runner::GenericRunner::new(
                bbr::BbrAlgorithm,
                init_cwnd_pkts * mss, // Convert packets to bytes
                mss,
            ))),
            _ => anyhow::bail!("Unknown algorithm: {}", name),
        }
    }

    /// List all available algorithms
    pub fn list() -> Vec<&'static str> {
        vec![
            "cubic",
            "reno",
            "generic-cubic",
            "generic-reno",
            "generic-bbr",
        ]
    }
}
