#!/usr/bin/env python3
"""
Mininet-based TCP Congestion Control Algorithm Testing Framework

Supports testing any algorithm available in net.ipv4.tcp_available_congestion_control,
including custom eBPF-based congestion control algorithms loaded via tcp_congestion_ops.

Usage:
    sudo python3 tcp_cong_test.py -a cubic reno my_ebpf_cc -d 21 81

Topology: Dumbbell network as described in NIST SP 500-282 Section 5.4
    s1------s2    s1 & s2 are backbone routers
     |       |
    s3      s4    s3 and s4 are access routers
    /\\      /\\
  h1  h3  h2  h4  h1/h3 are senders, h2/h4 are receivers
"""

import argparse
import csv
import json
from logging import config
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info, error
from mininet.clean import cleanup


@dataclass
class TestConfig:
    """Configuration for a single test run."""

    algorithm: str
    delay_ms: int
    iperf_runtime: int = 60
    iperf_delayed_start: int = 15
    output_dir: Path = field(default_factory=lambda: Path("./results"))
    sample_interval_ms: int = 100


@dataclass
class HostData:
    """Data collected for a single host."""

    time: list = field(default_factory=list)  # For cwnd samples
    cwnd: list = field(default_factory=list)
    throughput_mbps: list = field(default_factory=list)
    throughput_time: list = field(default_factory=list)
    rtt_ms: list = field(default_factory=list)
    retransmits: list = field(default_factory=list)


@dataclass
class TestResults:
    """Results from a test run."""

    algorithm: str
    delay_ms: int
    hosts: dict = field(default_factory=dict)

    def __post_init__(self):
        for host in ["h1", "h2", "h3", "h4"]:
            self.hosts[host] = HostData()


class DumbbellTopo(Topo):
    """
    Dumbbell topology for TCP congestion control testing.

    Based on NIST SP 500-282 Section 5.4 specification:
    - Backbone link: 984 Mbps with configurable delay
    - Access links: 252 Mbps
    - Host links: 960 Mbps
    - Queue sizes proportional to bandwidth-delay product
    """

    def build(self, delay_ms: int = 21):
        """
        Build the dumbbell topology.

        Args:
            delay_ms: One-way propagation delay for backbone link (RTT = 2 * delay_ms)
        """
        # Bandwidth in Mbps, delay in ms, queue sizes in packets (assuming 1500B MTU)
        # Backbone: 984 Mbps ~ 82 packets/ms
        backbone_params = {
            "bw": 984,
            "delay": f"{delay_ms}ms",
            "max_queue_size": int(82 * delay_ms),
            "use_htb": True,
        }

        # Access: 252 Mbps ~ 21 packets/ms, 20% BDP queue
        access_params = {
            "bw": 252,
            "delay": "0ms",
            "max_queue_size": max(1, int(21 * delay_ms * 0.2)),
            "use_htb": True,
        }

        # Host: 960 Mbps ~ 80 packets/ms
        host_params = {
            "bw": 960,
            "delay": "0ms",
            "max_queue_size": int(80 * delay_ms),
            "use_htb": True,
        }

        # Create switches (acting as routers)
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")

        # Backbone link
        self.addLink(s1, s2, cls=TCLink, **backbone_params)

        # Access links
        self.addLink(s1, s3, cls=TCLink, **access_params)
        self.addLink(s2, s4, cls=TCLink, **access_params)

        # Create hosts
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")

        # Host links - senders on s3, receivers on s4
        self.addLink(s3, h1, cls=TCLink, **host_params)
        self.addLink(s3, h3, cls=TCLink, **host_params)
        self.addLink(s4, h2, cls=TCLink, **host_params)
        self.addLink(s4, h4, cls=TCLink, **host_params)


class CwndMonitor:
    """Monitor TCP congestion window using ss with detailed debugging."""

    def __init__(self, output_file: Path, net, interval_ms: int = 100):
        self.output_file = output_file
        self.net = net
        self.interval_ms = interval_ms
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._data_lock = threading.Lock()
        self._raw_data = []
        self._sample_count = 0
        self._first_output_shown = False

    def start(self):
        """Start the monitoring thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the monitoring thread and save data."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        info(
            f"Collected {len(self._raw_data)} cwnd measurements from {self._sample_count} samples\n"
        )
        self._save_data()

    def _monitor_loop(self):
        """Main monitoring loop."""
        start_time = time.time()

        while not self._stop_event.is_set():
            timestamp = time.time() - start_time
            self._sample_count += 1

            # Query sender hosts
            for host_name in ["h1", "h3"]:
                try:
                    host = self.net.get(host_name)

                    # Try multiple ss command variants
                    commands = [
                        "ss -tino state established",
                        "ss -tin",
                        "ss -ti",
                    ]

                    for cmd in commands:
                        result = host.cmd(cmd)

                        # Show first successful output for debugging
                        if not self._first_output_shown and result and len(result) > 10:
                            info(f"\n=== First ss output from {host_name} ===\n")
                            info(f"Command: {cmd}\n")
                            info(result[:800] + "\n")
                            info("=== End ss output ===\n")
                            self._first_output_shown = True

                        # Try to parse
                        found = self._parse_ss_output(result, timestamp, host_name)
                        if found:
                            break

                    # Also try netstat as fallback
                    if self._sample_count == 1:
                        netstat_result = host.cmd("netstat -tn")
                        info(f"\n=== netstat output from {host_name} ===\n")
                        info(netstat_result[:500] + "\n")

                except Exception as e:
                    error(f"Error querying {host_name}: {e}\n")

            time.sleep(self.interval_ms / 1000.0)

    def _parse_ss_output(self, output: str, timestamp: float, host_name: str) -> bool:
        """Parse ss output for a specific host. Returns True if data found."""
        if not output:
            return False

        found_data = False
        lines = output.strip().split("\n")

        for i, line in enumerate(lines):
            # Look for connection indicators
            if not any(keyword in line for keyword in ["ESTAB", "tcp", "CONNECTED"]):
                continue

            # Collect full context
            full_text = line
            j = i + 1
            while j < len(lines) and lines[j] and lines[j][0] in [" ", "\t"]:
                full_text += " " + lines[j].strip()
                j += 1

            # Try to find cwnd anywhere in the text
            cwnd_match = re.search(r"cwnd:?(\d+)", full_text, re.IGNORECASE)
            rtt_match = re.search(
                r"rtt:?([\d.]+)[:/]?([\d.]+)?", full_text, re.IGNORECASE
            )

            if cwnd_match:
                cwnd = int(cwnd_match.group(1))
                rtt = float(rtt_match.group(1)) if rtt_match else 0.0

                # Extract addresses if possible
                parts = line.split()
                local = parts[3] if len(parts) > 3 else "unknown"
                remote = parts[4] if len(parts) > 4 else "unknown"

                with self._data_lock:
                    self._raw_data.append(
                        {
                            "timestamp": timestamp,
                            "host": host_name,
                            "local": local,
                            "remote": remote,
                            "cwnd": cwnd,
                            "rtt": rtt,
                            "retrans": 0,
                        }
                    )
                found_data = True

        return found_data

    def _save_data(self):
        """Save collected data to file."""
        with self._data_lock:
            if not self._raw_data:
                error("WARNING: No cwnd data collected!\n")

            with open(self.output_file, "w", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "timestamp",
                        "host",
                        "local",
                        "remote",
                        "cwnd",
                        "rtt",
                        "retrans",
                    ],
                )
                writer.writeheader()
                writer.writerows(self._raw_data)

    def get_data(self) -> dict:
        """Return collected data organized by host."""
        result = {
            "h1": HostData(),
            "h2": HostData(),
            "h3": HostData(),
            "h4": HostData(),
        }

        with self._data_lock:
            for entry in self._raw_data:
                host = entry["host"]
                if host in result:
                    result[host].time.append(entry["timestamp"])
                    result[host].cwnd.append(entry["cwnd"])
                    result[host].rtt_ms.append(entry["rtt"])
                    result[host].retransmits.append(entry["retrans"])

        return result


def get_available_algorithms() -> list:
    """Return list of available TCP congestion control algorithms."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip().split()
    except Exception:
        pass
    return ["cubic", "reno"]


def set_algorithm(host, algorithm: str) -> bool:
    """Set the TCP congestion control algorithm for a host."""
    result = host.cmd(f"sysctl -w net.ipv4.tcp_congestion_control={algorithm}")
    return "error" not in result.lower()


def run_iperf3_server(host, port: int = 5201) -> subprocess.Popen:
    """Start an iperf3 server on a host."""
    return host.popen(
        f"iperf3 -s -p {port}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_iperf3_client(
    host, server_ip: str, port: int, duration: int, algorithm: str, output_file: Path
) -> subprocess.Popen:
    """Start an iperf3 client on a host."""
    cmd = (
        f"iperf3 -c {server_ip} -p {port} -t {duration} "
        f"-C {algorithm} -J --logfile {output_file}"
    )
    return host.popen(cmd, shell=True)


def parse_iperf3_results(json_file: Path) -> HostData:
    """Parse iperf3 JSON output to extract throughput data."""
    data = HostData()

    try:
        with open(json_file, "r") as f:
            content = f.read()

        # iperf3 may write multiple JSON objects to the file
        # Split by "}\n{" and parse each separately, use the last valid one
        json_objects = []
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(content):
            content = content[idx:].lstrip()
            if not content:
                break
            try:
                obj, end_idx = decoder.raw_decode(content)
                json_objects.append(obj)
                idx += end_idx
            except json.JSONDecodeError:
                break

        # Use the last valid JSON object (typically the final summary)
        if json_objects:
            results = json_objects[-1]

            if "intervals" in results:
                for interval in results["intervals"]:
                    streams = interval.get("streams", [{}])
                    if streams:
                        stream = streams[0]
                        data.time.append(interval["sum"]["end"])
                        data.throughput_mbps.append(
                            interval["sum"]["bits_per_second"] / 1_000_000
                        )
                        data.retransmits.append(stream.get("retransmits", 0))
                        data.rtt_ms.append(stream.get("rtt", 0) / 1000)

    except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
        error(f"Error parsing iperf3 results from {json_file}: {e}\n")

    return data


def plot_cwnd(results: TestResults, output_dir: Path):
    """Generate congestion window vs time plot."""
    fig, ax = plt.subplots(figsize=(12, 6))

    for host in ["h1", "h3"]:
        data = results.hosts[host]
        if data.time and data.cwnd:
            ax.plot(data.time, data.cwnd, label=f"{host} (sender)", alpha=0.8)

    ax.set_xlabel("Time (seconds)")
    ax.set_ylabel("Congestion Window (segments)")
    ax.set_title(
        f"Congestion Window Evolution\n"
        f"Algorithm: {results.algorithm}, RTT: {results.delay_ms * 2}ms"
    )
    ax.legend()
    ax.grid(True, alpha=0.3)

    output_path = output_dir / f"cwnd_{results.algorithm}_{results.delay_ms}ms.png"
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    info(f"Saved cwnd plot: {output_path}\n")


def plot_throughput(results: TestResults, output_dir: Path):
    """Generate throughput vs time plot (fairness visualization)."""
    fig, ax = plt.subplots(figsize=(12, 6))

    for host in ["h1", "h3"]:
        data = results.hosts[host]

        # Check if throughput data exists
        if not data.throughput_mbps:
            continue

        # Use throughput_time if it exists, otherwise reconstruct from intervals
        if hasattr(data, "throughput_time") and data.throughput_time:
            time_data = data.throughput_time
        else:
            # Fallback: reconstruct assuming 1-second intervals
            time_data = list(range(1, len(data.throughput_mbps) + 1))

        ax.plot(time_data, data.throughput_mbps, label=f"{host} (sender)", alpha=0.8)

    ax.set_xlabel("Time (seconds)")
    ax.set_ylabel("Throughput (Mbps)")
    ax.set_title(
        f"TCP Fairness - Throughput Over Time\n"
        f"Algorithm: {results.algorithm}, RTT: {results.delay_ms * 2}ms"
    )
    ax.legend()
    ax.grid(True, alpha=0.3)

    output_path = (
        output_dir / f"throughput_{results.algorithm}_{results.delay_ms}ms.png"
    )
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    info(f"Saved throughput plot: {output_path}\n")


def plot_comparison(all_results: list, output_dir: Path):
    """Generate comparison plots across all tested algorithms."""
    if not all_results:
        return

    # Group by delay
    by_delay = {}
    for results in all_results:
        delay = results.delay_ms
        if delay not in by_delay:
            by_delay[delay] = []
        by_delay[delay].append(results)

    for delay, results_list in by_delay.items():
        fig, ax = plt.subplots(figsize=(12, 6))

        for results in results_list:
            data = results.hosts["h1"]

            # Check if throughput data exists
            if not data.throughput_mbps:
                continue

            # Use throughput_time if available, otherwise reconstruct
            if hasattr(data, "throughput_time") and data.throughput_time:
                time_data = data.throughput_time
            else:
                # Fallback: reconstruct assuming 1-second intervals
                time_data = list(range(1, len(data.throughput_mbps) + 1))

            ax.plot(time_data, data.throughput_mbps, label=results.algorithm, alpha=0.8)

        ax.set_xlabel("Time (seconds)")
        ax.set_ylabel("Throughput (Mbps)")
        ax.set_title(f"Algorithm Comparison - RTT: {delay * 2}ms")
        ax.legend()
        ax.grid(True, alpha=0.3)

        output_path = output_dir / f"comparison_{delay}ms.png"
        fig.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        info(f"Saved comparison plot: {output_path}\n")


def run_single_test(config: TestConfig) -> TestResults:
    """Run a single test with the specified configuration."""
    results = TestResults(algorithm=config.algorithm, delay_ms=config.delay_ms)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    # Verify algorithm is available
    available = get_available_algorithms()
    if config.algorithm not in available:
        error(f"Algorithm '{config.algorithm}' not available. Available: {available}\n")
        return results

    info(f"Starting test: algorithm={config.algorithm}, delay={config.delay_ms}ms\n")

    topo = DumbbellTopo(delay_ms=config.delay_ms)
    net = Mininet(topo=topo, link=TCLink, switch=OVSBridge, controller=None)

    monitor = None
    server_h2 = None
    server_h4 = None
    client_h1 = None
    client_h3 = None

    try:
        net.start()

        h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")
        host_ips = {"h1": h1.IP(), "h2": h2.IP(), "h3": h3.IP(), "h4": h4.IP()}
        info(f"Host IPs: {host_ips}\n")

        # Set congestion control on senders
        for host in [h1, h3]:
            if not set_algorithm(host, config.algorithm):
                error(f"Failed to set algorithm on {host.name}\n")

        # Start iperf3 servers
        info("Starting iperf3 servers...\n")
        server_h2 = run_iperf3_server(h2, 5201)
        server_h4 = run_iperf3_server(h4, 5202)
        time.sleep(2)

        # Start first client (h1 -> h2)
        info("Starting iperf3 client h1 -> h2...\n")
        iperf_h1_file = (
            config.output_dir / f"iperf_{config.algorithm}_h1_{config.delay_ms}ms.json"
        )
        client_h1 = run_iperf3_client(
            h1, h2.IP(), 5201, config.iperf_runtime, config.algorithm, iperf_h1_file
        )

        # Wait for TCP connection to establish
        info("Waiting for TCP connection to establish...\n")
        time.sleep(3)

        # Verify connection exists and start monitoring
        ss_output = h1.cmd("ss -tin")
        info(f"h1 connection check:\n{ss_output}\n")

        # Start cwnd monitoring AFTER connection is established
        cwnd_file = (
            config.output_dir / f"cwnd_{config.algorithm}_{config.delay_ms}ms.csv"
        )
        monitor = CwndMonitor(cwnd_file, net, config.sample_interval_ms)
        monitor.start()
        info("CWND monitoring started\n")

        # Delayed start for second client
        remaining_delay = (
            config.iperf_delayed_start - 3
        )  # Account for time already waited
        if remaining_delay > 0:
            info(f"Waiting {remaining_delay}s more before starting second client...\n")
            time.sleep(remaining_delay)

        # Start second client (h3 -> h4)
        info("Starting iperf3 client h3 -> h4...\n")
        iperf_h3_file = (
            config.output_dir / f"iperf_{config.algorithm}_h3_{config.delay_ms}ms.json"
        )
        client_h3 = run_iperf3_client(
            h3, h4.IP(), 5202, config.iperf_runtime, config.algorithm, iperf_h3_file
        )

        # Wait for completion
        info(f"Waiting for test completion ({config.iperf_runtime}s)...\n")
        if client_h1:
            client_h1.wait()
        if client_h3:
            client_h3.wait()

        # Stop monitoring
        if monitor:
            monitor.stop()

        # Terminate servers
        if server_h2:
            server_h2.terminate()
            server_h2.wait()
        if server_h4:
            server_h4.terminate()
            server_h4.wait()

        # Parse results
        if monitor:
            cwnd_data = monitor.get_data()
            results.hosts["h1"] = cwnd_data.get("h1", HostData())
            results.hosts["h3"] = cwnd_data.get("h3", HostData())

        iperf_h1_data = parse_iperf3_results(iperf_h1_file)
        iperf_h3_data = parse_iperf3_results(iperf_h3_file)

        results.hosts["h1"].throughput_mbps = iperf_h1_data.throughput_mbps
        results.hosts["h1"].throughput_time = (
            iperf_h1_data.time if iperf_h1_data.time else []
        )
        results.hosts["h3"].throughput_mbps = iperf_h3_data.throughput_mbps
        results.hosts["h3"].throughput_time = (
            [t + config.iperf_delayed_start for t in iperf_h3_data.time]
            if iperf_h3_data.time
            else []
        )

    except Exception as e:
        error(f"Test failed with error: {e}\n")
        import traceback

        traceback.print_exc()
    finally:
        info("Stopping network...\n")
        if monitor:
            monitor.stop()
        net.stop()

    return results


def run_tests(
    algorithms: list,
    delays: list,
    iperf_runtime: int = 60,
    iperf_delayed_start: int = 15,
    output_dir: str = "./results",
):
    """
    Run TCP congestion control tests for multiple algorithms and delays.

    Args:
        algorithms: List of algorithm names (must be in tcp_available_congestion_control)
        delays: List of one-way delays in milliseconds
        iperf_runtime: Duration of each iperf test in seconds
        iperf_delayed_start: Delay before starting second flow
        output_dir: Directory for output files
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    all_results = []

    info("Test configuration:\n")
    info(f"  Algorithms: {algorithms}\n")
    info(f"  Delays (one-way): {delays} ms\n")
    info(f"  iperf runtime: {iperf_runtime} s\n")
    info(f"  Delayed start: {iperf_delayed_start} s\n")
    info(f"  Output directory: {output_path}\n")

    for algorithm in algorithms:
        for delay in delays:
            config = TestConfig(
                algorithm=algorithm,
                delay_ms=delay,
                iperf_runtime=iperf_runtime,
                iperf_delayed_start=iperf_delayed_start,
                output_dir=output_path,
            )

            results = run_single_test(config)
            all_results.append(results)

            plot_cwnd(results, output_path)
            plot_throughput(results, output_path)

            cleanup()
            time.sleep(2)

    plot_comparison(all_results, output_path)

    return all_results


def connectivity_test(delay_ms: int = 21):
    """Run a basic connectivity test on the dumbbell topology."""
    info("Running connectivity test...\n")

    topo = DumbbellTopo(delay_ms=delay_ms)
    net = Mininet(topo=topo, link=TCLink, switch=OVSBridge, controller=None)

    try:
        net.start()
        info("Dumping host connections:\n")
        dumpNodeConnections(net.hosts)
        info("\nTesting network connectivity:\n")
        net.pingAll()

        h1, h2 = net.get("h1", "h2")
        info("\nTesting bandwidth h1 -> h2:\n")
        net.iperf(hosts=(h1, h2), seconds=10)
    finally:
        net.stop()


def main():
    parser = argparse.ArgumentParser(
        description="TCP Congestion Control Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -a cubic reno bbr -d 21 81
  %(prog)s -a cubic my_ebpf_cc -d 21 -t 30
  %(prog)s --list-algorithms
  %(prog)s --test-connectivity
        """,
    )

    parser.add_argument(
        "-a",
        "--algorithms",
        nargs="+",
        default=["cubic", "reno"],
        help="TCP congestion control algorithms to test",
    )
    parser.add_argument(
        "-d",
        "--delays",
        nargs="+",
        type=int,
        default=[21, 81, 162],
        help="One-way propagation delays in milliseconds",
    )
    parser.add_argument(
        "-t",
        "--runtime",
        type=int,
        default=60,
        help="iperf test duration in seconds (default: 60)",
    )
    parser.add_argument(
        "-s",
        "--delayed-start",
        type=int,
        default=15,
        help="Delay before starting second flow (default: 15)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="./results",
        help="Output directory (default: ./results)",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
    )
    parser.add_argument(
        "--test-connectivity", action="store_true", help="Run connectivity test only"
    )
    parser.add_argument(
        "--list-algorithms",
        action="store_true",
        help="List available congestion control algorithms",
    )

    args = parser.parse_args()
    setLogLevel(args.log_level)

    if args.list_algorithms:
        print("Available TCP congestion control algorithms:")
        for alg in get_available_algorithms():
            print(f"  {alg}")
        return 0

    if args.test_connectivity:
        connectivity_test()
        return 0

    run_tests(
        algorithms=args.algorithms,
        delays=args.delays,
        iperf_runtime=args.runtime,
        iperf_delayed_start=args.delayed_start,
        output_dir=args.output_dir,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
