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
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use('Agg')
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
    output_dir: Path = field(default_factory=lambda: Path('./results'))
    sample_interval_ms: int = 100


@dataclass
class HostData:
    """Data collected for a single host."""
    time: list = field(default_factory=list)
    cwnd: list = field(default_factory=list)
    throughput_mbps: list = field(default_factory=list)
    rtt_ms: list = field(default_factory=list)
    retransmits: list = field(default_factory=list)


@dataclass
class TestResults:
    """Results from a test run."""
    algorithm: str
    delay_ms: int
    hosts: dict = field(default_factory=dict)

    def __post_init__(self):
        for host in ['h1', 'h2', 'h3', 'h4']:
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
            'bw': 984,
            'delay': f'{delay_ms}ms',
            'max_queue_size': int(82 * delay_ms),
            'use_htb': True
        }

        # Access: 252 Mbps ~ 21 packets/ms, 20% BDP queue
        access_params = {
            'bw': 252,
            'delay': '0ms',
            'max_queue_size': max(1, int(21 * delay_ms * 0.2)),
            'use_htb': True
        }

        # Host: 960 Mbps ~ 80 packets/ms
        host_params = {
            'bw': 960,
            'delay': '0ms',
            'max_queue_size': int(80 * delay_ms),
            'use_htb': True
        }

        # Create switches (acting as routers)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Backbone link
        self.addLink(s1, s2, cls=TCLink, **backbone_params)

        # Access links
        self.addLink(s1, s3, cls=TCLink, **access_params)
        self.addLink(s2, s4, cls=TCLink, **access_params)

        # Create hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Host links - senders on s3, receivers on s4
        self.addLink(s3, h1, cls=TCLink, **host_params)
        self.addLink(s3, h3, cls=TCLink, **host_params)
        self.addLink(s4, h2, cls=TCLink, **host_params)
        self.addLink(s4, h4, cls=TCLink, **host_params)


class CwndMonitor:
    """
    Monitor TCP congestion window using the ss command.

    Replaces the deprecated tcp_probe kernel module with a userspace
    solution that works with modern kernels and eBPF congestion control.
    """

    def __init__(self, output_file: Path, host_ips: dict, interval_ms: int = 100):
        self.output_file = output_file
        self.host_ips = host_ips
        self.interval_ms = interval_ms
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._data_lock = threading.Lock()
        self._raw_data = []

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
        self._save_data()

    def _monitor_loop(self):
        """Main monitoring loop using ss command."""
        start_time = time.time()

        while not self._stop_event.is_set():
            try:
                result = subprocess.run(
                    ['ss', '-tin'],
                    capture_output=True,
                    text=True,
                    timeout=1
                )

                timestamp = time.time() - start_time
                self._parse_ss_output(result.stdout, timestamp)

            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                error(f"CwndMonitor error: {e}\n")

            time.sleep(self.interval_ms / 1000.0)

    def _parse_ss_output(self, output: str, timestamp: float):
        """Parse ss output to extract cwnd and other TCP metrics."""
        lines = output.strip().split('\n')
        i = 0

        while i < len(lines):
            line = lines[i]

            # Look for ESTAB connections
            if 'ESTAB' not in line:
                i += 1
                continue

            parts = line.split()
            if len(parts) < 5:
                i += 1
                continue

            local = parts[3]
            remote = parts[4]

            # The TCP info is typically on the next line
            info_line = lines[i + 1] if i + 1 < len(lines) else ""

            # Parse metrics
            cwnd_match = re.search(r'cwnd:(\d+)', info_line)
            rtt_match = re.search(r'rtt:(\d+\.?\d*)/(\d+\.?\d*)', info_line)
            retrans_match = re.search(r'retrans:\d+/(\d+)', info_line)

            if cwnd_match:
                cwnd = int(cwnd_match.group(1))
                rtt = float(rtt_match.group(1)) if rtt_match else 0
                retrans = int(retrans_match.group(1)) if retrans_match else 0

                # Identify which host this belongs to
                for host, ip in self.host_ips.items():
                    if ip in local:
                        with self._data_lock:
                            self._raw_data.append({
                                'timestamp': timestamp,
                                'host': host,
                                'local': local,
                                'remote': remote,
                                'cwnd': cwnd,
                                'rtt': rtt,
                                'retrans': retrans
                            })
                        break

            i += 1

    def _save_data(self):
        """Save collected data to file."""
        with self._data_lock:
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'timestamp', 'host', 'local', 'remote', 'cwnd', 'rtt', 'retrans'
                ])
                writer.writeheader()
                writer.writerows(self._raw_data)

    def get_data(self) -> dict:
        """Return collected data organized by host."""
        result = {host: HostData() for host in self.host_ips.keys()}

        with self._data_lock:
            for entry in self._raw_data:
                host = entry['host']
                if host in result:
                    result[host].time.append(entry['timestamp'])
                    result[host].cwnd.append(entry['cwnd'])
                    result[host].rtt_ms.append(entry['rtt'])
                    result[host].retransmits.append(entry['retrans'])

        return result


def get_available_algorithms() -> list:
    """Return list of available TCP congestion control algorithms."""
    try:
        result = subprocess.run(
            ['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip().split()
    except Exception:
        pass
    return ['cubic', 'reno']


def set_algorithm(host, algorithm: str) -> bool:
    """Set the TCP congestion control algorithm for a host."""
    result = host.cmd(f'sysctl -w net.ipv4.tcp_congestion_control={algorithm}')
    return 'error' not in result.lower()


def run_iperf3_server(host, port: int = 5201) -> subprocess.Popen:
    """Start an iperf3 server on a host."""
    return host.popen(
        f'iperf3 -s -p {port}',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )


def run_iperf3_client(host, server_ip: str, port: int, duration: int,
                      algorithm: str, output_file: Path) -> subprocess.Popen:
    """Start an iperf3 client on a host."""
    cmd = (
        f'iperf3 -c {server_ip} -p {port} -t {duration} '
        f'-C {algorithm} -J --logfile {output_file}'
    )
    return host.popen(cmd, shell=True)


def parse_iperf3_results(json_file: Path) -> HostData:
    """Parse iperf3 JSON output to extract throughput data."""
    data = HostData()

    try:
        with open(json_file, 'r') as f:
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

            if 'intervals' in results:
                for interval in results['intervals']:
                    streams = interval.get('streams', [{}])
                    if streams:
                        stream = streams[0]
                        data.time.append(interval['sum']['end'])
                        data.throughput_mbps.append(
                            interval['sum']['bits_per_second'] / 1_000_000
                        )
                        data.retransmits.append(stream.get('retransmits', 0))
                        data.rtt_ms.append(stream.get('rtt', 0) / 1000)

    except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
        error(f"Error parsing iperf3 results from {json_file}: {e}\n")

    return data


def plot_cwnd(results: TestResults, output_dir: Path):
    """Generate congestion window vs time plot."""
    fig, ax = plt.subplots(figsize=(12, 6))

    for host in ['h1', 'h3']:
        data = results.hosts[host]
        if data.time and data.cwnd:
            ax.plot(data.time, data.cwnd, label=f'{host} (sender)', alpha=0.8)

    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Congestion Window (segments)')
    ax.set_title(
        f'Congestion Window Evolution\n'
        f'Algorithm: {results.algorithm}, RTT: {results.delay_ms * 2}ms'
    )
    ax.legend()
    ax.grid(True, alpha=0.3)

    output_path = output_dir / f'cwnd_{results.algorithm}_{results.delay_ms}ms.png'
    fig.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    info(f"Saved cwnd plot: {output_path}\n")


def plot_throughput(results: TestResults, output_dir: Path):
    """Generate throughput vs time plot (fairness visualization)."""
    fig, ax = plt.subplots(figsize=(12, 6))

    for host in ['h1', 'h3']:
        data = results.hosts[host]
        if data.time and data.throughput_mbps:
            ax.plot(data.time, data.throughput_mbps, label=f'{host} (sender)', alpha=0.8)

    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Throughput (Mbps)')
    ax.set_title(
        f'TCP Fairness - Throughput Over Time\n'
        f'Algorithm: {results.algorithm}, RTT: {results.delay_ms * 2}ms'
    )
    ax.legend()
    ax.grid(True, alpha=0.3)

    output_path = output_dir / f'throughput_{results.algorithm}_{results.delay_ms}ms.png'
    fig.savefig(output_path, dpi=150, bbox_inches='tight')
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
            data = results.hosts['h1']
            if data.time and data.throughput_mbps:
                ax.plot(
                    data.time, data.throughput_mbps,
                    label=results.algorithm, alpha=0.8
                )

        ax.set_xlabel('Time (seconds)')
        ax.set_ylabel('Throughput (Mbps)')
        ax.set_title(f'Algorithm Comparison - RTT: {delay * 2}ms')
        ax.legend()
        ax.grid(True, alpha=0.3)

        output_path = output_dir / f'comparison_{delay}ms.png'
        fig.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close(fig)


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

    try:
        net.start()

        h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
        host_ips = {'h1': h1.IP(), 'h2': h2.IP(), 'h3': h3.IP(), 'h4': h4.IP()}
        info(f"Host IPs: {host_ips}\n")

        # Set congestion control on senders
        for host in [h1, h3]:
            if not set_algorithm(host, config.algorithm):
                error(f"Failed to set algorithm on {host.name}\n")

        # Start cwnd monitoring
        cwnd_file = config.output_dir / f'cwnd_{config.algorithm}_{config.delay_ms}ms.csv'
        monitor = CwndMonitor(cwnd_file, host_ips, config.sample_interval_ms)
        monitor.start()

        # Start iperf3 servers
        info("Starting iperf3 servers...\n")
        server_h2 = run_iperf3_server(h2, 5201)
        server_h4 = run_iperf3_server(h4, 5202)
        time.sleep(1)

        # Start first client (h1 -> h2)
        info("Starting iperf3 client h1 -> h2...\n")
        iperf_h1_file = config.output_dir / f'iperf_{config.algorithm}_h1_{config.delay_ms}ms.json'
        client_h1 = run_iperf3_client(
            h1, h2.IP(), 5201, config.iperf_runtime, config.algorithm, iperf_h1_file
        )

        # Delayed start for second client
        info(f"Waiting {config.iperf_delayed_start}s before starting second client...\n")
        time.sleep(config.iperf_delayed_start)

        # Start second client (h3 -> h4)
        info("Starting iperf3 client h3 -> h4...\n")
        iperf_h3_file = config.output_dir / f'iperf_{config.algorithm}_h3_{config.delay_ms}ms.json'
        client_h3 = run_iperf3_client(
            h3, h4.IP(), 5202, config.iperf_runtime, config.algorithm, iperf_h3_file
        )

        # Wait for completion
        info(f"Waiting for test completion ({config.iperf_runtime}s)...\n")
        client_h1.wait()
        client_h3.wait()

        # Stop monitoring
        monitor.stop()

        # Terminate servers
        server_h2.terminate()
        server_h4.terminate()
        server_h2.wait()
        server_h4.wait()

        # Parse results
        cwnd_data = monitor.get_data()
        results.hosts['h1'] = cwnd_data.get('h1', HostData())
        results.hosts['h3'] = cwnd_data.get('h3', HostData())

        # Merge iperf3 throughput data
        iperf_h1_data = parse_iperf3_results(iperf_h1_file)
        iperf_h3_data = parse_iperf3_results(iperf_h3_file)

        results.hosts['h1'].throughput_mbps = iperf_h1_data.throughput_mbps
        if iperf_h1_data.time:
            results.hosts['h1'].time = iperf_h1_data.time

        results.hosts['h3'].throughput_mbps = iperf_h3_data.throughput_mbps
        if iperf_h3_data.time:
            results.hosts['h3'].time = [t + config.iperf_delayed_start for t in iperf_h3_data.time]

    finally:
        info("Stopping network...\n")
        net.stop()

    return results


def run_tests(algorithms: list, delays: list, iperf_runtime: int = 60,
              iperf_delayed_start: int = 15, output_dir: str = './results'):
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
                output_dir=output_path
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

        h1, h2 = net.get('h1', 'h2')
        info("\nTesting bandwidth h1 -> h2:\n")
        net.iperf(hosts=(h1, h2), seconds=10)
    finally:
        net.stop()


def main():
    parser = argparse.ArgumentParser(
        description='TCP Congestion Control Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -a cubic reno bbr -d 21 81
  %(prog)s -a cubic my_ebpf_cc -d 21 -t 30
  %(prog)s --list-algorithms
  %(prog)s --test-connectivity
        """
    )

    parser.add_argument('-a', '--algorithms', nargs='+', default=['cubic', 'reno'],
                        help='TCP congestion control algorithms to test')
    parser.add_argument('-d', '--delays', nargs='+', type=int, default=[21, 81, 162],
                        help='One-way propagation delays in milliseconds')
    parser.add_argument('-t', '--runtime', type=int, default=60,
                        help='iperf test duration in seconds (default: 60)')
    parser.add_argument('-s', '--delayed-start', type=int, default=15,
                        help='Delay before starting second flow (default: 15)')
    parser.add_argument('-o', '--output-dir', default='./results',
                        help='Output directory (default: ./results)')
    parser.add_argument('-l', '--log-level', default='info',
                        choices=['debug', 'info', 'warning', 'error'])
    parser.add_argument('--test-connectivity', action='store_true',
                        help='Run connectivity test only')
    parser.add_argument('--list-algorithms', action='store_true',
                        help='List available congestion control algorithms')

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
        output_dir=args.output_dir
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
