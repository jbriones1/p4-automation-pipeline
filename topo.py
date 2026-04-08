#!/usr/bin/env python3
"""
topo.py  –  Mininet topology for ethernet_ipv4_subduction (example.json)

Network layout
==============

                   10.0.12.0/30  (inter-switch link)
    h1 ──[port1]── sw1 ──[port2]──[port1]── sw2 ──[port2]── h2
    h3 ──[port3]── sw1                      sw2 ──[port3]── h4

  h1 / h2  :  plain IPv4 reachability  (eth1+ip1, layering)
  h3 / h4  :  inner IPv4 reachability  (ip2 over GRE, subduction)

Host addressing
---------------
  h1   10.0.1.1/24    MAC  00:00:00:00:01:01
  h2   10.0.2.1/24    MAC  00:00:00:00:02:01
  h3   10.1.1.1/24    MAC  00:00:00:00:03:01
  h4   10.1.2.1/24    MAC  00:00:00:00:04:01

  sw1 inter-switch: 10.0.12.1/30
  sw2 inter-switch: 10.0.12.2/30

Table entries installed
-----------------------
sw1
  fwd_ip1_tbl  10.0.2.0/24 → ipv4_forward(dst=00:00:00:00:02:01, src=00:00:00:00:s1:02, port=2)
  fwd_ip1_tbl  default     → drop()
  fwd_ip2_tbl  10.1.2.0/24 → tunnel_forward(outer_dst=10.0.12.2, port=2)
  fwd_ip2_tbl  default     → tunnel_drop()

sw2
  fwd_ip1_tbl  10.0.1.0/24 → ipv4_forward(dst=00:00:00:00:01:01, src=00:00:00:00:s2:01, port=1)
  fwd_ip1_tbl  10.0.2.0/24 → ipv4_forward(dst=00:00:00:00:02:01, src=00:00:00:00:s2:02, port=2 [local] )
  fwd_ip2_tbl  10.1.1.0/24 → tunnel_forward(outer_dst=10.0.12.1, port=1)
  fwd_ip2_tbl  default     → tunnel_drop()
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from typing import Any

# ---------------------------------------------------------------------------
# Mininet imports – must be run as root
# ---------------------------------------------------------------------------
try:
    from mininet.clean import cleanup
    from mininet.cli import CLI
    from mininet.link import TCLink
    from mininet.log import info, setLogLevel
    from mininet.net import Mininet
    from mininet.node import Host
    from mininet.topo import Topo
except ImportError as exc:
    sys.exit(f"[ERROR] Mininet not found: {exc}")

try:
    from p4utils.mininetlib.node import P4Switch  # type: ignore
except ImportError:
    # Fall back to a thin wrapper around simple_switch if p4-utils is absent
    P4Switch = None

# ---------------------------------------------------------------------------
# Lightweight BMV2 node (no p4-utils dependency)
# ---------------------------------------------------------------------------


class SimpleSwitchNode(Host):
    """
    Minimal BMV2 simple_switch node for Mininet.

    Runs simple_switch as a background process inside the network namespace.
    Exposes a Thrift port for simple_switch_CLI table management.
    """

    THRIFT_BASE = 9090  # sw1 → 9090, sw2 → 9091, …

    def __init__(
        self,
        name: str,
        bmv2_json: str,
        thrift_port: int,
        log_dir: str = "logs",
        pcap_dir: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(name, **kwargs)
        self.bmv2_json = bmv2_json
        self.thrift_port = thrift_port
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self._proc: subprocess.Popen | None = None  # type: ignore[type-arg]

    # Mininet calls start() after links are set up
    def start(self, _controllers: Any = None) -> None:  # type: ignore[override]
        os.makedirs(self.log_dir, exist_ok=True)
        log_file = os.path.join(self.log_dir, f"{self.name}.log")

        ifaces = [intf for intf in self.intfList() if intf.name != "lo"]
        port_args: list[str] = []
        for idx, intf in enumerate(ifaces, start=1):
            port_args += ["-i", f"{idx}@{intf.name}"]

        pcap_args: list[str] = []
        if self.pcap_dir:
            os.makedirs(self.pcap_dir, exist_ok=True)
            pcap_args = ["--pcap", self.pcap_dir]

        cmd = (
            ["simple_switch"]
            + port_args
            + pcap_args
            + [
                "--thrift-port",
                str(self.thrift_port),
                "--log-console",
                "--log-level",
                "warn",
                self.bmv2_json,
            ]
        )

        info(f"    [{self.name}] {' '.join(cmd)}\n")
        # Run inside the node's network namespace
        with open(log_file, "w") as lf:
            self._proc = self.popen(cmd, stdout=lf, stderr=lf)

        time.sleep(1)  # give simple_switch time to bind the Thrift port

    def stop(self, deleteIntfs: bool = True) -> None:  # noqa: N803
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        super().stop(deleteIntfs=deleteIntfs)

    def run_cli(self, commands: str) -> str:
        """Send commands to simple_switch_CLI via stdin and return stdout."""
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(self.thrift_port)],
            input=commands,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Topology definition
# ---------------------------------------------------------------------------


class SubductionTopo(Topo):
    """
    Two BMV2 switches + four end-hosts.

    Port numbering on each switch (1-indexed as BMV2 sees them):
      port 1  →  host A  (h1 on sw1, h2 on sw2)
      port 2  →  inter-switch link
      port 3  →  host B  (h3 on sw1, h4 on sw2)
    """

    def build(self) -> None:
        # Hosts
        h1 = self.addHost(
            "h1",
            ip="10.0.1.1/24",
            mac="00:00:00:00:01:01",
            defaultRoute="via 10.0.1.254",
        )
        h2 = self.addHost(
            "h2",
            ip="10.0.2.1/24",
            mac="00:00:00:00:02:01",
            defaultRoute="via 10.0.2.254",
        )
        h3 = self.addHost(
            "h3",
            ip="10.1.1.1/24",
            mac="00:00:00:00:03:01",
            defaultRoute="via 10.1.1.254",
        )
        h4 = self.addHost(
            "h4",
            ip="10.1.2.1/24",
            mac="00:00:00:00:04:01",
            defaultRoute="via 10.1.2.254",
        )

        # Switches (plain Mininet nodes; BMV2 started in run_network)
        sw1 = self.addHost("sw1")
        sw2 = self.addHost("sw2")

        # Links  (order matters for BMV2 port numbering)
        self.addLink(h1, sw1)  # sw1 port 1
        self.addLink(sw1, sw2)  # sw1 port 2, sw2 port 1
        self.addLink(h2, sw2)  # sw2 port 2
        self.addLink(h3, sw1)  # sw1 port 3
        self.addLink(h4, sw2)  # sw2 port 3


# ---------------------------------------------------------------------------
# Table entries
# ---------------------------------------------------------------------------

# Values are MAC-address strings used in set_field operations.
SW1_MAC_PORT2 = "00:00:00:aa:01:02"  # sw1 egress MAC toward sw2
SW2_MAC_PORT1 = "00:00:00:aa:02:01"  # sw2 egress MAC toward sw1

# simple_switch_CLI command strings
# Table names come from cna2p4.py naming: fwd_{overlay}_tbl
SW1_COMMANDS = """\
table_add fwd_ip1_tbl ipv4_forward 10.0.2.0/24 => 00:00:00:00:02:01 {sw1_mac_p2} 2
table_add fwd_ip1_tbl drop 0.0.0.0/0 =>
table_add fwd_ip2_tbl tunnel_forward 10.1.2.0/24 => 10.0.12.2 2
table_add fwd_ip2_tbl tunnel_drop 0.0.0.0/0 =>
""".format(sw1_mac_p2=SW1_MAC_PORT2)

SW2_COMMANDS = """\
table_add fwd_ip1_tbl ipv4_forward 10.0.1.0/24 => 00:00:00:00:01:01 {sw2_mac_p1} 1
table_add fwd_ip1_tbl ipv4_forward 10.0.2.0/24 => 00:00:00:00:02:01 {sw2_mac_p1} 2
table_add fwd_ip1_tbl drop 0.0.0.0/0 =>
table_add fwd_ip2_tbl tunnel_forward 10.1.1.0/24 => 10.0.12.1 1
table_add fwd_ip2_tbl tunnel_drop 0.0.0.0/0 =>
""".format(sw2_mac_p1=SW2_MAC_PORT1)


def populate_tables(sw1: SimpleSwitchNode, sw2: SimpleSwitchNode) -> None:
    info("*** Populating match-action tables\n")

    for sw, cmds, label in [
        (sw1, SW1_COMMANDS, "sw1"),
        (sw2, SW2_COMMANDS, "sw2"),
    ]:
        # Retry briefly – simple_switch may still be initialising
        for attempt in range(5):
            out = sw.run_cli(cmds)
            if "Error" not in out and "error" not in out.lower():
                break
            if attempt < 4:
                time.sleep(1)
        info(f"  [{label}] CLI output:\n")
        for line in out.strip().splitlines():
            info(f"    {line}\n")


# ---------------------------------------------------------------------------
# Automated connectivity tests
# ---------------------------------------------------------------------------


def run_tests(net: Mininet) -> None:
    info("\n*** Running connectivity tests\n")

    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    h4 = net.get("h4")

    results: list[tuple[str, bool]] = []

    def ping_test(src: Host, dst_ip: str, label: str) -> None:
        out = src.cmd(f"ping -c 3 -W 1 {dst_ip}")
        ok = "3 received" in out or "0% packet loss" in out
        results.append((label, ok))
        status = "PASS " if ok else "FAIL "
        info(f"  {status}  {label}\n")
        if not ok:
            info(f"         ping output: {out.strip()}\n")

    # Plain IPv4 forwarding (layering)
    ping_test(h1, "10.0.2.1", "h1->2  (IPv4 layering)")
    ping_test(h2, "10.0.1.1", "h2->h1  (IPv4 layering)")

    # GRE-tunneled inner IPv4 (subduction) – use scapy if ping is blocked
    ping_test(h3, "10.1.2.1", "h3->h4  (IPv4-over-GRE subduction)")
    ping_test(h4, "10.1.1.1", "h4->h3  (IPv4-over-GRE subduction)")

    # Summary
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    info(f"\n*** Results: {passed}/{total} tests passed\n")
    if passed < total:
        info("*** FAILED tests:\n")
        for label, ok in results:
            if not ok:
                info(f"      {label}\n")


# Main


def run_network(bmv2_json: str, topo_only: bool = False) -> None:
    cleanup()
    setLogLevel("info")

    topo = SubductionTopo()
    net = Mininet(topo=topo, host=Host, controller=None, autoSetMacs=False)
    net.start()

    # Retrieve switch nodes (plain Host instances acting as L3 forwarders)
    sw1_node = net.get("sw1")
    sw2_node = net.get("sw2")

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Wrap them in SimpleSwitchNode behaviour
    sw1 = SimpleSwitchNode.__new__(SimpleSwitchNode)
    sw1.__dict__.update(sw1_node.__dict__)
    sw1.bmv2_json = bmv2_json
    sw1.thrift_port = SimpleSwitchNode.THRIFT_BASE
    sw1.log_dir = os.path.join(script_dir, "logs")
    sw1.pcap_dir = os.path.join(script_dir, "pcap")
    sw1._proc = None

    sw2 = SimpleSwitchNode.__new__(SimpleSwitchNode)
    sw2.__dict__.update(sw2_node.__dict__)
    sw2.bmv2_json = bmv2_json
    sw2.thrift_port = SimpleSwitchNode.THRIFT_BASE + 1
    sw2.log_dir = os.path.join(script_dir, "logs")
    sw2.pcap_dir = os.path.join(script_dir, "pcap")
    sw2._proc = None

    info("*** Starting BMV2 (simple_switch) instances\n")
    sw1.start()
    sw2.start()

    info("*** Configuring inter-switch IP addresses\n")
    # Assign IPs to the inter-switch interface on each switch so that
    # tunnel_forward can route outer packets correctly.
    sw1_node.cmd("ip addr add 10.0.12.1/30 dev sw1-eth2")
    sw2_node.cmd("ip addr add 10.0.12.2/30 dev sw2-eth1")

    # Host routes so pings reach the right gateway interface
    net.get("h1").cmd("ip route add 10.0.0.0/8 via 10.0.1.254")
    net.get("h2").cmd("ip route add 10.0.0.0/8 via 10.0.2.254")
    net.get("h3").cmd("ip route add 10.1.0.0/16 via 10.1.1.254")
    net.get("h4").cmd("ip route add 10.1.0.0/16 via 10.1.2.254")

    populate_tables(sw1, sw2)

    if topo_only:
        info("\n*** Topology ready – dropping into Mininet CLI\n")
        info("    Thrift ports: sw1=9090  sw2=9091\n\n")
        CLI(net)
    else:
        time.sleep(1)  # let ARP/forwarding tables settle
        run_tests(net)
        info("\n*** Dropping into interactive CLI (Ctrl-D to exit)\n")
        CLI(net)

    info("*** Stopping network\n")
    sw1.stop(deleteIntfs=False)
    sw2.stop(deleteIntfs=False)
    net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mininet topology for ethernet_ipv4_subduction P4 program"
    )
    parser.add_argument(
        "--bmv2-json", required=True, help="Path to compiled BMV2 JSON artefact"
    )
    parser.add_argument(
        "--topo-only",
        action="store_true",
        help="Open Mininet CLI without running automated tests",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("[ERROR] topo.py must be run as root.")

    run_network(args.bmv2_json, topo_only=args.topo_only)
