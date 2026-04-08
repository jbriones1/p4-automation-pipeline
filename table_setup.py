#!/usr/bin/env python3
"""
table_setup.py  –  Push match-action entries to both BMV2 switches.

Run this after the topology is already running (e.g. when using --topo-only).

Usage:
    python3 table_setup.py [--sw1-port 9090] [--sw2-port 9091]

Table names are derived from cna2p4.py naming convention:
    fwd_{overlay_id}_tbl

For example.json the compiled tables are:
    fwd_ip1_tbl   –  layering overlay (IPv4 forwarding)
    fwd_ip2_tbl   –  subduction overlay (inner IPv4 over GRE)

Action names are taken verbatim from forwarding_actions[].id in example.json:
    ipv4_forward(dst_mac, src_mac, egress_port)
    drop()
    tunnel_forward(outer_dst, egress_port)
    tunnel_drop()
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time


# ── Table entry specifications ────────────────────────────────────────────────
#
# Format: (table, action, [match_keys], [action_params])
# match_keys  – list of match values as strings (one per key in CNA match_keys[])
# action_params – list of param values as strings (positional, per action params)
#
# fwd_ip1_tbl key : ip1.dst_addr  lpm
#   ipv4_forward params: dst_mac  src_mac  egress_port
#
# fwd_ip2_tbl key : ip2.dst_addr  lpm
#   tunnel_forward params: outer_dst  egress_port

SW1_ENTRIES = [
    # Destination              Action           Match keys     Action params
    ("fwd_ip1_tbl", "ipv4_forward", ["10.0.2.0/24"], ["00:00:00:00:02:01",
                                                       "00:00:00:aa:01:02",
                                                       "2"]),
    ("fwd_ip1_tbl", "drop",         ["0.0.0.0/0"],   []),
    ("fwd_ip2_tbl", "tunnel_forward",["10.1.2.0/24"],["10.0.12.2", "2"]),
    ("fwd_ip2_tbl", "tunnel_drop",  ["0.0.0.0/0"],   []),
]

SW2_ENTRIES = [
    ("fwd_ip1_tbl", "ipv4_forward", ["10.0.1.0/24"], ["00:00:00:00:01:01",
                                                       "00:00:00:aa:02:01",
                                                       "1"]),
    ("fwd_ip1_tbl", "ipv4_forward", ["10.0.2.0/24"], ["00:00:00:00:02:01",
                                                       "00:00:00:aa:02:02",
                                                       "2"]),
    ("fwd_ip1_tbl", "drop",         ["0.0.0.0/0"],   []),
    ("fwd_ip2_tbl", "tunnel_forward",["10.1.1.0/24"],["10.0.12.1", "1"]),
    ("fwd_ip2_tbl", "tunnel_drop",  ["0.0.0.0/0"],   []),
]


def entry_to_cli(table: str, action: str,
                 match_keys: list[str], params: list[str]) -> str:
    """Render one table_add command for simple_switch_CLI."""
    match_str  = " ".join(match_keys)
    param_str  = " ".join(params)
    sep = " => " if params else " =>"
    return f"table_add {table} {action} {match_str}{sep}{param_str}"


def push_entries(thrift_port: int,
                 entries: list[tuple[str, str, list[str], list[str]]],
                 label: str) -> bool:
    commands = "\n".join(entry_to_cli(*e) for e in entries)
    print(f"\n[{label}] Sending table entries (Thrift port {thrift_port}):")
    print("─" * 60)
    print(commands)
    print("─" * 60)

    for attempt in range(5):
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=commands,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        if "Error" not in output and result.returncode == 0:
            print(f"[{label}] ✓ All entries installed successfully.")
            return True
        print(f"[{label}] Attempt {attempt+1}/5 failed – retrying in 1 s…")
        print(output.strip())
        time.sleep(1)

    print(f"[{label}] ✗ Failed to install table entries.")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Push table entries to BMV2 simple_switch instances."
    )
    parser.add_argument("--sw1-port", type=int, default=9090)
    parser.add_argument("--sw2-port", type=int, default=9091)
    args = parser.parse_args()

    ok1 = push_entries(args.sw1_port, SW1_ENTRIES, "sw1")
    ok2 = push_entries(args.sw2_port, SW2_ENTRIES, "sw2")

    if ok1 and ok2:
        print("\n✓ Table setup complete for both switches.")
    else:
        print("\n✗ One or more switches failed. Check that simple_switch is running.")
        sys.exit(1)


if __name__ == "__main__":
    main()
