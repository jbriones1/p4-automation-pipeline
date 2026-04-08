# Mininet Setup for `ethernet_ipv4_subduction`

Test environment for the P4 program compiled from `example.json` via `cna2p4.py`.

---

## Topology

```
  10.0.1.1/24             10.0.12.0/30              10.0.2.1/24
  h1 (MAC 00:00:00:00:01:01)                    h2 (MAC 00:00:00:00:02:01)
   |                                                  |
   | port 1                                    port 2 |
   +──────[  sw1  ]──────────────────────[  sw2  ]───+
          port 2 ↔ port 1      port 3 ↔ port 3
   |      10.0.12.1/30  10.0.12.2/30         |
   |                                          |
  h3 (10.1.1.1/24)               h4 (10.1.2.1/24)
  MAC 00:00:00:00:03:01          MAC 00:00:00:00:04:01
```

### What is being tested

| Path | CNA operator | P4 table |
|------|--------------|----------|
| h1 ↔ h2 | `layering` (eth1→ip1) | `fwd_ip1_tbl` |
| h3 ↔ h4 | `subduction` (ip1→gre1→ip2) | `fwd_ip2_tbl` |
| h1 → TCP port 80 on h2 | `session` (ip1.protocol=6 → tcp) | parser only |
| h3 → UDP inside GRE | `session` (ip2.protocol=17 → udp) | parser only |

---

## Prerequisites

```bash
# P4 toolchain
sudo apt install p4lang-p4c p4lang-bmv2

# Mininet
sudo apt install mininet python3-scapy

# Python dependencies
pip3 install scapy
```

---

## File layout

```
mininet_setup/
├── run.sh            # Master pipeline script (CNA→P4→BMV2→Mininet)
├── topo.py           # Mininet topology + BMV2 node wrapper + automated tests
├── table_setup.py    # Standalone table-entry pusher (useful with --topo-only)
└── test_traffic.py   # Scapy packet-level tests (run inside Mininet hosts)
```

Place these files alongside the project source (`cna2p4.py`, `example.json`, etc.).

---

## Quick Start

```bash
# Full pipeline: compile + run tests
sudo ./run.sh

# Skip compilation (reuse existing build/ artefacts)
sudo ./run.sh --no-compile

# Open Mininet CLI without running automated tests
sudo ./run.sh --topo-only
```

### Outputs

| Path | Contents |
|------|----------|
| `build/ethernet_ipv4_subduction.p4` | Generated P4 source |
| `build/ethernet_ipv4_subduction.json` | Compiled BMV2 JSON |
| `logs/p4c.log` | Compiler output |
| `logs/sw1.log` / `logs/sw2.log` | simple_switch runtime logs |
| `pcap/` | Per-interface packet captures |

---

## Manual table management

If you launched with `--topo-only`, push table entries separately:

```bash
python3 table_setup.py --sw1-port 9090 --sw2-port 9091
```

### Inspect tables interactively

```bash
simple_switch_CLI --thrift-port 9090
# P4 CLI> table_dump fwd_ip1_tbl
# P4 CLI> table_dump fwd_ip2_tbl
```

---

## Running Scapy tests from inside Mininet

```
mininet> h1 python3 test_traffic.py --iface h1-eth0 --test all
mininet> h1 python3 test_traffic.py --iface h1-eth0 --test gre_icmp
```

Individual tests:

| Test | `--test` flag | What it checks |
|------|--------------|----------------|
| Plain IPv4 ICMP | `ipv4_icmp` | Layering forwarding (eth1+ip1) |
| GRE tunnel ICMP | `gre_icmp` | Subduction (ip1→gre1→ip2) |
| TCP SYN forwarded | `tcp_session` | TCP session header parsed |
| UDP inside GRE | `udp_session` | UDP session header inside tunnel |

---

## Table entry reference

### sw1

| Table | Action | Match (LPM) | Params |
|-------|--------|-------------|--------|
| `fwd_ip1_tbl` | `ipv4_forward` | `10.0.2.0/24` | dst=`00:00:00:00:02:01` src=`00:00:00:aa:01:02` port=`2` |
| `fwd_ip1_tbl` | `drop` | `0.0.0.0/0` | — |
| `fwd_ip2_tbl` | `tunnel_forward` | `10.1.2.0/24` | outer_dst=`10.0.12.2` port=`2` |
| `fwd_ip2_tbl` | `tunnel_drop` | `0.0.0.0/0` | — |

### sw2

| Table | Action | Match (LPM) | Params |
|-------|--------|-------------|--------|
| `fwd_ip1_tbl` | `ipv4_forward` | `10.0.1.0/24` | dst=`00:00:00:00:01:01` src=`00:00:00:aa:02:01` port=`1` |
| `fwd_ip1_tbl` | `ipv4_forward` | `10.0.2.0/24` | dst=`00:00:00:00:02:01` src=`00:00:00:aa:02:02` port=`2` |
| `fwd_ip1_tbl` | `drop` | `0.0.0.0/0` | — |
| `fwd_ip2_tbl` | `tunnel_forward` | `10.1.1.0/24` | outer_dst=`10.0.12.1` port=`1` |
| `fwd_ip2_tbl` | `tunnel_drop` | `0.0.0.0/0` | — |

---

## Troubleshooting

**`simple_switch` not found**
```bash
sudo apt install p4lang-bmv2
# or build from source: github.com/p4lang/behavioral-model
```

**`p4c` compilation errors**
Check `logs/p4c.log`. The generated P4 targets BMV2 `v1model`. Ensure
`p4c --version` reports `>= 1.2`.

**Table entries rejected**
Action names must exactly match `forwarding_actions[].id` in `example.json`.
Run `table_dump <table>` in `simple_switch_CLI` to verify installed entries.

**Pings fail despite table entries**
Enable per-port pcap capture (already configured) and inspect:
```bash
tcpdump -r pcap/sw1-eth1.pcap
```
