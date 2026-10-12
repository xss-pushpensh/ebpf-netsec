# 🛡️ ebpf-netsec

**Kernel-level network security observability with eBPF.**

Captures every outbound TCP connection and DNS query system-wide with full
process context, detects C2 beaconing and DNS tunneling in real time, and
streams alerts to a live web dashboard and Discord.

![status](https://img.shields.io/badge/status-active-brightgreen)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![platform](https://img.shields.io/badge/platform-Linux-lightgrey)

---

## Why this exists

Userspace packet sniffers (tcpdump, Wireshark) can tell you *what* packets
crossed the wire — but not *which process* sent them. On encrypted traffic,
they see almost nothing useful.

`ebpf-netsec` hooks the Linux kernel directly via eBPF, so it sees every
outbound connection **at the moment the process makes it**, with the PID,
process name, destination IP, and port — no packet capture, no TLS decryption,
no missing context.

Then it applies statistical detectors:

- **Beaconing detection** — finds C2 "phone-home" patterns
- **DNS tunneling detection** — finds data exfiltration encoded in DNS queries

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     KERNEL SPACE (eBPF)                          │
│                                                                  │
│  tracepoint:syscalls:sys_enter_connect   → TCP connect events    │
│  kprobe:udp_sendmsg  (port 53 filter)    → DNS query events      │
└──────────────────────────────────────────────────────────────────┘
                             │
                    bpftrace (-q, line-buffered)
                             │
┌──────────────────────────────────────────────────────────────────┐
│                    USER SPACE (Python)                           │
│                                                                  │
│  BpftraceRunner ──► parser ──► TcpConnectEvent | DnsQueryEvent   │
│                          │                                       │
│                          ├──► EventDB (SQLite, WAL)              │
│                          ├──► Detection engine (every 15s)       │
│                          └──► FastAPI + WebSocket                │
│                                   • Live dashboard               │
│                                   • Discord webhook alerts       │
└──────────────────────────────────────────────────────────────────┘
```

---

## Features

- ✅ Kernel-level TCP capture with process context (PID + comm)
- ✅ Kernel-level DNS visibility
- ✅ SQLite persistence with WAL mode
- ✅ Beaconing detector (statistical)
- ✅ DNS tunnel detector (heuristic)
- ✅ Live web dashboard (FastAPI + WebSocket)
- ✅ Discord alerts (rich embeds)
- ✅ CLI: sniff, detect, dashboard, history, seed-demo
- ✅ pytest test suite
- ✅ Docker Compose deployment

---

## Screenshots

![dashboard](docs/dashboard.png)

![discord](docs/discord-alert.png)

---

## Requirements

| | |
|---|---|
| **OS** | Linux kernel **5.8+** (Kali, Ubuntu, Debian, Fedora) |
| **Python** | 3.10+ |
| **Packages** | `bpftrace`, `bpfcc-tools`, `linux-headers-$(uname -r)` |
| **Privileges** | root or `CAP_BPF` |

---

## Quick Start

```bash
sudo apt update
sudo apt install -y build-essential bpftrace bpfcc-tools \
    linux-headers-amd64 python3-pip python3-venv

git clone https://github.com/XSS.PUSHPENSH/ebpf-netsec.git
cd ebpf-netsec
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
sudo -E env PATH="$PATH" DISCORD_WEBHOOK_URL="$DISCORD_WEBHOOK_URL" \
    ./venv/bin/ebpf-netsec dashboard
```

Open **http://127.0.0.1:8080**.

---

## CLI Commands

```bash
ebpf-netsec sniff           # live TCP + DNS tables
ebpf-netsec detect          # live detection with alerts
ebpf-netsec dashboard       # web UI + Discord alerts
ebpf-netsec history --events --dns --beacons --tunnels
ebpf-netsec seed-demo       # insert synthetic beacon + tunnel
```

---

## Detection Logic

### Beaconing

Groups events by (process, destination, port) over a sliding window,
computes inter-arrival mean and standard deviation, flags flows where:

- count >= 5
- stddev / mean <= 0.5
- Mean interval between 0.5s and 3600s

Score = 10 × min(count/20, 1) × (1 − jitter).

### DNS Tunneling

Groups DNS queries by (process, server), flags flows where:

- Mean packet size >= 150 bytes OR count >= 30
- Minimum of 5 queries

Score = 10 × (0.7 × size_score + 0.3 × volume_score).

---

## Deployment

### Docker

```bash
export DISCORD_WEBHOOK_URL="..."
docker compose up --build
```

### systemd (bare-metal)

See docs/systemd.md (coming soon).

---

## Project Structure

```
ebpf-netsec/
├── ebpf/tcpconnect.bt             # bpftrace probes
├── src/ebpf_netsec/
│   ├── models.py                  # events
│   ├── cli.py                     # CLI
│   ├── sensors/bpftrace_runner.py # subprocess + parser
│   ├── storage/db.py              # SQLite (WAL)
│   ├── detect/
│   │   ├── beaconing.py
│   │   └── dns_tunnel.py
│   ├── api/dashboard.py           # FastAPI + WebSocket + HTML
│   └── notify/discord.py          # rich embeds
├── tests/                         # pytest
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── pyproject.toml
```

---

## Security Notes

- Only run against systems you own or have written authorization to test.
- The Discord webhook URL is a secret — never commit it.
- Dashboard binds to 127.0.0.1 by default.
- The SQLite DB contains traffic metadata — treat as sensitive.

---

## Roadmap

- [x] TCP + DNS sensor via eBPF
- [x] SQLite persistence
- [x] Beaconing + DNS tunnel detection
- [x] Web dashboard
- [x] Discord alerts
- [ ] TLS SNI extraction (uprobe)
- [ ] Container attribution (cgroup v2)
- [ ] MITRE ATT&CK tagging
- [ ] Prometheus metrics

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Nishant** — cybersecurity / network security.
Built on Kali Linux as a deep dive into eBPF and Linux observability.
