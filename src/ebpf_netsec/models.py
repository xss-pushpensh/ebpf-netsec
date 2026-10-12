"""Data models for ebpf-netsec."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Union


@dataclass(slots=True)
class TcpConnectEvent:
    timestamp: datetime
    pid: int
    comm: str
    daddr: str
    dport: int

    @property
    def is_dns(self) -> bool:
        return self.dport == 53

    def to_dict(self) -> dict:
        return {
            "type": "tcp",
            "timestamp": self.timestamp.isoformat(),
            "pid": self.pid, "comm": self.comm,
            "daddr": self.daddr, "dport": self.dport,
        }


@dataclass(slots=True)
class DnsQueryEvent:
    timestamp: datetime
    pid: int
    comm: str
    server: str       # DNS server IP
    size: int         # query packet size in bytes

    def to_dict(self) -> dict:
        return {
            "type": "dns",
            "timestamp": self.timestamp.isoformat(),
            "pid": self.pid, "comm": self.comm,
            "server": self.server, "size": self.size,
        }


Event = Union[TcpConnectEvent, DnsQueryEvent]
