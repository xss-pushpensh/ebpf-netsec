from __future__ import annotations
import ctypes, socket, struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from bcc import BPF

TCP_EVENT_FMT = "IIIIIHHQ16s"

@dataclass(slots=True)
class TcpConnectEvent:
    pid: int
    uid: int
    saddr: str
    daddr: str
    sport: int
    dport: int
    ts_ns: int
    comm: str

    @property
    def timestamp(self) -> datetime:
        return datetime.fromtimestamp(self.ts_ns / 1e9, tz=timezone.utc)

def _u32_to_ip(addr: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", addr))

class TcpConnectSensor:
    def __init__(self, c_path: Path | str = "ebpf/tcp_connect.c"):
        c_path = Path(c_path)
        if not c_path.exists():
            raise FileNotFoundError(f"eBPF C file not found: {c_path}")
        self._bpf = BPF(src_file=str(c_path))
        self._ringbuf = self._bpf["events"]

    def poll(self, callback: Callable[[TcpConnectEvent], None]) -> None:
        def _handle(ctx, data, size):
            raw = ctypes.string_at(data, size)
            (pid, uid, saddr, daddr, sport, dport, ts_ns, comm_bytes) = struct.unpack(
                TCP_EVENT_FMT, raw
            )
            comm = comm_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace")
            callback(TcpConnectEvent(pid, uid, _u32_to_ip(saddr), _u32_to_ip(daddr),
                                     sport, dport, ts_ns, comm))
        self._ringbuf.open_ring_buffer(_handle)
        while True:
            try:
                self._bpf.ring_buffer_poll(timeout=200)
            except KeyboardInterrupt:
                break
