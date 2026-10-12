"""Spawn bpftrace and stream parsed TCP + DNS events."""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from ebpf_netsec.models import TcpConnectEvent, DnsQueryEvent, Event


TCP_RE = re.compile(
    r"^TCP\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<pid>\d+)\s+(?P<comm>\S+)\s+"
    r"(?P<daddr>\S+)\s+(?P<dport>\d+)\s*$"
)

DNS_RE = re.compile(
    r"^DNS\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<pid>\d+)\s+(?P<comm>\S+)\s+"
    r"(?P<server>\S+)\s+(?P<size>\d+)\s*$"
)


def _parse_time(hms: str) -> datetime:
    hh, mm, ss = hms.split(":")
    now = datetime.now(timezone.utc)
    return now.replace(hour=int(hh), minute=int(mm),
                       second=int(ss), microsecond=0)


class BpftraceRunner:
    """Runs a bpftrace script and yields parsed events."""

    def __init__(self, script_path: Path | str, verbose: bool = False):
        self.script_path = Path(script_path).resolve()
        if not self.script_path.exists():
            raise FileNotFoundError(f"Script not found: {self.script_path}")
        self.verbose = verbose
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        cmd = ["bpftrace", "-q", str(self.script_path)]
        if shutil.which("stdbuf"):
            cmd = ["stdbuf", "-oL", "-eL"] + cmd
        if self.verbose:
            print(f"[debug] Running: {' '.join(cmd)}")
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def events(self) -> Iterator[Event]:
        if not self._proc or not self._proc.stdout:
            raise RuntimeError("Call start() first")

        for raw_line in self._proc.stdout:
            line = raw_line.rstrip("\n")
            if self.verbose:
                print(f"[debug] RAW: {line!r}")

            m = TCP_RE.match(line)
            if m:
                yield TcpConnectEvent(
                    timestamp=_parse_time(m.group("time")),
                    pid=int(m.group("pid")),
                    comm=m.group("comm"),
                    daddr=m.group("daddr"),
                    dport=int(m.group("dport")),
                )
                continue

            m = DNS_RE.match(line)
            if m:
                yield DnsQueryEvent(
                    timestamp=_parse_time(m.group("time")),
                    pid=int(m.group("pid")),
                    comm=m.group("comm"),
                    server=m.group("server"),
                    size=int(m.group("size")),
                )
                continue
