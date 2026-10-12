"""DNS tunnel detection via query size and volume heuristics.

DNS tunneling exfiltrates data by encoding it in subdomain labels.
The result: abnormally large DNS query packets (200+ bytes) or a
high volume of queries from a single process to a single server.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from ebpf_netsec.models import DnsQueryEvent


@dataclass(slots=True)
class DnsTunnel:
    comm: str
    server: str
    count: int
    mean_size: float
    max_size: int
    score: float


def detect_dns_tunnels(
    queries: Iterable[DnsQueryEvent],
    min_count: int = 5,
    suspicious_size: int = 150,
    high_volume: int = 30,
) -> list[DnsTunnel]:
    """
    Flag DNS flows where:
      * mean packet size > suspicious_size (encoded data), OR
      * count > high_volume in the window (flooding exfil)
    """
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for q in queries:
        groups[(q.comm, q.server)].append(q.size)

    tunnels: list[DnsTunnel] = []

    for (comm, server), sizes in groups.items():
        n = len(sizes)
        if n < min_count:
            continue

        mean = statistics.mean(sizes)
        mx = max(sizes)

        if mean < suspicious_size and n < high_volume:
            continue

        # Score: 0–10 based on how far above thresholds we are
        size_score = min(max(0.0, (mean - 80) / 200.0), 1.0)   # 80B normal → 280B+ = 1.0
        vol_score  = min(n / 50.0, 1.0)
        score = round(10.0 * (0.7 * size_score + 0.3 * vol_score), 2)

        tunnels.append(DnsTunnel(
            comm=comm, server=server,
            count=n,
            mean_size=round(mean, 1),
            max_size=mx,
            score=score,
        ))

    tunnels.sort(key=lambda t: t.score, reverse=True)
    return tunnels
