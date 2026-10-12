"""Beaconing detection: find low-jitter, high-count periodic connections."""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from ebpf_netsec.models import TcpConnectEvent


@dataclass(slots=True)
class Beacon:
    """A suspected beaconing flow."""
    comm: str
    daddr: str
    dport: int
    count: int
    mean_interval: float       # seconds
    stddev_interval: float     # seconds
    jitter_ratio: float        # stddev / mean  (0.0 = perfect beacon)
    score: float               # 0..10 (higher = more suspicious)


def detect_beacons(
    events: Iterable[TcpConnectEvent],
    min_count: int = 5,
    max_jitter: float = 0.5,
    min_interval: float = 0.5,
    max_interval: float = 3600.0,
) -> list[Beacon]:
    """
    Group events by (comm, daddr, dport), compute inter-arrival times,
    and flag flows with regular timing (low jitter) as beaconing.

    Args:
        events:       Iterable of TcpConnectEvent
        min_count:    Minimum events in a flow to consider
        max_jitter:   Max stddev/mean ratio (0.5 = ±50% jitter allowed)
        min_interval: Ignore intervals shorter than this (connection churn)
        max_interval: Ignore intervals longer than this (session gaps)
    """
    groups: dict[tuple, list] = defaultdict(list)
    for e in events:
        groups[(e.comm, e.daddr, e.dport)].append(e.timestamp)

    beacons: list[Beacon] = []

    for (comm, daddr, dport), times in groups.items():
        times.sort()
        n = len(times)
        if n < min_count:
            continue

        intervals = [
            (times[i] - times[i - 1]).total_seconds()
            for i in range(1, n)
        ]
        intervals = [i for i in intervals if i >= min_interval]
        if len(intervals) < min_count - 1:
            continue

        mean = statistics.mean(intervals)
        if mean > max_interval:
            continue

        stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        jitter = stdev / mean if mean > 0 else 1.0

        if jitter > max_jitter:
            continue

        # Score formula:
        #   more events + lower jitter  →  higher score
        count_weight = min(n / 20.0, 1.0)       # caps at 20 events
        jitter_weight = max(0.0, 1.0 - jitter)  # 1.0 = perfect beacon
        score = round(10.0 * count_weight * jitter_weight, 2)

        beacons.append(Beacon(
            comm=comm, daddr=daddr, dport=dport,
            count=n,
            mean_interval=round(mean, 2),
            stddev_interval=round(stdev, 2),
            jitter_ratio=round(jitter, 3),
            score=score,
        ))

    beacons.sort(key=lambda b: b.score, reverse=True)
    return beacons
