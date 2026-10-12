from datetime import datetime, timedelta, timezone

from ebpf_netsec.models import TcpConnectEvent
from ebpf_netsec.detect.beaconing import detect_beacons


def _mk(start, seconds_list, comm="malware", daddr="10.0.0.1", dport=4444):
    return [
        TcpConnectEvent(
            timestamp=start + timedelta(seconds=s),
            pid=1, comm=comm, daddr=daddr, dport=dport,
        )
        for s in seconds_list
    ]


def test_detects_perfect_beacon():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # 10 connections every 30s -> perfect beacon
    events = _mk(start, [i * 30 for i in range(10)])
    beacons = detect_beacons(events, min_count=5)
    assert len(beacons) == 1
    b = beacons[0]
    assert b.comm == "malware"
    assert b.count == 10
    assert b.mean_interval == 30.0
    assert b.jitter_ratio < 0.05
    assert b.score >= 5


def test_ignores_jittery_traffic():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # Irregular spacing -> high jitter -> not a beacon
    events = _mk(start, [0, 5, 55, 61, 62, 200, 201, 260, 261, 262])
    beacons = detect_beacons(events, min_count=5, max_jitter=0.3)
    assert beacons == []


def test_ignores_low_count():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = _mk(start, [0, 30, 60])
    beacons = detect_beacons(events, min_count=5)
    assert beacons == []
