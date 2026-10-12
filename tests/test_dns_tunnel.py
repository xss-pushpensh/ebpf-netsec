from datetime import datetime, timedelta, timezone

from ebpf_netsec.models import DnsQueryEvent
from ebpf_netsec.detect.dns_tunnel import detect_dns_tunnels


def test_detects_large_dns_queries():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        DnsQueryEvent(
            timestamp=start + timedelta(seconds=i * 5),
            pid=1, comm="malware", server="8.8.8.8", size=250,
        )
        for i in range(10)
    ]
    tunnels = detect_dns_tunnels(events, min_count=5)
    assert len(tunnels) == 1
    t = tunnels[0]
    assert t.comm == "malware"
    assert t.mean_size == 250.0
    assert t.max_size == 250


def test_ignores_normal_dns():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        DnsQueryEvent(
            timestamp=start + timedelta(seconds=i * 10),
            pid=1, comm="curl", server="8.8.8.8", size=55,
        )
        for i in range(10)
    ]
    tunnels = detect_dns_tunnels(events, min_count=5)
    assert tunnels == []
