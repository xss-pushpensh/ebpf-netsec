from datetime import datetime, timezone

from ebpf_netsec.models import TcpConnectEvent, DnsQueryEvent


def test_tcp_event_dict():
    e = TcpConnectEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        pid=1234, comm="curl", daddr="1.1.1.1", dport=443,
    )
    d = e.to_dict()
    assert d["type"] == "tcp"
    assert d["pid"] == 1234
    assert d["comm"] == "curl"
    assert d["daddr"] == "1.1.1.1"
    assert d["dport"] == 443


def test_tcp_is_dns_property():
    e = TcpConnectEvent(datetime.now(timezone.utc), 1, "x", "y", 53)
    assert e.is_dns is True
    e2 = TcpConnectEvent(datetime.now(timezone.utc), 1, "x", "y", 443)
    assert e2.is_dns is False


def test_dns_event_dict():
    e = DnsQueryEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        pid=5678, comm="dig", server="8.8.8.8", size=60,
    )
    d = e.to_dict()
    assert d["type"] == "dns"
    assert d["server"] == "8.8.8.8"
    assert d["size"] == 60
