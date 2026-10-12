import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ebpf_netsec.storage.db import EventDB
from ebpf_netsec.models import TcpConnectEvent, DnsQueryEvent
from ebpf_netsec.detect.beaconing import detect_beacons
from ebpf_netsec.detect.dns_tunnel import detect_dns_tunnels


def _tmp_db():
    tmpdir = tempfile.mkdtemp()
    return EventDB(Path(tmpdir) / "test.db")


def test_insert_and_read_tcp():
    db = _tmp_db()
    e = TcpConnectEvent(datetime.now(timezone.utc), 1, "curl", "1.1.1.1", 443)
    db.insert_event(e)
    events = db.recent_events(minutes=10)
    assert len(events) == 1
    assert events[0].comm == "curl"
    db.close()


def test_insert_and_read_dns():
    db = _tmp_db()
    q = DnsQueryEvent(datetime.now(timezone.utc), 1, "dig", "8.8.8.8", 60)
    db.insert_dns(q)
    queries = db.recent_dns(minutes=10)
    assert len(queries) == 1
    assert queries[0].size == 60
    db.close()


def test_stats():
    db = _tmp_db()
    db.insert_event(TcpConnectEvent(datetime.now(timezone.utc), 1, "a", "1.1.1.1", 80))
    db.insert_dns(DnsQueryEvent(datetime.now(timezone.utc), 1, "b", "8.8.8.8", 40))
    s = db.stats()
    assert s["events"] == 1
    assert s["dns_queries"] == 1
    assert s["beacons"] == 0
    assert s["dns_tunnels"] == 0
    db.close()
