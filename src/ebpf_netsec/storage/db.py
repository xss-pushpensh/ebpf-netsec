"""SQLite-backed event store for ebpf-netsec."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ebpf_netsec.models import TcpConnectEvent, DnsQueryEvent


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT    NOT NULL,
    pid     INTEGER NOT NULL,
    comm    TEXT    NOT NULL,
    daddr   TEXT    NOT NULL,
    dport   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_flow ON events(comm, daddr, dport, ts);

CREATE TABLE IF NOT EXISTS dns_queries (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT    NOT NULL,
    pid     INTEGER NOT NULL,
    comm    TEXT    NOT NULL,
    server  TEXT    NOT NULL,
    size    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_ts   ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_flow ON dns_queries(comm, server, ts);

CREATE TABLE IF NOT EXISTS beacons (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at      TEXT    NOT NULL,
    comm             TEXT    NOT NULL,
    daddr            TEXT    NOT NULL,
    dport            INTEGER NOT NULL,
    count            INTEGER NOT NULL,
    mean_interval    REAL    NOT NULL,
    stddev_interval  REAL    NOT NULL,
    jitter_ratio     REAL    NOT NULL,
    score            REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_beacons_detected_at ON beacons(detected_at);

CREATE TABLE IF NOT EXISTS dns_tunnels (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at      TEXT    NOT NULL,
    comm             TEXT    NOT NULL,
    server           TEXT    NOT NULL,
    count            INTEGER NOT NULL,
    mean_size        REAL    NOT NULL,
    max_size         INTEGER NOT NULL,
    score            REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_tunnels_detected_at ON dns_tunnels(detected_at);
"""


class EventDB:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)

    # ---------- writers ----------

    def insert_event(self, evt: TcpConnectEvent) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events(ts,pid,comm,daddr,dport) VALUES(?,?,?,?,?)",
                (evt.timestamp.isoformat(), evt.pid, evt.comm,
                 evt.daddr, evt.dport),
            )

    def insert_dns(self, q: DnsQueryEvent) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO dns_queries(ts,pid,comm,server,size) "
                "VALUES(?,?,?,?,?)",
                (q.timestamp.isoformat(), q.pid, q.comm,
                 q.server, q.size),
            )

    def insert_beacon(self, b) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO beacons(detected_at,comm,daddr,dport,count,"
                "mean_interval,stddev_interval,jitter_ratio,score) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    b.comm, b.daddr, b.dport, b.count,
                    b.mean_interval, b.stddev_interval,
                    b.jitter_ratio, b.score,
                ),
            )

    def insert_dns_tunnel(self, t) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO dns_tunnels(detected_at,comm,server,count,"
                "mean_size,max_size,score) VALUES(?,?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    t.comm, t.server, t.count,
                    t.mean_size, t.max_size, t.score,
                ),
            )

    # ---------- readers ----------

    def recent_events(self, minutes: int = 10) -> list[TcpConnectEvent]:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        cur = self._conn.execute(
            "SELECT ts,pid,comm,daddr,dport FROM events WHERE ts >= ? "
            "ORDER BY ts", (cutoff,),
        )
        return [
            TcpConnectEvent(
                timestamp=datetime.fromisoformat(ts),
                pid=pid, comm=comm, daddr=daddr, dport=dport,
            )
            for ts, pid, comm, daddr, dport in cur
        ]

    def recent_dns(self, minutes: int = 10) -> list[DnsQueryEvent]:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        cur = self._conn.execute(
            "SELECT ts,pid,comm,server,size FROM dns_queries WHERE ts >= ? "
            "ORDER BY ts", (cutoff,),
        )
        return [
            DnsQueryEvent(
                timestamp=datetime.fromisoformat(ts),
                pid=pid, comm=comm, server=server, size=size,
            )
            for ts, pid, comm, server, size in cur
        ]

    def recent_beacons(self, limit: int = 50):
        cur = self._conn.execute(
            "SELECT detected_at,comm,daddr,dport,count,"
            "mean_interval,stddev_interval,jitter_ratio,score "
            "FROM beacons ORDER BY detected_at DESC LIMIT ?", (limit,),
        )
        return list(cur)

    def recent_dns_tunnels(self, limit: int = 50):
        cur = self._conn.execute(
            "SELECT detected_at,comm,server,count,mean_size,max_size,score "
            "FROM dns_tunnels ORDER BY detected_at DESC LIMIT ?", (limit,),
        )
        return list(cur)

    def stats(self) -> dict:
        e  = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        d  = self._conn.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
        b  = self._conn.execute("SELECT COUNT(*) FROM beacons").fetchone()[0]
        t  = self._conn.execute("SELECT COUNT(*) FROM dns_tunnels").fetchone()[0]
        return {"events": e, "dns_queries": d, "beacons": b, "dns_tunnels": t}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
