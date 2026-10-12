"""CLI for ebpf-netsec."""

from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

import click
from rich.console import Console
from rich.table import Table

from ebpf_netsec.sensors.bpftrace_runner import BpftraceRunner
from ebpf_netsec.storage.db import EventDB
from ebpf_netsec.detect.beaconing import detect_beacons
from ebpf_netsec.detect.dns_tunnel import detect_dns_tunnels
from ebpf_netsec.models import TcpConnectEvent, DnsQueryEvent

console = Console()
DEFAULT_SCRIPT = "ebpf/tcpconnect.bt"
DEFAULT_DB = "data/events.db"


def _conn_table(rows, max_rows):
    t = Table(title="Outbound TCP Connections")
    t.add_column("Time", style="dim")
    t.add_column("PID", justify="right")
    t.add_column("Process", style="cyan")
    t.add_column("Dst", style="yellow")
    t.add_column("Port", justify="right", style="magenta")
    for r in rows[-max_rows:]:
        t.add_row(*r)
    return t


def _dns_table(rows, max_rows):
    t = Table(title="DNS Queries")
    t.add_column("Time", style="dim")
    t.add_column("PID", justify="right")
    t.add_column("Process", style="cyan")
    t.add_column("Server", style="yellow")
    t.add_column("Size", justify="right", style="magenta")
    for r in rows[-max_rows:]:
        t.add_row(*r)
    return t


@click.group()
def cli():
    """eBPF Network Security Observability."""


@cli.command()
@click.option("--script", default=DEFAULT_SCRIPT)
@click.option("--max-rows", default=20)
@click.option("--debug", is_flag=True)
def sniff(script, max_rows, debug):
    """Stream TCP + DNS events in a live dual table."""
    runner = BpftraceRunner(script, verbose=debug)
    runner.start()
    console.print("[bold green]Attached. Watching TCP + DNS...[/bold green]\n")

    tcp_rows, dns_rows = [], []
    tcp_n = dns_n = 0

    try:
        for evt in runner.events():
            if isinstance(evt, TcpConnectEvent):
                tcp_n += 1
                tcp_rows.append((
                    evt.timestamp.strftime("%H:%M:%S"),
                    str(evt.pid), evt.comm, evt.daddr, str(evt.dport),
                ))
            else:
                dns_n += 1
                dns_rows.append((
                    evt.timestamp.strftime("%H:%M:%S"),
                    str(evt.pid), evt.comm, evt.server, str(evt.size),
                ))
            console.clear()
            console.print(_conn_table(tcp_rows, max_rows))
            console.print()
            console.print(_dns_table(dns_rows, max_rows))
            console.print(
                f"\n[dim]TCP: {tcp_n}   DNS: {dns_n}   "
                f"Ctrl+C to stop[/dim]"
            )
    except KeyboardInterrupt:
        pass
    finally:
        runner.stop()
        console.print(
            f"\n[bold red]Stopped. TCP: {tcp_n}  DNS: {dns_n}[/bold red]"
        )


@cli.command()
@click.option("--script", default=DEFAULT_SCRIPT)
@click.option("--db", default=DEFAULT_DB)
@click.option("--window", default=5)
@click.option("--interval", default=15)
@click.option("--min-count", default=5)
@click.option("--score-threshold", default=4.0)
@click.option("--debug", is_flag=True)
def detect(script, db, window, interval, min_count, score_threshold, debug):
    """Run live detection for beacons + DNS tunnels (CLI)."""
    database = EventDB(db)
    console.print(f"[bold green]DB:[/bold green] {database.path}")

    runner = BpftraceRunner(script, verbose=debug)
    runner.start()
    console.print("[bold green]Attached. Watching for threats...[/bold green]\n")

    tcp_rows, dns_rows = [], []
    tcp_n = dns_n = alerts = 0
    last_detect = 0.0
    seen_beacons: set[tuple] = set()
    seen_tunnels: set[tuple] = set()

    try:
        for evt in runner.events():
            if isinstance(evt, TcpConnectEvent):
                tcp_n += 1
                database.insert_event(evt)
                tcp_rows.append((
                    evt.timestamp.strftime("%H:%M:%S"),
                    str(evt.pid), evt.comm, evt.daddr, str(evt.dport),
                ))
            else:
                dns_n += 1
                database.insert_dns(evt)
                dns_rows.append((
                    evt.timestamp.strftime("%H:%M:%S"),
                    str(evt.pid), evt.comm, evt.server, str(evt.size),
                ))

            now = time.time()
            if now - last_detect >= interval:
                last_detect = now

                for b in detect_beacons(
                    database.recent_events(minutes=window),
                    min_count=min_count,
                ):
                    key = ("b", b.comm, b.daddr, b.dport)
                    if b.score >= score_threshold and key not in seen_beacons:
                        seen_beacons.add(key)
                        database.insert_beacon(b)
                        alerts += 1
                        console.print(
                            f"\n[bold red]⚠  BEACON[/bold red]  "
                            f"[cyan]{b.comm}[/cyan] → "
                            f"[yellow]{b.daddr}:{b.dport}[/yellow]  "
                            f"score=[red]{b.score}[/red]  "
                            f"count={b.count}  mean={b.mean_interval}s"
                        )

                for t in detect_dns_tunnels(
                    database.recent_dns(minutes=window),
                    min_count=min_count,
                ):
                    key = ("t", t.comm, t.server)
                    if t.score >= score_threshold and key not in seen_tunnels:
                        seen_tunnels.add(key)
                        database.insert_dns_tunnel(t)
                        alerts += 1
                        console.print(
                            f"\n[bold red]⚠  DNS TUNNEL[/bold red]  "
                            f"[cyan]{t.comm}[/cyan] → "
                            f"[yellow]{t.server}[/yellow]  "
                            f"score=[red]{t.score}[/red]  "
                            f"count={t.count}"
                        )

            console.clear()
            console.print(_conn_table(tcp_rows, 12))
            console.print()
            console.print(_dns_table(dns_rows, 8))
            console.print(
                f"\n[dim]TCP: {tcp_n}   DNS: {dns_n}   "
                f"Alerts: {alerts}   Ctrl+C to stop[/dim]"
            )
    except KeyboardInterrupt:
        pass
    finally:
        runner.stop()
        database.close()
        console.print(
            f"\n[bold red]Stopped. TCP: {tcp_n}  DNS: {dns_n}  "
            f"Alerts: {alerts}[/bold red]"
        )


@cli.command()
@click.option("--script", default=DEFAULT_SCRIPT)
@click.option("--db", default=DEFAULT_DB)
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8080)
@click.option("--interval", default=15)
def dashboard(script, db, host, port, interval):
    """Launch the live web dashboard."""
    import uvicorn
    from ebpf_netsec.api.dashboard import create_app

    app = create_app(script=script, db_path=db, detect_interval=interval)
    console.print(
        f"[bold green]Dashboard:[/bold green] "
        f"http://{host}:{port}\n"
    )
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    uvicorn.run(app, host=host, port=port, log_level="warning")


@cli.command()
@click.option("--db", default=DEFAULT_DB)
@click.option("--events/--no-events", default=False)
@click.option("--dns/--no-dns", default=False)
@click.option("--beacons/--no-beacons", default=True)
@click.option("--tunnels/--no-tunnels", default=True)
@click.option("--limit", default=30)
def history(db, events, dns, beacons, tunnels, limit):
    """Query stored events, DNS, beacons, and tunnels."""
    database = EventDB(db)
    console.print(f"[bold]DB:[/bold] {database.path}")
    console.print(f"[bold]Stats:[/bold] {database.stats()}\n")

    if events:
        recent = database.recent_events(minutes=60)[-limit:]
        t = Table(title=f"Last {len(recent)} TCP events")
        t.add_column("Time", style="dim")
        t.add_column("PID", justify="right")
        t.add_column("Process", style="cyan")
        t.add_column("Dst", style="yellow")
        t.add_column("Port", justify="right", style="magenta")
        for e in recent:
            t.add_row(e.timestamp.strftime("%H:%M:%S"),
                      str(e.pid), e.comm, e.daddr, str(e.dport))
        console.print(t); console.print()

    if dns:
        recent = database.recent_dns(minutes=60)[-limit:]
        t = Table(title=f"Last {len(recent)} DNS queries")
        t.add_column("Time", style="dim")
        t.add_column("PID", justify="right")
        t.add_column("Process", style="cyan")
        t.add_column("Server", style="yellow")
        t.add_column("Size", justify="right", style="magenta")
        for e in recent:
            t.add_row(e.timestamp.strftime("%H:%M:%S"),
                      str(e.pid), e.comm, e.server, str(e.size))
        console.print(t); console.print()

    if beacons:
        rows = database.recent_beacons(limit=limit)
        if rows:
            t = Table(title=f"Last {len(rows)} beacons")
            t.add_column("Detected", style="dim")
            t.add_column("Score", justify="right", style="red")
            t.add_column("Process", style="cyan")
            t.add_column("Dst", style="yellow")
            t.add_column("Port", justify="right", style="magenta")
            t.add_column("Count", justify="right")
            t.add_column("Mean(s)", justify="right")
            t.add_column("Jitter", justify="right")
            for r in rows:
                dt, comm, daddr, dport, count, mean, sd, jit, sc = r
                t.add_row(dt[11:19], f"{sc:.2f}", comm, daddr,
                          str(dport), str(count), f"{mean:.2f}",
                          f"{jit:.3f}")
            console.print(t)
        else:
            console.print("[yellow]No beacons yet.[/yellow]")

    if tunnels:
        rows = database.recent_dns_tunnels(limit=limit)
        if rows:
            t = Table(title=f"Last {len(rows)} DNS tunnels")
            t.add_column("Detected", style="dim")
            t.add_column("Score", justify="right", style="red")
            t.add_column("Process", style="cyan")
            t.add_column("Server", style="yellow")
            t.add_column("Count", justify="right")
            t.add_column("Mean B", justify="right")
            t.add_column("Max B", justify="right")
            for r in rows:
                dt, comm, server, count, mean, mx, sc = r
                t.add_row(dt[11:19], f"{sc:.2f}", comm, server,
                          str(count), f"{mean:.1f}", str(mx))
            console.print(t)
        else:
            console.print("[yellow]No DNS tunnels yet.[/yellow]")

    database.close()


@cli.command("seed-demo")
@click.option("--db", default=DEFAULT_DB)
def seed_demo(db):
    """Seed synthetic beacon + DNS tunnel events."""
    database = EventDB(db)
    base = datetime.now(timezone.utc) - timedelta(minutes=5)

    for i in range(20):
        ts = base + timedelta(seconds=i * 30 + random.uniform(-0.3, 0.3))
        database.insert_event(TcpConnectEvent(
            ts, 99999, "fake-malware", "203.0.113.42", 4444,
        ))

    for _ in range(15):
        ts = base + timedelta(seconds=random.uniform(0, 300))
        database.insert_event(TcpConnectEvent(
            ts, 11111, "curl", "93.184.216.34", 443,
        ))

    for i in range(15):
        ts = base + timedelta(seconds=i * 10 + random.uniform(-1, 1))
        database.insert_dns(DnsQueryEvent(
            ts, 99999, "fake-malware", "8.8.8.8",
            size=random.randint(220, 280),
        ))

    for _ in range(10):
        ts = base + timedelta(seconds=random.uniform(0, 300))
        database.insert_dns(DnsQueryEvent(
            ts, 11111, "curl", "8.8.8.8", size=random.randint(40, 80),
        ))

    console.print(f"[green]Seeded synthetic data into {database.path}[/green]\n")
    console.print("Try:")
    console.print("  [bold]ebpf-netsec dashboard[/bold]")
    console.print("  [bold]ebpf-netsec history --beacons --tunnels[/bold]")
    database.close()


if __name__ == "__main__":
    cli()
