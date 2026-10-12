"""Discord webhook alert notifier with rate limiting."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Optional

import requests


# Discord embed colors (decimal)
COLOR_BEACON = 0xF85149   # red
COLOR_TUNNEL = 0xFFA657   # orange
COLOR_INFO   = 0x58A6FF   # blue


class DiscordNotifier:
    """Sends rich embed alerts to a Discord channel via webhook."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        min_interval: float = 3.0,
    ):
        self.webhook_url = webhook_url or os.environ.get(
            "DISCORD_WEBHOOK_URL", ""
        )
        self.min_interval = min_interval
        self._last_send = 0.0
        self.enabled = bool(self.webhook_url)

        if not self.enabled:
            print(
                "[notify] Discord disabled — set DISCORD_WEBHOOK_URL "
                "to enable."
            )

    def _post(self, payload: dict) -> bool:
        if not self.enabled:
            return False
        now = time.time()
        if now - self._last_send < self.min_interval:
            return False
        self._last_send = now
        try:
            r = requests.post(self.webhook_url, json=payload, timeout=5)
            return r.status_code in (200, 204)
        except Exception as e:
            print(f"[notify] Discord send failed: {e}")
            return False

    def send_beacon(self, b) -> bool:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return self._post({
            "username": "ebpf-netsec",
            "embeds": [{
                "title": "🚨 Beacon Detected",
                "color": COLOR_BEACON,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "fields": [
                    {"name": "Process", "value": f"`{b.comm}`", "inline": True},
                    {"name": "Target", "value": f"`{b.daddr}:{b.dport}`", "inline": True},
                    {"name": "Score", "value": f"**{b.score}** / 10", "inline": True},
                    {"name": "Events", "value": str(b.count), "inline": True},
                    {"name": "Mean Interval", "value": f"{b.mean_interval}s", "inline": True},
                    {"name": "Jitter", "value": f"`{b.jitter_ratio}` (lower = worse)", "inline": True},
                ],
                "footer": {"text": f"ebpf-netsec • {ts}"},
            }],
        })

    def send_tunnel(self, t) -> bool:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return self._post({
            "username": "ebpf-netsec",
            "embeds": [{
                "title": "🚨 DNS Tunnel Detected",
                "color": COLOR_TUNNEL,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "fields": [
                    {"name": "Process", "value": f"`{t.comm}`", "inline": True},
                    {"name": "DNS Server", "value": f"`{t.server}`", "inline": True},
                    {"name": "Score", "value": f"**{t.score}** / 10", "inline": True},
                    {"name": "Queries", "value": str(t.count), "inline": True},
                    {"name": "Mean Size", "value": f"{t.mean_size} B", "inline": True},
                    {"name": "Max Size", "value": f"{t.max_size} B", "inline": True},
                ],
                "footer": {"text": f"ebpf-netsec • {ts}"},
            }],
        })

    def send_startup(self) -> bool:
        return self._post({
            "username": "ebpf-netsec",
            "embeds": [{
                "title": "✅ ebpf-netsec started",
                "description": "Kernel-level network monitoring is now live.",
                "color": COLOR_INFO,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }],
        })
