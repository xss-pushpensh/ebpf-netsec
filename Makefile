.PHONY: help install dev test sniff detect dashboard seed history clean

help:
	@echo "  install    Install package"
	@echo "  dev        Install with dev deps"
	@echo "  test       Run pytest"
	@echo "  sniff      Live TCP + DNS view"
	@echo "  detect     Live detection CLI"
	@echo "  dashboard  Web dashboard"
	@echo "  seed       Seed synthetic data"
	@echo "  history    Show stored events"
	@echo "  clean      Remove caches and DB"

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -v

sniff:
	sudo -E env PATH="$$PATH" ./venv/bin/ebpf-netsec sniff

detect:
	sudo -E env PATH="$$PATH" ./venv/bin/ebpf-netsec detect

dashboard:
	sudo -E env PATH="$$PATH" DISCORD_WEBHOOK_URL="$$DISCORD_WEBHOOK_URL" \
		./venv/bin/ebpf-netsec dashboard

seed:
	./venv/bin/ebpf-netsec seed-demo

history:
	./venv/bin/ebpf-netsec history --events --dns --beacons --tunnels

clean:
	rm -rf data/*.db* reports/*.html .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
