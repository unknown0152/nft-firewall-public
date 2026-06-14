.PHONY: backup-state bundle check venv

BUNDLE_DIR ?= /var/backups/nft-firewall

check:
	./scripts/dev-check.sh

venv:
	python3 -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip
	. .venv/bin/activate && python -m pip install ruff mypy pytest pytest-cov hypothesis

bundle:
	mkdir -p "$(BUNDLE_DIR)"
	git bundle create "$(BUNDLE_DIR)/nft-firewall-$$(date -u +%Y%m%dT%H%M%SZ).bundle" --all

backup-state:
	mkdir -p "$(BUNDLE_DIR)"
	tmp="$$(mktemp)"; \
	for path in \
		/etc/nftables.conf \
		/var/lib/nft-firewall/dynamic-sets.json \
		/var/lib/nft-firewall/watchdog-markers.json \
		/var/log/nft-firewall/audit.jsonl \
		/opt/nft-firewall/config/firewall.ini \
		/etc/nft-firewall/firewall.ini \
		/etc/nft-watchdog.conf \
		/etc/systemd/system/nft-*.service \
		/etc/systemd/system/nft-*.timer; do \
		for match in $$path; do \
			[ -e "$$match" ] && printf '%s\n' "$$match" >> "$$tmp"; \
		done; \
	done; \
	tar --create --gzip --absolute-names --files-from "$$tmp" \
		--file "$(BUNDLE_DIR)/nft-firewall-runtime-state-$$(date -u +%Y%m%dT%H%M%SZ).tar.gz"; \
	rm -f "$$tmp"
