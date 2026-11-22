# vnc-watch — Makefile
#
#   make            show help
#   make check      verify the script and report optional dependencies
#   make install    install the user service, symlink and state directory
#   make status     show service and configuration state
#
# Everything is per-user. Nothing here needs root.

SHELL      := /bin/sh
PYTHON     ?= $(shell test -x /usr/bin/python3 && echo /usr/bin/python3 || command -v python3)
PREFIX     ?= $(HOME)/.local
BINDIR     ?= $(PREFIX)/bin
UNITDIR    ?= $(HOME)/.config/systemd/user
STATE      ?= $(HOME)/.local/state/vnc-watch

# Optional seat-lock state file for the exam/lock guard. Empty = disabled.
# Set it for your machine, e.g. make install LOCKFILE=/run/seat-lock/seat0.json
LOCKFILE   ?=

SRC        := vnc-watch.py
LINK       := $(BINDIR)/vnc-watch
UNIT       := $(UNITDIR)/vnc-watch.service
SERVICE    := vnc-watch.service

.PHONY: help check install uninstall status logs restart stop start \
        channels test popup-test shortcut lockdown xwatch audit menu run clean purge

help:
	@echo "vnc-watch"
	@echo ""
	@echo "  make check        validate the script, list optional dependencies"
	@echo "  make install      symlink + systemd user service + state dir"
	@echo "  make uninstall    stop and remove the service and symlink"
	@echo "  make purge        uninstall, then delete the state directory"
	@echo "  make status       service state and configured alert channels"
	@echo "  make logs         tail the alert log"
	@echo "  make restart      restart the detection daemon"
	@echo ""
	@echo "  make shortcut     bind Ctrl+Alt+Shift+L to lockdown"
	@echo "  make channels     show/edit remote alert channels"
	@echo "  make test         send a test message to each channel"
	@echo "  make popup-test   preview the action window (no auto action)"
	@echo "  make lockdown     close any VNC/RDP session and lock the screen"
	@echo "  make xwatch       evict screen-capture tools on :0 (root included)"
	@echo "  make audit        classify connections in the current VNC log"
	@echo "  make menu         interactive menu"
	@echo "  make run          run the detector in the foreground"
	@echo ""
	@echo "  vars: PYTHON=$(PYTHON) PREFIX=$(PREFIX) LOCKFILE=$(LOCKFILE)"

check:
	@$(PYTHON) -c 'import sys; assert sys.version_info >= (3,8), "python 3.8+ required"; print("python  :", sys.version.split()[0], "OK")'
	@$(PYTHON) -m py_compile $(SRC) && echo "compile : OK"
	@command -v systemctl >/dev/null 2>&1 && echo "systemd : present" || echo "systemd : MISSING (run the daemon manually)"
	@command -v xinput    >/dev/null 2>&1 && echo "xinput  : present" || echo "xinput  : missing (XTEST signal disabled)"
	@command -v gdbus     >/dev/null 2>&1 && echo "gdbus   : present" || echo "gdbus   : missing (desktop notifications fall back to notify-send)"
	@command -v loginctl  >/dev/null 2>&1 && echo "loginctl: present" || echo "loginctl: missing (session detection uses utmp only)"
	@$(PYTHON) -c 'import gi; gi.require_version("Gtk","3.0"); from gi.repository import Gtk' 2>/dev/null \
		&& echo "gtk3    : present (action window)" || echo "gtk3    : missing (action window disabled)"
	@test -r /var/run/utmp && echo "utmp    : readable" || echo "utmp    : not readable (login detection disabled)"

install: check
	@mkdir -p "$(BINDIR)" "$(STATE)"
	@chmod 700 "$(STATE)"
	@ln -sfn "$(CURDIR)/$(SRC)" "$(LINK)"
	@echo "link    : $(LINK) -> $(CURDIR)/$(SRC)"
	@mkdir -p "$(UNITDIR)"
	@sed -e 's|@PYTHON@|$(PYTHON)|g' \
	     -e 's|@EXEC@|$(LINK)|g' \
	     -e 's|@DOC@|$(CURDIR)/README.md|g' \
	     -e 's|@LOCKFILE@|$(LOCKFILE)|g' \
	     packaging/vnc-watch.service.in > "$(UNIT)"
	@echo "unit    : $(UNIT)"
	@if command -v systemctl >/dev/null 2>&1; then \
		systemctl --user daemon-reload && \
		systemctl --user enable $(SERVICE) >/dev/null 2>&1; \
		systemctl --user restart $(SERVICE) && echo "service : started"; \
	else \
		echo "service : systemd not available, start with: $(LINK) watch --input-watch"; \
	fi
	@$(MAKE) --no-print-directory status

uninstall:
	@if command -v systemctl >/dev/null 2>&1; then \
		systemctl --user disable --now $(SERVICE) >/dev/null 2>&1 || true; \
	fi
	@rm -f "$(UNIT)" "$(LINK)"
	@if command -v systemctl >/dev/null 2>&1; then systemctl --user daemon-reload; fi
	@echo "removed the service and the $(LINK) symlink"
	@echo "state kept in $(STATE) (use 'make purge' to delete it)"

purge: uninstall
	@rm -rf "$(STATE)"
	@echo "deleted $(STATE)"

status:
	@printf 'service : '; \
		if command -v systemctl >/dev/null 2>&1; then \
			systemctl --user is-active $(SERVICE) 2>/dev/null || echo "inactive"; \
		else echo "systemd unavailable"; fi
	@printf 'binary  : '; test -e "$(LINK)" && echo "$(LINK)" || echo "not installed"
	@printf 'state   : '; test -d "$(STATE)" && echo "$(STATE)" || echo "missing"
	@if test -f "$(STATE)/channels.json"; then \
		printf 'channels: '; $(PYTHON) -c 'import json,sys; d=json.load(open(sys.argv[1])); print(", ".join(k for k,v in d.items() if v) or "none")' "$(STATE)/channels.json"; \
	else printf 'channels: none configured\n'; fi

logs:
	@tail -n 30 "$(STATE)/vnc-watch.log" 2>/dev/null || echo "no log yet"

restart:
	@systemctl --user restart $(SERVICE) 2>/dev/null || $(LINK) watch --input-watch

stop:
	@systemctl --user stop $(SERVICE) 2>/dev/null || true

start:
	@systemctl --user start $(SERVICE) 2>/dev/null || $(LINK) watch --input-watch

shortcut:
	@$(LINK) shortcut $(ARGS)

channels:
	@$(LINK) channels $(ARGS)

test:
	@$(LINK) channels --test

popup-test:
	@$(LINK) popup --no-auto --timeout 30 \
		--reason "Preview: VNC viewer attached" \
		--detail "127.0.0.1 -> local :5900 (no real detection)"

lockdown:
	@$(LINK) lockdown

xwatch:
	@$(LINK) xwatch $(ARGS)

audit:
	@$(LINK) audit

menu:
	@$(LINK) menu

run:
	@$(LINK) watch --input-watch

clean:
	@rm -rf __pycache__
	@echo "cleaned"