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

# Off-machine alert identity. Empty = privacy-preserving default (no host or
# user in webhook payloads). Opt in per install, e.g.
#   make install ALERTIDENTITY=host,user
ALERTIDENTITY ?=

SRC        := vnc-watch.py
LINK       := $(BINDIR)/vnc-watch
UNIT       := $(UNITDIR)/vnc-watch.service
SERVICE    := vnc-watch.service
TRAYUNIT   := $(UNITDIR)/vnc-watch-tray.service
TRAYSERVICE := vnc-watch-tray.service

# Tray backend: empty = auto (top-bar indicator when the AppIndicator shell
# extension is enabled, otherwise a docked floating chip). Force with
# indicator or floating.
TRAYBACKEND ?=

.PHONY: help check install uninstall status logs restart stop start \
        channels test test-fixtures test-ssh popup-test shortcut lockdown \
        xwatch audit ssh menu run tray tray-stop clean purge panel-install \
        panel-uninstall panel-restart panel-status units update reload \
        panel-refresh

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
	@echo "  make update       git pull, then restart every running piece"
	@echo "  make reload       restart every running piece (no pull)"
	@echo ""
	@echo "  make shortcut     bind Ctrl+Alt+Shift+L to lockdown"
	@echo "  make channels     show/edit remote alert channels"
	@echo "  make test         send a test message to each channel"
	@echo "  make test-fixtures  isolation tests (browser wipe + SSH subsystem)"
	@echo "  make test-ssh     SSH subsystem isolation tests (temp HOME)"
	@echo "  make popup-test   preview the action window (no auto action)"
	@echo "  make lockdown     close any VNC/RDP session and lock the screen"
	@echo "  make xwatch       evict screen-capture tools on :0 (root included)"
	@echo "  make audit        classify connections in the current VNC log"
	@echo "  make ssh          SSH subsystem view (sessions, procs, wtmp, x11vnc)"
	@echo "  make menu         interactive menu"
	@echo "  make tray         run the tray icon in the foreground"
	@echo "  make tray-stop    stop the tray service"
	@echo "  make run          run the detector in the foreground"
	@echo ""
	@echo "  make panel-install    GNOME top-panel indicator (per-user, no root)"
	@echo "  make panel-status     show the panel indicator install state"
	@echo "  make panel-restart    reload the shell to pick up the indicator"
	@echo "  make panel-uninstall  remove the panel indicator"
	@echo ""
	@echo "  vars: PYTHON=$(PYTHON) PREFIX=$(PREFIX) LOCKFILE=$(LOCKFILE)"
	@echo "        TRAYBACKEND=$(TRAYBACKEND) (indicator|floating|empty=auto)"

check:
	@$(PYTHON) -c 'import sys; assert sys.version_info >= (3,8), "python 3.8+ required"; print("python  :", sys.version.split()[0], "OK")'
	@$(PYTHON) -m py_compile $(SRC) && echo "compile : OK"
	@command -v systemctl >/dev/null 2>&1 && echo "systemd : present" || echo "systemd : MISSING (run the daemon manually)"
	@command -v xinput    >/dev/null 2>&1 && echo "xinput  : present" || echo "xinput  : missing (XTEST signal disabled)"
	@command -v gdbus     >/dev/null 2>&1 && echo "gdbus   : present" || echo "gdbus   : missing (desktop notifications fall back to notify-send)"
	@command -v loginctl  >/dev/null 2>&1 && echo "loginctl: present" || echo "loginctl: missing (session detection uses utmp only)"
	@$(PYTHON) -c 'import gi; gi.require_version("Gtk","3.0"); from gi.repository import Gtk' 2>/dev/null \
		&& echo "gtk3    : present (action window)" || echo "gtk3    : missing (action window disabled)"
	@$(PYTHON) -c 'import json; json.load(open("gnome-extension/metadata.json")); print("extmeta : OK")' 2>/dev/null \
		|| echo "extmeta : gnome-extension/metadata.json missing or invalid"
	@$(PYTHON) -c 'import importlib.util, sys; s=importlib.util.spec_from_file_location("vw", "$(SRC)"); m=importlib.util.module_from_spec(s); sys.argv=["vnc-watch"]; s.loader.exec_module(m); p=m.browser_config_ok(); print("browsers: OK") if not p else (print("browsers: FAIL " + "; ".join(p)) or sys.exit(1))'
	@test -r /var/run/utmp && echo "utmp    : readable" || echo "utmp    : not readable (login detection disabled)"
	@command -v loginctl >/dev/null 2>&1 && echo "ssh sess: loginctl present" || echo "ssh sess: loginctl missing (SSH session detection off)"
	@command -v ss       >/dev/null 2>&1 && echo "ssh conn: ss present" || echo "ssh conn: ss missing (SSH connection detection off)"
	@test -r /var/log/wtmp && echo "ssh wtmp: readable" || echo "ssh wtmp: not readable (remote-login history off)"
	@test -r /var/log/auth.log && echo "ssh auth: auth.log readable (login method visible)" || echo "ssh auth: auth.log not readable (needs adm; method/key not read)"

install: check units
	@mkdir -p "$(BINDIR)" "$(STATE)"
	@chmod 700 "$(STATE)"
	@ln -sfn "$(CURDIR)/$(SRC)" "$(LINK)"
	@echo "link    : $(LINK) -> $(CURDIR)/$(SRC)"
	@if command -v systemctl >/dev/null 2>&1; then \
		systemctl --user daemon-reload && \
		systemctl --user enable $(SERVICE) >/dev/null 2>&1; \
		systemctl --user restart $(SERVICE) && echo "service : started"; \
		systemctl --user disable --now $(TRAYSERVICE) >/dev/null 2>&1 || true; \
		echo "tray    : legacy, not started. For the top-panel dot run 'make panel-install'"; \
	else \
		echo "service : systemd not available, start with: $(LINK) watch --input-watch"; \
		echo "panel   : install the GNOME top-panel dot with 'make panel-install'"; \
	fi
	@$(MAKE) --no-print-directory status

# Generate the systemd user units from the templates. Split out so 'make update'
# can re-apply unit changes after a pull without redoing the whole install.
units:
	@mkdir -p "$(UNITDIR)"
	@sed -e 's|@PYTHON@|$(PYTHON)|g' \
	     -e 's|@EXEC@|$(LINK)|g' \
	     -e 's|@DOC@|$(CURDIR)/README.md|g' \
	     -e 's|@LOCKFILE@|$(LOCKFILE)|g' \
	     -e 's|@ALERTIDENTITY@|$(ALERTIDENTITY)|g' \
	     packaging/vnc-watch.service.in > "$(UNIT)"
	@echo "unit    : $(UNIT)"
	@sed -e 's|@PYTHON@|$(PYTHON)|g' \
	     -e 's|@EXEC@|$(LINK)|g' \
	     -e 's|@DOC@|$(CURDIR)/README.md|g' \
	     -e 's|@TRAYBACKEND@|$(TRAYBACKEND)|g' \
	     packaging/vnc-watch-tray.service.in > "$(TRAYUNIT)"
	@echo "unit    : $(TRAYUNIT)"

uninstall:
	@if command -v systemctl >/dev/null 2>&1; then \
		systemctl --user disable --now $(SERVICE) >/dev/null 2>&1 || true; \
		systemctl --user disable --now $(TRAYSERVICE) >/dev/null 2>&1 || true; \
	fi
	@rm -f "$(UNIT)" "$(TRAYUNIT)" "$(LINK)"
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
	@printf 'tray    : '; \
		if command -v systemctl >/dev/null 2>&1; then \
			systemctl --user is-active $(TRAYSERVICE) 2>/dev/null || echo "inactive"; \
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

# After 'git pull': the daemon runs the symlinked source, so the file on disk
# changes but the running process keeps the old code. This pulls the latest
# code, re-applies the systemd units, restarts the daemon and refreshes the
# panel indicator — one button, everything back on the new code.
update:
	@git pull --ff-only || { echo "update  : git pull failed; fix the tree, then run 'make reload'"; exit 1; }
	@$(MAKE) --no-print-directory reload

# Bring every running piece onto the current working tree: units, daemon, tray,
# panel. Safe to run any time; parts that are not installed are skipped.
reload: units
	@if command -v systemctl >/dev/null 2>&1; then \
		systemctl --user daemon-reload; \
		if systemctl --user is-active --quiet $(SERVICE); then \
			systemctl --user restart $(SERVICE) && echo "daemon  : restarted"; \
		else echo "daemon  : not active (start it with 'make start')"; fi; \
		systemctl --user try-restart $(TRAYSERVICE) >/dev/null 2>&1 || true; \
	else \
		echo "daemon  : systemd unavailable; restart '$(LINK) watch --input-watch' by hand"; \
	fi
	@sh packaging/install-panel.sh refresh

# Re-sync the installed panel extension from the repo and reload the shell only
# if the files actually changed. No-op when the panel was never installed.
panel-refresh:
	@sh packaging/install-panel.sh refresh

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

test-fixtures: test-ssh test-hardening
	@$(PYTHON) tests/test_browser_wipe.py

test-ssh:
	@$(PYTHON) tests/test_ssh_detect.py

test-hardening:
	@$(PYTHON) tests/test_hardening.py

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

ssh:
	@$(LINK) ssh

menu:
	@$(LINK) menu

tray:
	@$(LINK) tray $(ARGS)

tray-stop:
	@systemctl --user stop $(TRAYSERVICE) 2>/dev/null || pkill -f 'vnc-watch tray' || true

run:
	@$(LINK) watch --input-watch

panel-install:
	@sh packaging/install-panel.sh install

panel-uninstall:
	@sh packaging/install-panel.sh uninstall

panel-restart:
	@sh packaging/install-panel.sh restart

panel-status:
	@sh packaging/install-panel.sh status

clean:
	@rm -rf __pycache__
	@echo "cleaned"