#!/bin/sh
# vnc-watch top-panel indicator installer (per-user, no root).
#
# Puts a real GNOME top-panel button next to volume/battery by installing a
# small shell extension into a per-user directory that GNOME Shell treats as a
# *system* data dir. It never writes dconf, never edits a system file, and
# never needs root. See README "Top-panel indicator (Plan B)" for the why.
#
# Usage: install-panel.sh [install|uninstall|restart|status]
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
uuid=vnc-watch@local
xdg="${HOME}/.vnc-watch-xdg"
extdir="${xdg}/gnome-shell/extensions/${uuid}"
modedir="${xdg}/gnome-shell/modes"
unitdir="${HOME}/.config/systemd/user"
dropin="${unitdir}/org.gnome.Shell@x11.service.d"
mode_src=/usr/share/gnome-shell/modes/ubuntu.json

die() { echo "vnc-watch: $*" >&2; exit 1; }

# The base XDG_DATA_DIRS the running shell already has, so we only prepend.
shell_base_dirs() {
    shpid=$(pgrep -x gnome-shell | head -n1 || true)
    dirs=
    if [ -n "$shpid" ] && [ -r "/proc/${shpid}/environ" ]; then
        dirs=$(tr '\0' '\n' < "/proc/${shpid}/environ" \
               | sed -n 's/^XDG_DATA_DIRS=//p')
    fi
    [ -n "$dirs" ] || dirs="/usr/local/share/:/usr/share/:/var/lib/snapd/desktop"
    printf '%s' "$dirs"
}

do_install() {
    [ -r "$mode_src" ] || die "missing ${mode_src}; is this a GNOME box?"
    mkdir -p "$extdir" "$modedir" "$dropin"
    cp "${here}/gnome-extension/metadata.json" "$extdir/"
    cp "${here}/gnome-extension/extension.js" "$extdir/"

    # Mode file: the system 'ubuntu' mode with our UUID appended to the
    # session-mode extension list. Found first because our data dir is first
    # in XDG_DATA_DIRS.
    python3 - "$mode_src" "${modedir}/ubuntu.json" "$uuid" <<'PY'
import json, sys
src, dst, uuid = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src) as fh:
    mode = json.load(fh)
enabled = list(mode.get("enabledExtensions", []))
if uuid not in enabled:
    enabled.append(uuid)
mode["enabledExtensions"] = enabled
with open(dst, "w") as fh:
    json.dump(mode, fh, indent=4)
    fh.write("\n")
PY

    # Systemd user drop-in: give the shell our data dir, and treat a SIGTERM
    # exit as success so a forced reload never trips the "session failed"
    # screen (the unit is Restart=always + RefuseManualStop).
    base=$(shell_base_dirs)
    cat > "$dropin/override.conf" <<EOF
# Added by 'make panel-install' (vnc-watch). Lets GNOME Shell find the
# per-user top-panel indicator without root, dconf, or system files.
# Remove with 'make panel-uninstall'.
[Service]
Environment=XDG_DATA_DIRS=${xdg}:${base}
SuccessExitStatus=
SuccessExitStatus=1
SuccessExitStatus=SIGTERM
EOF

    echo "extension : ${extdir}"
    echo "mode file : ${modedir}/ubuntu.json"
    echo "drop-in   : ${dropin}/override.conf"
    echo
    echo "XDG_DATA_DIRS -> ${xdg}:${base}"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload
        echo
        echo "Run 'make panel-restart' to reload the shell into the new env."
    fi
}

do_restart() {
    command -v systemctl >/dev/null 2>&1 || die "systemd user session required"
    systemctl --user daemon-reload
    pid=$(systemctl --user show -p MainPID --value org.gnome.Shell@x11.service 2>/dev/null || true)
    [ -n "$pid" ] && [ "$pid" != 0 ] || pid=$(pgrep -x gnome-shell | head -n1 || true)
    [ -n "$pid" ] || die "cannot find the gnome-shell process"
    echo "restarting GNOME Shell (pid ${pid}); this redraws the panel."
    kill -TERM "$pid"
    # Wait for the new shell to own the bus name.
    i=0
    while [ "$i" -lt 40 ]; do
        if gdbus call --session --dest org.freedesktop.DBus \
             --object-path /org/freedesktop/DBus \
             --method org.freedesktop.DBus.NameHasOwner org.gnome.Shell \
             2>/dev/null | grep -q true; then
            sleep 1
            echo "shell back up; panel indicator should be visible."
            return 0
        fi
        i=$((i + 1)); sleep 0.5
    done
    die "shell did not come back within 20s; check 'systemctl --user status org.gnome.Shell@x11.service'"
}

do_uninstall() {
    rm -rf "$extdir"
    rm -f "${modedir}/ubuntu.json"
    rmdir "$modedir" 2>/dev/null || true
    rm -f "$dropin/override.conf"
    rmdir "$dropin" 2>/dev/null || true
    rm -rf "$xdg"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload
    fi
    echo "removed the panel extension, mode file, and shell drop-in"
    echo "restart the shell (or log out/in) to drop the panel button"
}

do_status() {
    printf 'extension : '; [ -f "$extdir/extension.js" ] && echo "$extdir" || echo "not installed"
    printf 'mode file : '; [ -f "$modedir/ubuntu.json" ] && echo "$modedir/ubuntu.json" || echo "not installed"
    printf 'drop-in   : '; [ -f "$dropin/override.conf" ] && echo "$dropin/override.conf" || echo "not installed"
    printf 'shell env : '; \
        if command -v systemctl >/dev/null 2>&1; then \
            systemctl --user show-environment 2>/dev/null | sed -n 's/^XDG_DATA_DIRS=//p' || true; \
        fi
}

case "${1:-install}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    restart)   do_restart ;;
    status)    do_status ;;
    *) die "usage: install-panel.sh [install|uninstall|restart|status]" ;;
esac
