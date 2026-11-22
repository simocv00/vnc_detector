#!/usr/bin/env python3
"""vnc-watch - unprivileged, best-effort remote-viewing detection for this session.

    vnc-watch watch    live detection (default)
    vnc-watch audit    classify every connection in the current x11vnc log
    vnc-watch portal   one-shot screencast / RDP / VNC status
    vnc-watch kick     close a running VNC server (confirmation required)
    vnc-watch lockdown close remote access and lock the screen
    vnc-watch xwatch   evict screen-capture tools on :0 (root included)
    vnc-watch channels remote alerts (Discord / Telegram / ntfy / WhatsApp)
    vnc-watch clear    delete browser + Discord data; --encrypt keeps an
                       AES-256 archive instead, --restore brings one back
    vnc-watch menu     read the daemon's state and offer manual actions
    vnc-watch tray     top-bar icon: white when idle, red when a viewer is
                       attached; click for quick actions (clear browser +
                       Discord data, kick, lock)

Flags kept as aliases for existing callers:
    --audit          same as `audit`
    --portal         same as `portal`
    --input-watch    `watch` plus XTEST injection watching
    --x-watch        `watch` plus X client count watching (noisy)
    --yes            with `kick`/`xwatch`: skip the interactive confirmation
    --dry-run        with `kick`/`xwatch`: report the target, change nothing
    --set KEY=VALUE  with `channels`: store one channel setting
    --test           with `channels`: send a test message

Out-of-band alerts are optional. Every alert (viewer, socket, new login,
action taken) is also pushed to each configured channel, so a copy of the log
survives off this machine. Configuration lives in channels.json (0600):
    discord_webhook   https://discord.com/api/webhooks/...
    telegram_token + telegram_chat
    ntfy_topic (+ optional ntfy_server)
    whatsapp_phone + whatsapp_apikey   (CallMeBot)
    webhook_url       any endpoint that accepts JSON

`kick` uses the X-Resource extension to map the VNC server's X client to its
PID and then calls XKillClient on it. That is an ordinary X operation available
to any client holding display :0 - no root and no exploit. It tears down the
whole VNC server (all viewers at once); X11 has no per-viewer kill primitive.

State directory: ~/.local/state/vnc-watch/   (created 0700; files 0600)
    vnc-watch.log        alert log
    xinput-xi2.log       raw XTEST event dump, capped at 2 MB
    xinput-xi2.log.err   why xinput exited, if it did
    state.json           daemon -> menu snapshot, written atomically
    ack.json             menu acknowledgements (bookkeeping only)
    tray-*.png           tray icon (generated on first run, 0600)

Confidence vocabulary - protocol evidence only, never "a human is watching":
    CONFIRMED RFB SESSION  "Pixel format" seen for that connection
    PROBABLE               RFB protocol version exchanged
    SUSPICIOUS             socket held >= 10 s with no protocol evidence
    INFO                   probe, instant connect/close, rejected websocket

Supporting-only signals that never change a tier: xdamage objects, x11vnc
client_count, X client count, CPU use, autorepeat flips, XTEST events.

Best-effort by construction: a root viewer can hide (`-quiet`, log truncation,
or bypassing VNC entirely). XGetImage grabs and /dev/fb0 reads are invisible
here, and XTEST injection cannot be attributed to a source. /proc/net/tcp uid
is the LOCAL socket owner (0 for x11vnc), never the remote user.
"""
import argparse
import ast
import collections
import ctypes
import errno
import fcntl
import hashlib
import hmac
import io
import json
import os
import queue
import re
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


def _env_num(name, default, cast):
    """Read a numeric env var without letting a typo kill the whole tool.

    A malformed `VNC_WATCH_*` value (``5M``, empty string, negative) must not
    raise at import time: that would disable audit, menu and watch alike. Fall
    back to the documented default and say so on stderr once.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = cast(raw.strip())
    except (TypeError, ValueError):
        sys.stderr.write(f"vnc-watch: invalid {name}={raw!r}; "
                         f"using default {default}\n")
        return default
    if isinstance(value, int) and value < 0:
        sys.stderr.write(f"vnc-watch: invalid negative {name}={raw!r}; "
                         f"using default {default}\n")
        return default
    return value


LOG = "/var/log/x11vnc.log"

BASE_STATE = os.path.expanduser("~/.local/state")
STATE_DIR = os.path.join(BASE_STATE, "vnc-watch")
ALERT_LOG = os.path.join(STATE_DIR, "vnc-watch.log")
XI_LOG = os.path.join(STATE_DIR, "xinput-xi2.log")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
ACK_FILE = os.path.join(STATE_DIR, "ack.json")

# Old loose locations, migrated into STATE_DIR on first run so history survives.
LEGACY_STATE = [
    (os.path.join(BASE_STATE, "vnc-watch.log"), ALERT_LOG),
    (os.path.join(BASE_STATE, "xinput-xi2.log"), XI_LOG),
    (os.path.join(BASE_STATE, "xinput-xi2.log.err"), XI_LOG + ".err"),
    (os.path.join(BASE_STATE, "vnc-watch.out"), os.path.join(STATE_DIR, "vnc-watch.out")),
]

WEAK_SECONDS = 10.0
REMOTE_PORTS = {3389, 5900, 5901, 5902, 5903, 11100}
# Overridable only so tests can exercise rotation without 2 MB of writes.
XI_LOG_MAX = _env_num("VNC_WATCH_XI_MAX", 2 * 1024 * 1024, int)
# The alert log is rotated once when it exceeds this, keeping one `.1` backup,
# so an unattended daemon cannot slowly fill a small home volume.
ALERT_LOG_MAX = _env_num("VNC_WATCH_LOG_MAX", 5 * 1024 * 1024, int)

REPLACE_ID = {"viewer": 4201, "socket": 4202, "xclients": 4203,
              "cpu": 4204, "xtest": 4205, "autorepeat": 4206, "port": 4207}
COOLDOWN = {"viewer": 0, "socket": 5, "xclients": 1800, "cpu": 1800,
            "xtest": 30, "autorepeat": 900, "port": 600,
            # SSH subsystem (separate kinds, never VNC/RDP tiers)
            "ssh-session": 0, "ssh-connection": 30, "ssh-command": 0,
            "ssh-x11vnc": 60, "ssh-daemon": 30, "ssh-history": 0,
            "ssh-keychange": 60}
# Kinds whose suppressed repeats are rare enough to keep an audit trail.
LOG_SUPPRESSED = {"socket", "viewer", "port", "autorepeat", "cpu",
                  "ssh-connection", "ssh-daemon"}

TS = re.compile(r"^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) (.*)$")
GOT = re.compile(r"Got connection from client (\S+)")
GONE = re.compile(r"Client (\S+) gone")
DEVLINE = re.compile(r"device: \d+ \((\d+)\)")

_last_alert = {}
_suppressed = collections.Counter()


# --------------------------------------------------------------- state files
def ensure_state_dir():
    """Create the state dir and migrate legacy loose files once.

    Never raises: on a full or unwritable volume the daemon must keep running
    (it degrades to in-memory detection plus stderr). Returns the list of
    (old, new) pairs that were moved.
    """
    moved = []
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        try:
            os.chmod(STATE_DIR, 0o700)
        except OSError:
            pass
    except OSError as exc:
        sys.stderr.write(f"vnc-watch: state dir unavailable ({exc}); "
                         f"continuing without persistence\n")
        return moved
    for old, new in LEGACY_STATE:
        if os.path.abspath(old) == os.path.abspath(new):
            continue
        if os.path.exists(old) and not os.path.exists(new):
            try:
                os.replace(old, new)
                moved.append((old, new))
            except OSError:
                pass
    return moved


def write_json_atomic(path, obj):
    """Write JSON as 0600 via a temp file + os.replace (no partial readers)."""
    tmp = f"{path}.tmp.{os.getpid()}"
    data = json.dumps(obj, indent=1, sort_keys=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(data + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        # Durability: fsync the directory so the rename survives a crash.
        # Best-effort; some filesystems reject directory fsync.
        try:
            dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


WATCH_LOCK = os.path.join(STATE_DIR, "watch.lock")


def acquire_watch_lock():
    """Take an exclusive lock for the live watcher.

    Two `vnc-watch watch` processes would double-alert and race on state.json.
    Returns (fd, None) on success or (None, reason) when another instance holds
    the lock. Does nothing on platforms without fcntl.flock (non-POSIX).
    """
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        fd = os.open(WATCH_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        # Full or unwritable volume: degrade to running unlocked rather than
        # refusing to watch at all. A warning is enough here.
        sys.stderr.write(f"vnc-watch: cannot open {WATCH_LOCK}: {exc}; "
                         f"running without the single-instance lock\n")
        return None, None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            os.close(fd)
            return None, "another vnc-watch watch is already running"
        # Filesystem without working locks: keep watching, just unlocked.
        sys.stderr.write(f"vnc-watch: flock unavailable ({exc}); "
                         f"running without the single-instance lock\n")
        return fd, None
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:
        pass
    return fd, None


def safe_size(path, default=0):
    """os.path.getsize that never raises (file may vanish between checks)."""
    try:
        return os.path.getsize(path)
    except OSError:
        return default


# ------------------------------------------------------------------- alerts
def log_alert(msg):
    """Append to the alert log. A write failure must never kill detection."""
    try:
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        try:
            if ALERT_LOG_MAX > 0 and os.path.getsize(ALERT_LOG) > ALERT_LOG_MAX:
                os.replace(ALERT_LOG, ALERT_LOG + ".1")
        except OSError:
            pass                       # missing file or rotation refused
        with open(ALERT_LOG, "a") as fh:
            fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {msg}\n")
    except OSError as exc:
        # stderr lands in the unit's journal; do not recurse into the log.
        sys.stderr.write(f"vnc-watch: log write failed: {exc}\n")


def notify(title, body, kind, urgent=True):
    """Notify via D-Bus: libnotify 0.7.9 here has no `-r`, so notify-send
    cannot set replaces_id and every call with it fails ('Unknown option -r')."""
    rid = REPLACE_ID.get(kind, 0)
    hints = "{\"urgency\": <byte %d>}" % (2 if urgent else 1)
    expire = 0 if kind == "viewer" else 8000
    cmd = ["gdbus", "call", "--session",
           "--dest", "org.freedesktop.Notifications",
           "--object-path", "/org/freedesktop/Notifications",
           "--method", "org.freedesktop.Notifications.Notify",
           "vnc-watch", str(rid), "", title, body, "[]", hints, str(expire)]
    if not shutil.which("gdbus"):
        cmd = ["notify-send", "-u", "critical" if urgent else "normal",
               "-t", str(expire), "-a", "vnc-watch", title, body]
    try:
        r = subprocess.run(cmd, timeout=3, capture_output=True, text=True)
        if r.returncode != 0:
            log_alert(f"(notify failed rc={r.returncode}: "
                      f"{(r.stderr or '').strip()[:120]})")
        elif r.stdout.strip():
            print(f"[notify] {kind} accepted: {r.stdout.strip()}", flush=True)
    except (OSError, subprocess.SubprocessError) as exc:
        log_alert(f"(notify failed: {exc})")
    sys.stdout.write("\a")
    sys.stdout.flush()


# ------------------------------------------------------- remote alerting
# Optional. Configure once with `vnc-watch channels --set key=value`.
# Credentials live in ~/.local/state/vnc-watch/channels.json (0600). Anything
# root-owned on this host can read them; that is unavoidable with local config.
CHANNELS_FILE = os.path.join(STATE_DIR, "channels.json")
CHANNEL_KEYS = ("discord_webhook", "telegram_token", "telegram_chat",
                "ntfy_topic", "ntfy_server", "whatsapp_phone",
                "whatsapp_apikey", "webhook_url")
_remote_q = queue.Queue(maxsize=100)
_remote_started = False


def load_channels():
    try:
        with open(CHANNELS_FILE) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(doc, dict):
        return {}
    return {k: v for k, v in doc.items() if isinstance(v, str) and v}


def save_channels(doc):
    """Persist channel config 0600. Returns False if the write failed."""
    ensure_state_dir()
    tmp = CHANNELS_FILE + f".tmp.{os.getpid()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, CHANNELS_FILE)
        return True
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        sys.stderr.write(f"vnc-watch: cannot write channels: {exc}\n")
        return False


def configured_channels(doc=None):
    doc = load_channels() if doc is None else doc
    out = []
    if doc.get("discord_webhook"):
        out.append("discord")
    if doc.get("telegram_token") and doc.get("telegram_chat"):
        out.append("telegram")
    if doc.get("ntfy_topic"):
        out.append("ntfy")
    if doc.get("whatsapp_phone") and doc.get("whatsapp_apikey"):
        out.append("whatsapp")
    if doc.get("webhook_url"):
        out.append("webhook")
    return out


def mask(value):
    value = str(value)
    return "..." + value[-4:] if len(value) > 4 else "set"


def _http(url, data=None, headers=None, timeout=8):
    hdrs = {"User-Agent": "vnc-watch/1.0"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2048).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, str(exc)


def _send_discord(doc, title, text):
    body = json.dumps({
        "username": "vnc-watch",
        "content": f"**{title}**\n{text}",
        "allowed_mentions": {"parse": []},
    }).encode()
    code, body_txt = _http(doc["discord_webhook"], body,
                           {"Content-Type": "application/json"})
    return 200 <= code < 300, f"http {code} {body_txt[:120]}"


def _send_telegram(doc, title, text):
    url = f"https://api.telegram.org/bot{doc['telegram_token']}/sendMessage"
    body = urllib.parse.urlencode({
        "chat_id": doc["telegram_chat"],
        "text": f"{title}\n{text}",
        "disable_web_page_preview": "true",
    }).encode()
    code, body_txt = _http(url, body,
                           {"Content-Type": "application/x-www-form-urlencoded"})
    return 200 <= code < 300, f"http {code} {body_txt[:120]}"


def _send_ntfy(doc, title, text):
    server = (doc.get("ntfy_server") or "https://ntfy.sh").rstrip("/")
    topic = urllib.parse.quote(doc["ntfy_topic"].strip("/"), safe="")
    ascii_title = title.encode("ascii", "replace").decode("ascii")
    code, body_txt = _http(f"{server}/{topic}", text.encode(), {
        "Title": ascii_title[:60],
        "Priority": "high",
        "Tags": "warning",
        "Content-Type": "text/plain; charset=utf-8",
    })
    return 200 <= code < 300, f"http {code} {body_txt[:120]}"


def _send_whatsapp(doc, title, text):
    query = urllib.parse.urlencode({
        "phone": doc["whatsapp_phone"],
        "text": f"{title}\n{text}",
        "apikey": doc["whatsapp_apikey"],
    })
    code, body_txt = _http("https://api.callmebot.com/whatsapp.php?" + query)
    return 200 <= code < 300, f"http {code} {body_txt[:120]}"


def _send_webhook(doc, title, text):
    body = json.dumps({
        "title": title, "text": text, "host": socket.gethostname(),
        "user": os.environ.get("USER") or str(os.getuid()),
        "time": datetime.now().isoformat(timespec="seconds"),
    }).encode()
    code, body_txt = _http(doc["webhook_url"], body,
                           {"Content-Type": "application/json"})
    return 200 <= code < 300, f"http {code} {body_txt[:120]}"


SENDERS = {"discord": _send_discord, "telegram": _send_telegram,
           "ntfy": _send_ntfy, "whatsapp": _send_whatsapp,
           "webhook": _send_webhook}


def deliver_all(title, text, verbose=False):
    doc = load_channels()
    names = configured_channels(doc)
    results = []
    for name in names:
        try:
            ok, info = SENDERS[name](doc, title, text)
        except Exception as exc:                # never let a sink break the rest
            ok, info = False, f"{type(exc).__name__}: {exc}"
        results.append((name, ok, info))
        if verbose:
            print(f"  {name:<9} {'ok' if ok else 'FAILED'}  {info}")
    return results


def _remote_worker():
    while True:
        title, text = _remote_q.get()
        for name, ok, info in deliver_all(title, text):
            log_alert(f"remote {name}: {'ok' if ok else 'failed: ' + info}")


def remote_alert(title, text):
    """Queue an out-of-band message. Never blocks; drops when the queue is full."""
    global _remote_started
    if not configured_channels():
        return False
    try:
        _remote_q.put_nowait((title, text))
    except queue.Full:
        log_alert("remote alert dropped: queue full")
        return False
    if not _remote_started:
        threading.Thread(target=_remote_worker, daemon=True).start()
        _remote_started = True
    return True


def remote_send_sync(title, text):
    """Send now and log each result. For short-lived CLI processes."""
    results = deliver_all(title, text)
    for name, ok, info in results:
        log_alert(f"remote {name}: {'ok' if ok else 'failed: ' + info}")
    return results


def remote_message(kind, msg):
    """Payload for an off-machine alert.

    Identifying fields (hostname, username) are omitted by default and kept
    local. Set VNC_WATCH_ALERT_IDENTITY=host,user to opt in explicitly; that
    is the only way they leave the machine, and no replacement identifier is
    added when the variable is unset.
    """
    ident = os.environ.get("VNC_WATCH_ALERT_IDENTITY", "").lower()
    fields = []
    if "host" in ident:
        fields.append(f"host: {socket.gethostname()}")
    if "user" in ident:
        fields.append(f"user: {os.environ.get('USER') or os.getuid()}")
    lines = [msg]
    if fields:
        lines.append("")
        lines.extend(fields)
    lines.append("")
    lines.append(f"time: {datetime.now():%Y-%m-%d %H:%M:%S %Z}")
    return (f"vnc-watch: {kind}", "\n".join(lines))


def channels_command(apply_sets=(), clears=(), test=False):
    doc = load_channels()
    changed = False
    for item in apply_sets or ():
        if "=" not in item:
            print(f"ignored (need KEY=VALUE): {item}")
            continue
        key, value = item.split("=", 1)
        key, value = key.strip(), value.strip()
        if key not in CHANNEL_KEYS:
            print(f"unknown key {key!r}; valid: {', '.join(CHANNEL_KEYS)}")
            continue
        if value:
            doc[key] = value
        else:
            doc.pop(key, None)
        changed = True
    for key in clears or ():
        if key in doc:
            doc.pop(key)
            changed = True
    if changed:
        if save_channels(doc):
            print(f"saved {CHANNELS_FILE} (0600)\n")
        else:
            print(f"could not write {CHANNELS_FILE}\n")
            return 1

    names = configured_channels(doc)
    print("== remote alerts ==\n")
    print("file     :", CHANNELS_FILE)
    print("channels :", ", ".join(names) or "none configured")
    if doc:
        for key in sorted(doc):
            print(f"  {key:<16} {mask(doc[key])}")
    if not names:
        print("\nSetup examples (pick one, run the command, then --test):")
        print("  vnc-watch channels --set ntfy_topic=my-secret-topic-9f2a")
        print("  vnc-watch channels --set discord_webhook=https://discord.com/api/webhooks/...")
        print("  vnc-watch channels --set telegram_token=123:ABC --set telegram_chat=12345678")
        print("  vnc-watch channels --set whatsapp_phone=+15551234567 --set whatsapp_apikey=123456")
    if test:
        if not names:
            print("\nnothing to test")
            return 1
        print("\nsending test message ...")
        results = deliver_all("vnc-watch test",
                              f"test from {socket.gethostname()}")
        print()
        for name, ok, info in results:
            print(f"  {name:<9} {'ok' if ok else 'FAILED'}  {info}")
        return 0 if all(ok for _, ok, _ in results) else 2
    print()
    return 0


def alert(kind, msg, urgent=True, key=None):
    """Log always; notify at most once per cooldown window."""
    key = key or kind
    now = time.monotonic()
    if now - _last_alert.get(key, 0.0) < COOLDOWN.get(kind, 60):
        _suppressed[key] += 1
        if kind in LOG_SUPPRESSED:
            log_alert(f"(suppressed) {msg}")
        return
    n = _suppressed.pop(key, 0)
    _last_alert[key] = now
    if n:
        msg = f"{msg} ({n} similar suppressed since last alert)"
    log_alert(msg)
    notify("VNC watch", msg, kind, urgent)
    title, body = remote_message(kind, msg)
    remote_alert(title, body)


# ----------------------------------------------------------------- log tail
class Tail:
    """Poll-based tailer that survives rotation, truncation and permission loss.

    Every filesystem call is guarded: a log that disappears, is replaced by a
    directory, or becomes unreadable mid-run must never take the watcher down.
    A partial line without a newline is bounded, so a hostile or corrupt file
    cannot grow memory without limit.
    """

    MAX_PARTIAL = 1 << 20                  # 1 MiB of a single unterminated line

    def __init__(self, path, from_end=True):
        self.path = path
        self.fh = None
        self.key = None
        self.buf = b""
        self._open(from_end)

    def _open(self, from_end):
        fh = open(self.path, "rb")
        try:
            st = os.fstat(fh.fileno())
        except OSError:
            fh.close()
            raise
        self.fh = fh
        self.key = (st.st_dev, st.st_ino)
        if from_end:
            fh.seek(0, os.SEEK_END)
        self.buf = b""

    def _reopen(self, from_end):
        """Reopen after a rotation; returns False instead of raising."""
        try:
            self._open(from_end)
            return True
        except OSError:
            self.fh = None
            self.key = None
            return False

    def readlines(self):
        try:
            st = os.stat(self.path)
        except OSError:
            if self.fh is None:
                self._reopen(True)
            return []                      # briefly missing mid-rotation
        if self.fh is None:
            self._reopen(True)
            return []
        if (st.st_dev, st.st_ino) != self.key:
            try:
                old = self._read()         # finish the old inode first
            except OSError:
                old = []
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None
            if not self._reopen(False):    # new file from the beginning
                return old
            return old + self._read()
        try:
            if st.st_size < self.fh.tell():    # truncated in place
                self.fh.seek(0)
                self.buf = b""
            return self._read()
        except OSError:
            self.fh = None
            self.key = None
            return []

    def _read(self):
        data = self.fh.read()
        if not data:
            return []
        self.buf += data
        *done, self.buf = self.buf.split(b"\n")   # keep the partial tail
        if len(self.buf) > self.MAX_PARTIAL:
            # One enormous unterminated line: keep the tail so memory stays
            # bounded instead of buffering the whole file.
            self.buf = self.buf[-self.MAX_PARTIAL:]
        return [line.decode("utf-8", "replace") for line in done]

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None


# -------------------------------------------------------------- log parsing
def parse_line(line):
    m = TS.match(line)
    if not m:
        return None
    stamp, rest = m.group(1), m.group(2)
    low = rest.lower()
    if GOT.search(rest):
        return stamp, "got", GOT.search(rest).group(1)
    if GONE.search(rest):
        return stamp, "gone", GONE.search(rest).group(1)
    if "pixel format" in low:
        return stamp, "strong", rest.strip()
    if "client protocol version" in low:
        return stamp, "medium", rest.strip()
    if "normal socket connection" in low:
        return stamp, "normal", rest.strip()
    if "websockets handshake" in low:
        return stamp, "ws", rest.strip()
    return None


def new_conn(peer, stamp, port=None, source="log"):
    return {"peer": peer, "port": port, "source": source, "start": stamp,
            "mono": time.monotonic(), "strong": False, "medium": False,
            "normal": False, "ws": False, "closed": False, "end": None,
            "dur": 0.0, "correlated": True}


def open_target(conns):
    """Pick the connection a peerless log line belongs to.

    x11vnc logs handshake lines without an address, so attribution is only
    possible when exactly one peer has a connection open. Then the oldest open
    connection for that peer is used. Otherwise nothing is guessed: the caller
    reports the event as uncorrelated.
    """
    by_peer = {}
    for c in conns:
        if not c.get("closed"):
            by_peer.setdefault(c["peer"], []).append(c)
    if len(by_peer) == 1:
        peer = next(iter(by_peer))
        return by_peer[peer][0], peer
    return None, None


def close_conn(conns, peer):
    """Close the oldest open connection for `peer` (FIFO accept order)."""
    for c in conns:
        if not c.get("closed") and c["peer"] == peer:
            c["closed"] = True
            return c
    return None


def tier(c):
    if c["strong"]:
        return "CONFIRMED RFB SESSION", "RFB handshake completed (Pixel format seen)"
    if c["medium"]:
        return "PROBABLE", "RFB protocol version exchanged, no handshake"
    if c["normal"] and c["dur"] >= WEAK_SECONDS:
        return "SUSPICIOUS", f"held socket {c['dur']:.0f}s, no protocol evidence"
    return "INFO", "probe or instant connect/close"


# -------------------------------------------------------------------- audit
def audit():
    ensure_state_dir()
    try:
        fh = open(LOG, errors="replace")
    except OSError as exc:
        print(f"cannot read {LOG}: {exc}")
        return 1

    # Stream the file: a large or growing log must not be loaded into memory
    # whole, especially on a nearly full home volume.
    conns, uncorrelated = [], []
    with fh:
        for line in fh:
            ev = parse_line(line)
            if not ev:
                continue
            stamp, kind, payload = ev
            if kind == "got":
                conns.append(new_conn(payload, stamp))
            elif kind == "gone":
                c = close_conn(conns, payload)
                if c:
                    c["end"] = stamp
            elif kind in ("strong", "medium", "normal", "ws"):
                c, _ = open_target(conns)
                if c is None:
                    uncorrelated.append((stamp, kind, payload))
                else:
                    c[kind] = True

    if not conns:
        print("No connections recorded in the current x11vnc log.")
        ssh_audit_section()
        return 0

    fmt = "%d/%m/%Y %H:%M:%S"
    for c in conns:
        try:
            t0 = datetime.strptime(c["start"], fmt)
            t1 = datetime.strptime(c["end"], fmt) if c["end"] else datetime.now()
            c["dur"] = (t1 - t0).total_seconds()
        except ValueError:
            c["dur"] = 0.0

    print(f"{'START':<21} {'PEER':<18} {'DUR':>7}  {'TIER':<22} VERDICT")
    print("-" * 96)
    counts = collections.Counter()
    for c in conns:
        t, verdict = tier(c)
        counts[t] += 1
        if t == "INFO" and c["ws"]:
            verdict = "probe (websocket handshake rejected)"
        print(f"{c['start']:<21} {c['peer']:<18} {c['dur']:7.1f}s  {t:<22} {verdict}")
    print("-" * 96)
    print(f"{len(conns)} connection(s): "
          f"{counts['CONFIRMED RFB SESSION']} confirmed, "
          f"{counts['PROBABLE']} probable, "
          f"{counts['SUSPICIOUS']} suspicious, {counts['INFO']} info")

    if uncorrelated:
        print(f"\n{len(uncorrelated)} uncorrelated protocol event(s): more than one "
              f"connection was open and the log carries no address for them, so "
              f"no connection was promoted:")
        for stamp, kind, payload in uncorrelated:
            print(f"  {stamp}  {kind}: {payload[:70]}")
    ssh_audit_section()
    return 0


# ------------------------------------------------------------------- probes
def norm_addr(addr):
    """'[::ffff:10.1.2.3]:5555' -> ('10.1.2.3', '5555')."""
    host, _, port = addr.rpartition(":")
    host = host.strip("[]")
    if host.lower().startswith("::ffff:") and "." in host:
        host = host[7:]
    return host, port


def socket_peers():
    """Established inbound connections to any watched service port."""
    try:
        out = subprocess.run(["ss", "-H", "-tn", "state", "established"],
                             capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None                        # unavailable, not "none"
    peers = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:                     # Recv-Q Send-Q Local Peer
            continue
        try:
            lport = int(p[2].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if lport in REMOTE_PORTS:
            host, rport = norm_addr(p[3])
            peers.append((lport, host, rport))
    return peers


def listening_ports():
    try:
        out = subprocess.run(["ss", "-H", "-tln"], capture_output=True,
                             text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    ports = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4:
            m = re.search(r":(\d+)$", p[3])
            if m:
                ports.add(int(m.group(1)))
    return ports


def x11vnc_pid():
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    with open(f"/proc/{pid}/comm") as fh:
                        if fh.read().strip() == "x11vnc":
                            return int(pid)
                except OSError:
                    pass
    except OSError:
        pass
    return None


# ---------------------------------------------------- closing a VNC server
# X-Resource 1.2 reports, per X client, an opaque ID blob per requested mask.
# Bit 1 (value 2) is the PID; bit 0 is unused by this server, hence the mask.
XRES_PID_MASK = 2
VNC_SERVER_COMMS = {"x11vnc", "Xvnc", "Xtightvnc", "Xvnc4",
                    "vino-server", "wayvnc", "krfb"}
# Optional path to a seat-lock state file (JSON) used by the exam/lock guard.
# Empty by default: without it the guard is inert. Set it for your machine
# with VNC_WATCH_LOCK_FILE, e.g. Environment= in the systemd user unit.
POLICY_FILE = os.environ.get("VNC_WATCH_LOCK_FILE", "")


class _XResClient(ctypes.Structure):
    _fields_ = [("resource_base", ctypes.c_ulong),
                ("resource_mask", ctypes.c_ulong)]


class _XResSpec(ctypes.Structure):
    _fields_ = [("client", ctypes.c_ulong), ("mask", ctypes.c_long)]


class _XResIdValue(ctypes.Structure):
    _fields_ = [("spec", _XResSpec), ("length", ctypes.c_long),
                ("value", ctypes.c_void_p)]


def _x_libs():
    try:
        X = ctypes.CDLL("libX11.so.6")
        R = ctypes.CDLL("libXRes.so.1")
    except OSError as exc:
        raise RuntimeError(f"X libraries unavailable: {exc}")
    X.XOpenDisplay.restype = ctypes.c_void_p
    X.XOpenDisplay.argtypes = [ctypes.c_char_p]
    X.XKillClient.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    X.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
    X.XCloseDisplay.argtypes = [ctypes.c_void_p]
    return X, R


def x_clients_with_pids():
    """[(x_client_base, pid)] for every X client, via X-Resource 1.2.

    Raises RuntimeError with a human-readable reason when the extension or the
    display is unavailable, so callers can report "unavailable" instead of
    silently finding nothing.
    """
    X, R = _x_libs()
    R.XResQueryClients.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                   ctypes.POINTER(ctypes.POINTER(_XResClient))]
    R.XResQueryClientIds.argtypes = [ctypes.c_void_p, ctypes.c_long,
                                     ctypes.POINTER(_XResSpec),
                                     ctypes.POINTER(ctypes.c_long),
                                     ctypes.POINTER(ctypes.POINTER(_XResIdValue))]
    d = ctypes.c_void_p(X.XOpenDisplay(None))
    if not d.value:
        raise RuntimeError("cannot open X display :0")
    try:
        maj, mnr = ctypes.c_int(), ctypes.c_int()
        if not R.XResQueryVersion(d, ctypes.byref(maj), ctypes.byref(mnr)):
            raise RuntimeError("X server has no X-Resource extension")
        n = ctypes.c_int(0)
        cl = ctypes.POINTER(_XResClient)()
        if not R.XResQueryClients(d, ctypes.byref(n), ctypes.byref(cl)):
            raise RuntimeError("XResQueryClients was refused")
        out = []
        for i in range(n.value):
            base = cl[i].resource_base
            spec = _XResSpec(client=base, mask=XRES_PID_MASK)
            cnt = ctypes.c_long(0)
            ids = ctypes.POINTER(_XResIdValue)()
            # libXRes returns 0 here even on success; trust the reply count.
            R.XResQueryClientIds(d, 1, ctypes.byref(spec),
                                 ctypes.byref(cnt), ctypes.byref(ids))
            pid = None
            for j in range(cnt.value):
                v = ids[j]
                if v.value and v.length >= 4:
                    pid = int.from_bytes(
                        ctypes.string_at(v.value, 4), "little")
            out.append((base, pid))
        return out
    finally:
        X.XCloseDisplay(d)


def kill_x_client(base):
    """Drop one X client's server connection. Returns True if the request sent."""
    X, _ = _x_libs()
    d = ctypes.c_void_p(X.XOpenDisplay(None))
    if not d.value:
        return False
    try:
        X.XKillClient(d, ctypes.c_ulong(base))
        X.XSync(d, 0)
        return True
    finally:
        X.XCloseDisplay(d)


def proc_state(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(") ", 1)[1].split()[0]
    except (OSError, IndexError):
        return None


def proc_dead(pid):
    """True once the process has exited or is a zombie awaiting its parent."""
    return proc_state(pid) in (None, "Z", "X")


def proc_uid(pid):
    """Owning uid of a pid, or None. The Uid line in /proc/<pid>/status is
    world-readable, so another user's X client is still attributable."""
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def proc_comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as fh:
            return fh.read().strip()
    except OSError:
        return "?"


# Tier 1: the comm name alone identifies a dedicated viewer or grabber.
# Targeted by identity, not uid: the viewer we care about is a root-run
# x11vnc, and a uid-0 exemption would skip it.
DIRECT_COMMS = frozenset({
    "x11vnc", "xvnc", "xtightvnc", "x0vncserver", "vncserver", "vino-server",
    "gnome-remote-de", "xwd", "scrot", "import", "maim", "flameshot",
    "gnome-screenshot", "spectacle", "recordmydesktop", "kazam", "peek",
    "byzanz", "obs",
})
# Prefix matches for names the 15-char truncation or version suffix splits.
DIRECT_PREFIXES = ("xfce4-screensho", "simplescreenrec", "gnome-remote")
# Tier 2: general multimedia tools. A capture only when argv names a display
# grab; a plain transcode/playback is a candidate, never evicted on its name.
AMBIGUOUS_COMMS = frozenset({"ffmpeg", "ffplay", "ffprobe"})
AMBIGUOUS_PREFIXES = ("gst-launch",)
GRAB_TOKENS = ("x11grab", "ximagesrc", "xdisplay")
# Processes that must never be killed even if a name collides. lightdm is the
# uid-0 session manager; killing it ends the session you are protecting.
PROTECTED_COMMS = frozenset({"lightdm", "Xorg", "gnome-shell"})


def exempt_uids():
    """Uids whose X clients are never evicted. Only this user by default -
    root is NOT exempt, because the viewer we hunt runs as root. Extend with
    VNC_WATCH_X_EXEMPT_UIDS. VNC_WATCH_X_EVICT_SELF=1 drops even this user."""
    keep = set()
    if os.environ.get("VNC_WATCH_X_EVICT_SELF", "") not in ("1", "yes", "true"):
        keep.add(os.getuid())
    raw = os.environ.get("VNC_WATCH_X_EXEMPT_UIDS", "")
    for tok in raw.replace(",", " ").split():
        try:
            keep.add(int(tok))
        except ValueError:
            pass
    return keep


def exempt_comms():
    """Extra comm names to never target, from VNC_WATCH_X_EXEMPT_COMMS."""
    raw = os.environ.get("VNC_WATCH_X_EXEMPT_COMMS", "")
    return PROTECTED_COMMS | {t for t in raw.replace(",", " ").split() if t}


def proc_cmdline(pid):
    """argv of a pid, or [] when unreadable. Used only to corroborate an
    ambiguous multimedia tool; it never identifies a target on its own."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return [a.decode("utf-8", "replace")
                    for a in fh.read().split(b"\0") if a]
    except OSError:
        return []


def capture_kind(comm, pid):
    """Classify a process name for screen capture.

    'direct'       - comm alone identifies a viewer/grabber
    'corroborated' - ambiguous multimedia tool with a display grab in argv
    'candidate'    - ambiguous multimedia tool, no display grab (not evicted)
    None           - not a capture tool

    A name match is a candidate, never proof of active viewing.
    """
    c = (comm or "").lower()
    if c in DIRECT_COMMS or any(c.startswith(p) for p in DIRECT_PREFIXES):
        return "direct"
    if c in AMBIGUOUS_COMMS or any(c.startswith(p) for p in AMBIGUOUS_PREFIXES):
        blob = " ".join(proc_cmdline(pid)).lower()
        return ("corroborated" if any(t in blob for t in GRAB_TOKENS)
                else "candidate")
    return None


def x_client_inventory():
    """[{base,pid,uid,comm,candidate,target,why}] for every X client on :0.

    `candidate` is True when the process matches a capture signature (name, or
    name plus argv for ambiguous multimedia tools); it is NOT proof of active
    viewing. `target` is True only for a candidate that also passes the
    protected-name and exempt-uid filters. pid None is never a target.
    """
    keep = exempt_uids()
    safe = exempt_comms()
    out = []
    for base, pid in x_clients_with_pids():
        if pid is None:
            out.append({"base": base, "pid": None, "uid": None, "comm": "?",
                        "candidate": False, "target": False,
                        "why": "unmapped"})
            continue
        uid = proc_uid(pid)
        comm = proc_comm(pid)
        kind = capture_kind(comm, pid)
        cand = kind is not None
        if kind is None:
            why, tgt = "not a capture tool", False
        elif comm in safe:
            why, tgt = "protected", False
        elif uid is not None and uid in keep:
            why, tgt = "exempt uid", False
        elif kind == "candidate":
            why, tgt = "multimedia name, no display-grab in argv", False
        elif kind == "corroborated":
            why, tgt = "display-grab in argv, uid not exempt", True
        else:
            why, tgt = "capture tool, uid not exempt", True
        out.append({"base": base, "pid": pid, "uid": uid, "comm": comm,
                    "candidate": cand, "target": tgt, "why": why})
    return out


def current_pid_for_base(base):
    """Fresh XRes lookup for one resource base, or None if the base is gone or
    unmappable. Used to revalidate a target immediately before XKillClient,
    because the original base->pid binding may have been recycled since the
    listing."""
    for b, pid in x_clients_with_pids():
        if b == base:
            return pid
    return None


def _target_line(c, outcome):
    uid = "-" if c["uid"] is None else c["uid"]
    pid = "-" if c["pid"] is None else c["pid"]
    return f"pid={pid} uid={uid} comm={c['comm']} -> {outcome}"


def xwatch_event_body(result, target_lines, survivors, notes, lock_note=None):
    """Multi-line body for the off-machine xwatch event.

    Counters are DERIVED from `target_lines`, the single source of truth, so
    the reported evicted/skipped/errors totals can never disagree with the
    per-target outcomes listed in the same message.

      evicted  -> the outcome line ends in "-> evicted"
      skipped  -> the outcome line contains "-> skipped"
      errors   -> every other intended target (kill raised / not sent)

    A *skip* is safe race-avoidance: the base->pid binding changed before the
    kill, so we refused to kill a recycled resource (an identity change, not a
    failure). An *error* is operational: the kill was attempted and failed or
    was not sent. They are counted and listed separately.

    `result` ("all connections dropped" / "partial" / "no eviction" /
    "refused (...)") is computed by the caller and echoed verbatim. The body
    does NOT carry argv/cmdline or filesystem paths.
    """
    evicted = sum(1 for t in target_lines if t.endswith("-> evicted"))
    skipped = sum(1 for t in target_lines if "-> skipped" in t)
    errors = len(target_lines) - evicted - skipped
    lines = ["event: xwatch", "action: evict capture-tool candidates",
             f"result: {result}", f"targets: {len(target_lines)}",
             f"evicted: {evicted}", f"skipped: {skipped}", f"errors: {errors}"]
    if lock_note:
        lines.append(f"lock: {lock_note}")
    if target_lines:
        lines.append("details:")
        lines.extend("  " + t for t in target_lines[:20])
    lines.append(f"survivors: {survivors}")
    if notes:
        lines.append("notes:")
        lines.extend("  " + n for n in notes[:10])
    return "\n".join(lines)


def xwatch_command(apply=False, assume_yes=False):
    """Evict X clients that are capture-tool candidates.

    A candidate is a process whose comm (and, for ambiguous multimedia tools,
    argv) matches a screen-capture signature; a match is NOT proof of active
    viewing. `target` additionally requires a non-exempt uid (root counts) and
    a name not on the protected list.

    Identity is revalidated immediately before every XKillClient: the current
    base->pid mapping must still equal the original target and its comm must be
    unchanged, or the kill is skipped. This narrows, but cannot close, the
    race: the fresh lookup and the kill are separate X round-trips, so a client
    can still exit and free its base in the gap. See the README.

    Eviction is refused while an exam/lock window is active, for normal, menu,
    and --yes invocation alike. No automatic or loop eviction exists.
    """
    print("\n== X clients on :0 (capture-tool candidates) ==\n")
    try:
        inv = x_client_inventory()
    except RuntimeError as exc:
        print(f"  detection unavailable: {exc}")
        return 1
    for c in sorted(inv, key=lambda r: (not r["target"],
                                        r["uid"] if r["uid"] is not None else -1,
                                        r["pid"] or 0)):
        tag = "EVICT?" if c["target"] else ("cand" if c["candidate"] else "ok")
        uid = "-" if c["uid"] is None else str(c["uid"])
        pid = "-" if c["pid"] is None else str(c["pid"])
        print(f"  {tag:<7} base=0x{c['base']:<9x} pid={pid:<8} "
              f"uid={uid:<7} {c['comm']:<16} {c['why']}")
    targets = [c for c in inv if c["target"]]
    cands = [c for c in inv if c["candidate"]]
    print(f"\n  {len(inv)} X client(s); {len(cands)} candidate(s); "
          f"{len(targets)} would be evicted")
    print("  A candidate is a signature match, not proof of active viewing.")
    if not targets:
        print("  nothing to evict\n")
        return 0

    locked, why = active_lock_window()
    if locked:
        print(f"\n  note   : lock window active ({why}); eviction disabled")
    if apply and locked:
        print(f"\n  refused: {why}. Eviction is disabled during an "
              f"exam/lock window.\n")
        log_alert(f"action=xwatch outcome=refused-lock ({why})")
        remote_send_sync(*remote_message(
            "action",
            xwatch_event_body("refused (exam/lock window; no eviction)",
                              [], 0, [], "exam/lock window active")))
        return 1

    print("\n  root is NOT exempt: a root-run viewer is the point. Eviction")
    print("  drops the candidate's connection to :0; its service may restart it.")
    if not apply:
        print("\n  dry run: nothing changed\n")
        return 0
    if not assume_yes and not confirm("Evict these capture-tool candidates now?"):
        print("cancelled\n")
        log_alert("action=xwatch outcome=cancelled")
        return 1

    killed, target_lines, notes = [], [], []
    skipped = 0            # safe identity-change skips (race avoidance)
    errors = 0             # operational failures (kill raised / not sent)
    for c in targets:
        fresh = current_pid_for_base(c["base"])
        outcome = None
        if fresh is None:
            outcome = "skipped (base gone before kill)"
        elif fresh != c["pid"]:
            outcome = f"skipped (identity changed, now pid {fresh})"
        elif proc_comm(fresh) != c["comm"]:
            outcome = "skipped (comm changed)"
        if outcome:
            notes.append(f"skip base 0x{c['base']:x}: {outcome}")
            target_lines.append(_target_line(c, outcome))
            skipped += 1
            continue
        try:
            sent = kill_x_client(c["base"])
        except RuntimeError as exc:
            notes.append(f"error base 0x{c['base']:x}: {exc}")
            target_lines.append(_target_line(c, "error"))
            errors += 1
            continue
        if sent:
            killed.append(c)
            target_lines.append(_target_line(c, "evicted"))
        else:
            notes.append(f"error base 0x{c['base']:x}: XKillClient not sent")
            target_lines.append(_target_line(c, "not sent"))
            errors += 1

    # Verify by pid, not base: resource bases are recycled, so a killed base
    # 0xNN can reappear for a different client. A kill succeeded when the pid
    # no longer maps to any X connection; if it still does it either held a
    # second connection or reconnected.
    time.sleep(0.3)
    try:
        still_connected = {p for _b, p in x_clients_with_pids()}
    except RuntimeError:
        still_connected = set()
    survivor_pids = {c["pid"] for c in killed
                     if c["pid"] is not None and c["pid"] in still_connected}
    survivors = [c for c in killed if c["pid"] in survivor_pids]
    # Full success requires EVERY intended target evicted by us and none
    # surviving. Any skip (target already gone / base recycled) or error leaves
    # the run short of full, so it must never read "all connections dropped".
    all_dropped = (bool(targets) and len(killed) == len(targets)
                   and not survivor_pids)
    if all_dropped:
        result = "all connections dropped"
    elif killed:
        result = "partial"
    else:
        result = "no eviction"

    for c in killed:
        print(f"  evicted: pid {c['pid']} uid {c['uid']} {c['comm']}")
    for n in notes:
        print(f"  {'skip' if n.startswith('skip ') else 'error'}   : {n}")
    for c in survivors:
        print(f"  note   : pid {c['pid']} still has an X connection "
              f"(held another or reconnected)")
    print(f"  result : {result} "
          f"(evicted={len(killed)} skipped={skipped} errors={errors} "
          f"survivors={len(survivors)})\n")
    log_alert(f"action=xwatch evicted={len(killed)} skipped={skipped} "
              f"survivors={len(survivors)} errors={errors}")
    remote_send_sync(*remote_message(
        "action",
        xwatch_event_body(result, target_lines, len(survivors), notes)))
    return 0 if all_dropped else 2


def vnc_servers():
    """[{pid, comm, base}] for running VNC servers we can attribute.

    `base` is None when no X client maps to that PID (server may be gone or
    the mapping may be unavailable).
    """
    comms = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError as exc:
        raise RuntimeError(f"cannot scan /proc: {exc}")
    for pid in pids:
        try:
            with open(f"/proc/{pid}/comm") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if comm in VNC_SERVER_COMMS:
            comms[int(pid)] = comm
    if not comms:
        return []
    try:
        mapping = x_clients_with_pids()
    except RuntimeError:
        mapping = []
    by_pid = {}
    for base, pid in mapping:
        if pid in comms and pid not in by_pid:
            by_pid[pid] = base
    return [{"pid": pid, "comm": comm, "base": by_pid.get(pid)}
            for pid, comm in sorted(comms.items())]


def _load_seat_state():
    """Parse the seat-state JSON named by VNC_WATCH_LOCK_FILE.

    Returns (doc, reason). `doc` is the parsed JSON object, or None when the
    state cannot be used: no path configured, file missing or unreadable,
    malformed JSON, or not a JSON object. `reason` explains the None case.

    This is the single parser for the seat-state file, shared by the detection
    guard (`active_lock_window`) and the lock-action verifier (`_locked_now`),
    so both read the same file the same way.
    """
    if not POLICY_FILE:
        return None, "VNC_WATCH_LOCK_FILE is not configured"
    try:
        with open(POLICY_FILE) as fh:
            doc = json.load(fh)
    except OSError as exc:
        return None, f"seat state unreadable ({type(exc).__name__})"
    except ValueError:
        return None, "seat state malformed (invalid JSON)"
    if not isinstance(doc, dict):
        return None, "seat state malformed (not a JSON object)"
    return doc, ""


def _locked_now():
    """Authoritative lock state for verifying a lock action, as (state, detail).

    Reads only the `locked` field, deliberately ignoring `intervals` (those
    describe scheduled lock windows, not whether a lock request took effect).
    `state` is True for the literal JSON true, False for an explicit false or a
    missing field, and None when the state file cannot be read — so "unlocked"
    is never confused with "cannot verify".
    """
    doc, why = _load_seat_state()
    if doc is None:
        return None, why
    return doc.get("locked") is True, f"locked={doc.get('locked')!r}"


def active_lock_window():
    """(True, reason) if a seat controller reports an active lock.

    Reads the file named by VNC_WATCH_LOCK_FILE (POLICY_FILE), if any. It is
    expected to be JSON describing the seat, not the account, so it applies to
    whoever is logged in at :0. With no path configured, an unreadable file or
    malformed content, the state is "unknown" and treated as not active.
    """
    doc, _why = _load_seat_state()
    if doc is None:
        return False, "lock state unavailable"
    if doc.get("locked") is True:
        return True, f"seat locked by {doc.get('username') or doc.get('session')}"
    now = time.time()
    for span in doc.get("intervals") or []:
        try:
            start, end = float(span[0]), float(span[1])
        except (TypeError, IndexError, ValueError):
            continue
        if start <= now <= end:
            return True, "inside a campus lock interval"
    return False, "no active lock window"


def listening_on(port):
    ports = listening_ports()
    return None if ports is None else port in ports


def close_vnc(apply=False):
    """Find a running VNC server and, if `apply`, end it via XKillClient.

    Returns a dict describing what was found and done. Never fires unless
    `apply` is true. Refuses while a campus lock/exam window is active.
    """
    found = []
    notes = []
    try:
        servers = vnc_servers()
    except RuntimeError as exc:
        return {"found": [], "killed": [], "verified": False,
                "notes": [f"detection unavailable: {exc}"]}
    if not servers:
        return {"found": [], "killed": [], "verified": False,
                "notes": ["no VNC server process (x11vnc/Xvnc/vino-server) "
                          "is running"]}
    locked, why = active_lock_window()
    if apply and locked:
        return {"found": servers, "killed": [], "verified": False,
                "notes": [f"refused: {why}"]}
    for s in servers:
        if s["base"] is None:
            notes.append(f"pid {s['pid']} ({s['comm']}): no X client maps to "
                         f"this PID; cannot address it with XKillClient")
        found.append(s)
    if not apply:
        return {"found": found, "killed": [], "verified": False,
                "notes": notes + ["dry run: nothing changed"]}

    killed = []
    for s in found:
        if s["base"] is None:
            continue
        try:
            sent = kill_x_client(s["base"])
        except RuntimeError as exc:
            notes.append(f"pid {s['pid']}: {exc}")
            continue
        if not sent:
            notes.append(f"pid {s['pid']}: XKillClient could not be sent")
            continue
        killed.append(s)

    # Give the server a moment to notice the dead display and exit.
    deadline = time.time() + 5
    while time.time() < deadline and any(
            not proc_dead(s["pid"]) for s in killed):
        time.sleep(0.1)

    verified = bool(killed) and all(proc_dead(s["pid"]) for s in killed)
    survivors = [s for s in killed if not proc_dead(s["pid"])]
    for s in survivors:
        notes.append(f"pid {s['pid']} ({s['comm']}) still alive after "
                     f"XKillClient; it may reconnect to :0")
    ports = sorted(p for p in REMOTE_PORTS if listening_on(p))
    if ports:
        notes.append("still listening: " + ", ".join(f":{p}" for p in ports))
    return {"found": found, "killed": killed, "verified": verified,
            "notes": notes}


def format_close_result(res):
    lines = []
    for s in res["found"]:
        base = "unmapped" if s["base"] is None else f"x-client 0x{s['base']:x}"
        lines.append(f"  found : pid {s['pid']:>7}  {s['comm']:<12} {base}")
    for s in res["killed"]:
        lines.append(f"  killed: pid {s['pid']:>7}  {s['comm']:<12}")
    for n in res["notes"]:
        lines.append(f"  note  : {n}")
    if res["killed"]:
        lines.append("  result: " + ("viewer side is gone" if res["verified"]
                                     else "kill sent, but NOT verified"))
    return "\n".join(lines)


def rdp_status():
    """(active, listening) for the user's own GNOME RDP service."""
    try:
        r = subprocess.run(["systemctl", "--user", "is-active",
                            "gnome-remote-desktop"],
                           capture_output=True, text=True, timeout=3)
        active = r.stdout.strip() == "active"
    except (OSError, subprocess.SubprocessError):
        active = None
    return active, listening_on(3389)


def close_rdp(apply=False):
    """Stop the user's own gnome-remote-desktop service (drops its sessions)."""
    active, port = rdp_status()
    res = {"active": active, "listening": port, "stopped": False, "notes": []}
    if not active:
        res["notes"].append("gnome-remote-desktop is not active")
        return res
    if not apply:
        res["notes"].append("dry run: nothing changed")
        return res
    try:
        r = subprocess.run(["systemctl", "--user", "stop",
                            "gnome-remote-desktop"],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        res["notes"].append(f"stop failed: {exc}")
        return res
    if r.returncode != 0:
        res["notes"].append(
            f"stop failed: {(r.stderr or r.stdout).strip() or r.returncode}")
        return res
    res["stopped"] = True
    return res


# --------------------------------------------------- wiping local traces
# Irreversible. Only paths inside your own home are touched, symlinks are
# never followed out of it, and every removal is written to the alert log.
# Running browsers may re-flush some databases from memory; close them for a
# complete wipe.
# Chromium-family per-profile data. Everything here is deleted whole (the
# bookmark file lives separately, so nothing in this list holds bookmarks).
# SQLite databases are removed as files together with their -journal/-wal/-shm
# sidecars (see SQLITE_SIDECARS); no row-level editing is done for these.
CHROMIUM_WIPE_ITEMS = [
    # history and download history (History holds both)
    "History", "Visited Links", "Top Sites",
    # autofill / credentials (no preservation wanted)
    "Web Data", "Login Data", "Login Data For Account", "Affiliation Database",
    # cookies and sessions
    "Cookies", "Network/Cookies",
    "Sessions", "Current Session", "Current Tabs", "Last Session", "Last Tabs",
    "Session Storage", "Local Storage", "IndexedDB",
    # caches
    "Cache", "Code Cache", "GPUCache", "Service Worker",
    "Shared Dictionary", "WebStorage", "Storage",
    # network / connection state
    "Network Persistent State", "Network/Network Persistent State",
    "Network/TransportSecurity", "TransportSecurity",
]
# Firefox per-profile data. places.sqlite is NOT in this list: it holds
# bookmarks as well as history, so it is opened and cleaned via SQL
# (see _clean_firefox_places) so bookmarks survive. formhistory.sqlite holds
# form/autofill history and is deleted whole.
FIREFOX_WIPE_ITEMS = [
    "cookies.sqlite", "formhistory.sqlite", "webappsstore.sqlite",
    "logins.json", "logins-backup.json", "key4.db", "key3.db",
    "signons.sqlite",
    "sessionstore-backups", "sessionstore.jsonlz4",
    "storage", "cache2", "startupCache", "shader-cache", "crashes",
]
SQLITE_SIDECARS = ("-journal", "-wal", "-shm")
# places.sqlite is NOT deleted: it holds bookmarks as well as history. It is
# opened and cleaned via SQL (see _clean_firefox_places) so bookmarks survive.
FIREFOX_PLACES = "places.sqlite"
DISCORD_ROOTS = ["~/.config/discord", "~/.config/discordcanary",
                 "~/.config/discordptb", "~/.config/BetterDiscord"]
DISCORD_ITEMS = ["Cache", "Code Cache", "GPUCache", "Local Storage",
                 "Session Storage", "IndexedDB", "logs",
                 "Network Persistent State", "Service Worker"]


def _size_of(path):
    if os.path.isdir(path) and not os.path.islink(path):
        try:
            return dir_size(path)[0]
        except OSError:
            return 0
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _remove_path(path, apply):
    """Remove one path inside home. Returns bytes that would be/were freed."""
    home = os.path.realpath(os.path.expanduser("~"))
    if not os.path.lexists(path):
        return 0
    real = os.path.realpath(path)
    if not (real == home or real.startswith(home + os.sep)):
        raise RuntimeError(f"refusing path outside home: {path}")
    size = _size_of(real)
    if not apply:
        return size
    if os.path.isdir(real) and not os.path.islink(path):
        shutil.rmtree(real)
    else:
        os.unlink(path)
    return size


def _remove_path_with_sidecars(path, apply):
    """Remove a path and, for a file, its SQLite -journal/-wal/-shm siblings.

    Deleting a database file without its WAL/SHM siblings leaves rows behind
    in the -wal, so a whole-file database removal always takes the sidecars
    too. The sidecars never exist without the main file, but a stale one is
    still collected."""
    # Check the type before removal: after it succeeds the path is gone and
    # isdir() would be False, making a directory look like a file.
    was_dir = os.path.isdir(path) and not os.path.islink(path)
    freed = _remove_path(path, apply)
    if not was_dir:
        for suffix in SQLITE_SIDECARS:
            freed += _remove_path(path + suffix, apply)
    return freed


def _file_in_use(path):
    """pid of any same-user process holding `path` open, else None.

    The last safety net before deleting: even if a browser was not detected by
    name, an open file descriptor means something is using the file. Never
    delete out from under a live process."""
    try:
        target = os.path.realpath(path)
    except OSError:
        return None
    if not os.path.exists(target):
        return None
    uid = os.getuid()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return None
    for pid in pids:
        try:
            if os.stat(f"/proc/{pid}").st_uid != uid:
                continue
            fddir = f"/proc/{pid}/fd"
            for fd in os.listdir(fddir):
                try:
                    link = os.readlink(os.path.join(fddir, fd))
                except OSError:
                    continue
                if link.endswith(" (deleted)"):
                    link = link[:-10]
                if link == target:
                    return int(pid)
        except OSError:
            continue
    return None


def _clean_firefox_places(path, apply):
    """Clean a Firefox places.sqlite while keeping bookmarks.

    Deleted: history visits, typed-input history, and places not referenced by
    any bookmark. Kept: the bookmark tree (moz_bookmarks and the places they
    point at) and bookmark annotations (moz_items_annos). Never deletes the
    file. Raises RuntimeError on any failure (open, lock, checkpoint, vacuum,
    integrity) so the caller skips it rather than leaving a half-cleaned or
    corrupt database.
    """
    if not in_home(path):
        raise RuntimeError("refusing path outside home")
    if not apply:
        return _size_of(path)
    before = _size_of(path)
    try:
        con = sqlite3.connect(path, timeout=1.0)
    except sqlite3.Error as exc:
        raise RuntimeError(f"cannot open: {exc}")
    try:
        cur = con.cursor()
        have = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "moz_places" not in have:
            raise RuntimeError("not a Firefox places database")
        cur.execute("PRAGMA foreign_keys=OFF")
        cur.execute("PRAGMA secure_delete=ON")  # scrub freed pages on VACUUM
        cur.execute("BEGIN IMMEDIATE")          # lock now, fail fast if in use
        cur.execute("DELETE FROM moz_historyvisits")
        if "moz_inputhistory" in have:
            cur.execute("DELETE FROM moz_inputhistory")
        cur.execute("DELETE FROM moz_places WHERE id NOT IN "
                    "(SELECT fk FROM moz_bookmarks WHERE fk IS NOT NULL)")
        if "moz_annos" in have:
            cur.execute("DELETE FROM moz_annos WHERE place_id NOT IN "
                        "(SELECT id FROM moz_places)")
        con.commit()
        # The WAL may still hold pre-delete rows. A TRUNCATE checkpoint must
        # succeed before we consider the clean complete; if it cannot, stop.
        try:
            row = cur.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        except sqlite3.Error as exc:
            raise RuntimeError(f"wal_checkpoint failed: {exc}")
        if row and row[0] > 0:                  # busy: not fully checkpointed
            raise RuntimeError(f"wal_checkpoint busy ({row[0]})")
        try:
            cur.execute("VACUUM")               # secure_delete overwrites pages
        except sqlite3.Error as exc:
            raise RuntimeError(f"vacuum failed: {exc}")
        ic = cur.execute("PRAGMA integrity_check").fetchone()
        if not ic or ic[0] != "ok":
            raise RuntimeError(f"integrity_check: {ic[0] if ic else 'no row'}")
    except sqlite3.Error as exc:
        try:
            con.rollback()
        except sqlite3.Error:
            pass
        raise RuntimeError(f"sqlite: {exc}")
    finally:
        con.close()
    # Checkpoint succeeded, so the sidecars are empty snapshots: drop them.
    for suffix in ("-wal", "-shm"):
        side = path + suffix
        if os.path.lexists(side):
            try:
                os.unlink(side)
            except OSError:
                pass
    return max(0, before - _size_of(path))


def browser_config_ok():
    """Return a list of problems with the BROWSERS table (empty = consistent).

    Guards the invariant that every browser both has profiles to discover and
    a process marker to detect, so a browser can never block cleanup without
    being handled (or be handled without being detectable)."""
    problems = []
    if not BROWSER_ROOTS:
        problems.append("no browser roots defined")
    if not BROWSER_COMMS:
        problems.append("no browser process markers defined")
    for b in BROWSERS:
        if not b.get("roots"):
            problems.append(f"{b['name']}: no roots")
        if not b.get("comms"):
            problems.append(f"{b['name']}: no process markers")
    return problems


def _browser_data_roots(b):
    """Existing whole directories that hold this browser's local data.

    A browser is cleared by removing its data directories, not selected files:
    that is what guarantees no history, logged-in account, or session-restore
    state survives. Native and Snap use the profile root; a Flatpak browser
    gets its whole `~/.var/app/<id>` directory, so its `cache/` and `data/`
    go too and the narrower `config/...` path is then redundant.
    """
    found = []

    def push(rel):
        p = os.path.expanduser(rel)
        if os.path.lexists(p) and p not in found:
            found.append(p)

    for fid in b.get("flatpak_ids", ()):
        push(f"~/.var/app/{fid}")
    for _label, rel in b["roots"]:
        p = os.path.expanduser(rel)
        if any(p == q or p.startswith(q + os.sep) for q in found):
            continue                      # already covered by ~/.var/app/<id>
        push(rel)
    return found


def _browser_root_label(b, path):
    if "/.var/app/" in path:
        return f"{b['name']} (flatpak)"
    if "/snap/" in path:
        return f"{b['name']} (snap)"
    return f"{b['name']} (native)"


def wipe_targets():
    """[(label, path, kind)] of existing browser and Discord data to clean.

    Browser data is targeted as whole directories — native, Snap and Flatpak —
    so a Clear leaves no profile behind: no history, no logged-in account, no
    session-restore state. kind is "remove" (whole-file/whole-dir removal)."""
    targets = []
    seen = set()

    def add(label, path, kind="remove"):
        if os.path.lexists(path) and path not in seen:
            seen.add(path)
            targets.append((label, path, kind))

    for b in BROWSERS:
        for root in _browser_data_roots(b):
            add(_browser_root_label(b, root), root)
    for rel in DISCORD_ROOTS:
        root = os.path.expanduser(rel)
        if not os.path.isdir(root):
            continue
        for item in DISCORD_ITEMS:
            add(f"discord/{os.path.basename(root)}", os.path.join(root, item))
    return targets


def _clear_survey():
    """Independent Clear discovery: (targets, running_browsers, total_bytes).

    Browser shutdown is never coupled to whether profile data was found."""
    targets = wipe_targets()
    browsers = running_browsers()
    total = sum(_size_of(p) for _l, p, _k in targets)
    return targets, browsers, total


def _clear_has_work(targets, browsers):
    """Clear proceeds if there is data to remove OR a browser to close."""
    return bool(targets) or bool(browsers)


def wipe_private_data(apply=True, allow_running=False, encrypt=False,
                      passphrase=None):
    """Delete (or encrypt) browser and Discord private data.

    Refuses to clean a category whose application is still running (unless
    `allow_running`), and refuses any individual path a same-user process holds
    open, so a live file is never deleted out from under a process. Chromium-
    family databases are deleted whole with their WAL/SHM sidecars; Firefox
    places.sqlite is cleaned in place with bookmarks preserved.

    With `encrypt=True` the eligible paths are first written to one encrypted,
    restorable archive (`vault_store`) and verified; only then are the
    originals removed. If the archive cannot be created or verified, nothing is
    deleted. No passphrase is ever stored.

    Returns {'items': [(label, path, bytes)], 'total': int, 'errors': [...],
             'skipped': [...], 'vault': path|None, 'removed': [path, ...],
             'remaining': [path, ...]}. `removed`/`remaining` name exactly which
             originals were and were not deleted — there is no atomic rollback.
    """
    res = {"items": [], "total": 0, "errors": [], "skipped": [], "vault": None,
           "removed": [], "remaining": []}
    browsers = running_browsers()
    discord = running_discord()
    discord_roots = [os.path.expanduser(r) for r in DISCORD_ROOTS]
    eligible = []
    for label, path, kind in wipe_targets():
        is_discord = label.startswith("discord/") or any(
            path.startswith(r + os.sep) or path == r for r in discord_roots)
        if apply and not allow_running:
            if browsers and not is_discord:
                res["skipped"].append(
                    f"{path}: a browser is running (not stopped)")
                res["remaining"].append(path)
                continue
            if discord and is_discord:
                res["skipped"].append(
                    f"{path}: Discord is running (not stopped)")
                res["remaining"].append(path)
                continue
        if apply:
            holder = _file_in_use(path)
            if holder is not None:
                res["skipped"].append(
                    f"{path}: in use by pid {holder} (not stopped)")
                res["remaining"].append(path)
                continue
        if apply and encrypt:
            eligible.append((label, path, kind))
            continue
        try:
            if kind == "places":
                n = _clean_firefox_places(path, apply)
            else:
                n = _remove_path_with_sidecars(path, apply)
        except (OSError, RuntimeError) as exc:
            res["errors"].append(f"{path}: {exc}")
            if apply and os.path.lexists(path):
                res["remaining"].append(path)
            continue
        res["items"].append((label, path, n))
        res["total"] += n
        if apply:
            res["removed"].append(path)

    if apply and encrypt and eligible:
        try:
            res["vault"] = vault_store([p for _l, p, _k in eligible], passphrase)
        except (OSError, RuntimeError) as exc:
            # Fail closed: the archive did not verify, so keep every original.
            res["errors"].append(f"vault: {exc} (nothing deleted)")
            for _label, path, _kind in eligible:
                res["remaining"].append(path)
            eligible = []
        for label, path, _kind in eligible:
            size = _size_of(path)
            try:
                _remove_path_with_sidecars(path, True)
            except (OSError, RuntimeError) as exc:
                res["errors"].append(f"{path}: {exc}")
                res["remaining"].append(path)
                continue
            res["items"].append((label, path, size))
            res["total"] += size
            res["removed"].append(path)

    if apply:
        verb = "archived" if encrypt else "removed"
        log_alert(f"wipe: {verb} {len(res['items'])} item(s), "
                  f"{res['total'] / 1048576:.1f} MB, "
                  f"{len(res['errors'])} error(s), "
                  f"{len(res['skipped'])} skipped, "
                  f"{len(res['remaining'])} left in place")
        if res["vault"]:
            log_alert(f"vault: {res['vault']} (encrypted, restorable)")
        for label, path, n in res["items"]:
            log_alert(f"wipe: {label} {path} ({n / 1048576:.1f} MB)")
        for s in res["skipped"]:
            log_alert(f"wipe skipped: {s}")
        for s in res["remaining"]:
            log_alert(f"wipe: still present {s}")
    return res


# ------------------------------------------------------------------- vault
# "Encrypt instead of delete": the same targets are written to one encrypted,
# restorable tar under the state dir. The originals are removed only after the
# archive has been MAC-verified, decrypted, and every member re-hashed against
# a per-file SHA-256 manifest recorded at archive time. A passphrase is read
# from VNC_WATCH_VAULT_PASSPHRASE or prompted for; it is never persisted.
#
# On-disk envelope (authenticated, encrypt-then-MAC). The ciphertext is written
# first, then authenticated; the MAC is verified *before* any decryption, so a
# modified, truncated, corrupted or wrong-passphrase archive never reaches the
# cipher:
#
#     "VWVAULT1"      8 bytes    magic
#     salt           16 bytes    random, per archive
#     HMAC-SHA256    32 bytes    over magic || salt || ciphertext
#     ciphertext      ...        backend AES-256 of the tar stream
#
# The HMAC key is PBKDF2-HMAC-SHA256(passphrase, salt, 200000). The openssl
# CBC path carries no authentication of its own, so this envelope is what makes
# it authenticated; the gpg path is authenticated by this MAC as well.
VAULT_DIR = os.path.join(STATE_DIR, "vault")
VAULT_SUFFIXES = (".tar.gpg", ".tar.enc")
VAULT_MAGIC = b"VWVAULT1"
VAULT_KDF_ITER = 200000
VAULT_SALT_LEN = 16
VAULT_MAC_LEN = 32
VAULT_HEADER_LEN = len(VAULT_MAGIC) + VAULT_SALT_LEN + VAULT_MAC_LEN
VAULT_MANIFEST = ".vnc-watch-manifest.json"
_CHUNK = 1 << 20


def _crypto_backend(force=None):
    """'gpg', 'openssl', or None. gpg is preferred (AES256, battle-tested).

    `force` pins one backend (used by tests to exercise each path independently).
    """
    if force in ("gpg", "openssl"):
        return force if shutil.which(force) else None
    if shutil.which("gpg"):
        return "gpg"
    if shutil.which("openssl"):
        return "openssl"
    return None


def _pass_fd(passphrase):
    """A pipe holding the passphrase, to keep it out of argv/`ps`."""
    r, w = os.pipe()
    os.write(w, (passphrase + "\n").encode())
    os.close(w)
    return r


def _cipher_argv(backend, fd, encrypt, src, dst):
    if backend == "gpg":
        base = ["gpg", "--batch", "--yes", "--quiet", "--no-tty",
                "--no-symkey-cache", "--pinentry-mode", "loopback",
                "--passphrase-fd", str(fd)]
        if encrypt:
            return base + ["--symmetric", "--cipher-algo", "AES256",
                           "--output", dst, src]
        return base + ["--output", dst, "--decrypt", src]
    base = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-md", "sha256",
            "-salt", "-pass", f"fd:{fd}", "-in", src, "-out", dst]
    if encrypt:
        return base
    return base + ["-d"]


def _cipher_apply(backend, passphrase, src, dst, encrypt):
    """Encrypt or decrypt file `src` to `dst`; raise on a nonzero exit."""
    fd = _pass_fd(passphrase)
    try:
        proc = subprocess.Popen(
            _cipher_argv(backend, fd, encrypt, src, dst),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, pass_fds=(fd,))
        err = proc.stderr.read().decode("utf-8", "replace")
        rc = proc.wait()
    finally:
        os.close(fd)
    if rc != 0:
        verb = "encrypt" if encrypt else "decrypt"
        raise RuntimeError(f"{verb} failed (rc={rc}): {err.strip()[:200]}")


def _derive_mac_key(passphrase, salt):
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt,
                               VAULT_KDF_ITER, dklen=VAULT_MAC_LEN)


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _fsync_dir(path):
    try:
        dfd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def _vault_seal(backend, passphrase, plain_path, out_path):
    """Encrypt `plain_path` and write the authenticated envelope to out_path."""
    ct_path = os.path.join(os.path.dirname(out_path), ".vwct-" +
                           os.path.basename(out_path))
    try:
        _cipher_apply(backend, passphrase, plain_path, ct_path, True)
        salt = os.urandom(VAULT_SALT_LEN)
        key = _derive_mac_key(passphrase, salt)
        mac = hmac.new(key, digestmod="sha256")
        mac.update(VAULT_MAGIC + salt)
        with open(ct_path, "rb") as cf, os.fdopen(
                os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                        0o600), "wb") as of:
            of.write(VAULT_MAGIC + salt + b"\x00" * VAULT_MAC_LEN)
            while True:
                chunk = cf.read(_CHUNK)
                if not chunk:
                    break
                mac.update(chunk)
                of.write(chunk)
            of.seek(len(VAULT_MAGIC) + VAULT_SALT_LEN)
            of.write(mac.digest())
        _fsync_dir(os.path.dirname(out_path))
    finally:
        _unlink(ct_path)


def _vault_open(backend, passphrase, archive, workdir):
    """Verify the envelope MAC, then decrypt.

    Returns the decrypted plaintext path under `workdir`. Raises RuntimeError
    on a bad magic/short header or a MAC mismatch *before* invoking the cipher,
    so a modified, truncated, corrupted or wrong-passphrase archive is never
    decrypted.
    """
    ct_path = os.path.join(workdir, "body.ct")
    with open(archive, "rb") as f:
        header = f.read(VAULT_HEADER_LEN)
        if (len(header) < VAULT_HEADER_LEN
                or header[:len(VAULT_MAGIC)] != VAULT_MAGIC):
            raise RuntimeError("not a vault archive (bad magic or truncated)")
        salt = header[len(VAULT_MAGIC):len(VAULT_MAGIC) + VAULT_SALT_LEN]
        want = header[len(VAULT_MAGIC) + VAULT_SALT_LEN:VAULT_HEADER_LEN]
        key = _derive_mac_key(passphrase, salt)
        mac = hmac.new(key, digestmod="sha256")
        mac.update(VAULT_MAGIC + salt)
        with open(ct_path, "wb") as cf:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                mac.update(chunk)
                cf.write(chunk)
    if not hmac.compare_digest(mac.digest(), want):
        _unlink(ct_path)
        raise RuntimeError(
            "authentication failed: wrong passphrase, or the archive was "
            "modified, corrupted or truncated")
    plain = os.path.join(workdir, "plain.tar")
    _cipher_apply(backend, passphrase, ct_path, plain, False)
    _unlink(ct_path)
    return plain


def _hash_file(path):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _collect_entries(paths):
    """Walk `paths`; return (entries, skipped).

    `entries` is a depth-first list of dicts {rel, path, type, sha256, size,
    mode}. Every regular file gets a SHA-256 taken here. Symlinks, devices,
    sockets and fifos are recorded in `skipped` and never archived (a symlink
    cannot be hashed, and restoring one could point outside home).
    """
    home = os.path.realpath(os.path.expanduser("~"))
    entries = []
    skipped = []
    seen = set()

    def add(path, rel):
        if rel in seen:
            skipped.append(f"{rel}: duplicate path")
            return
        if os.path.islink(path):
            skipped.append(f"{rel}: symlink (not archived)")
            return
        st = os.lstat(path)
        if stat.S_ISREG(st.st_mode):
            digest, size = _hash_file(path)
            entries.append({"rel": rel, "path": path, "type": "file",
                            "sha256": digest, "size": size,
                            "mode": stat.S_IMODE(st.st_mode)})
            seen.add(rel)
        elif stat.S_ISDIR(st.st_mode):
            entries.append({"rel": rel, "path": path, "type": "dir",
                            "sha256": None, "size": 0,
                            "mode": stat.S_IMODE(st.st_mode)})
            seen.add(rel)
            for name in sorted(os.listdir(path)):
                add(os.path.join(path, name), os.path.join(rel, name))
        else:
            skipped.append(f"{rel}: special file (not archived)")

    for path in paths:
        if not os.path.lexists(path):
            continue
        add(path, os.path.relpath(os.path.realpath(path), home))
    return entries, skipped


def _write_plain_tar(plain_path, entries):
    """Write the tar with the manifest first, then each member."""
    with tarfile.open(plain_path, "w") as tar:
        manifest = {"version": 1, "entries":
                    [{k: e[k] for k in ("rel", "type", "sha256", "size",
                                        "mode")} for e in entries]}
        data = json.dumps(manifest, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo(VAULT_MANIFEST)
        info.size = len(data)
        info.mode = 0o600
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(data))
        for entry in entries:
            tar.add(entry["path"], arcname=entry["rel"], recursive=False)


def _parse_manifest(tar):
    try:
        fh = tar.extractfile(VAULT_MANIFEST)
    except KeyError:
        raise RuntimeError("archive has no manifest")
    if fh is None:
        raise RuntimeError("archive manifest is not a regular file")
    try:
        return json.loads(fh.read().decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"archive manifest is unreadable: {exc}")


def _vault_verify_plain(plain_path):
    """Re-hash every archived member and compare it with the manifest.

    Raises if a regular member's SHA-256 or size differs (the source changed
    while archiving, or the archive was modified), if a declared member is
    missing, if the archive carries an unexpected member, or if any member is a
    link or special file.
    """
    declared = {}
    found = set()
    with tarfile.open(plain_path, "r") as tar:
        manifest = _parse_manifest(tar)
        for entry in manifest.get("entries", []):
            declared[entry["rel"]] = entry
        for member in tar.getmembers():
            if member.name == VAULT_MANIFEST:
                continue
            _safe_member_name(member.name)
            if member.issym() or member.islnk():
                raise RuntimeError(f"archive contains a link: {member.name}")
            if not (member.isreg() or member.isdir()):
                raise RuntimeError(
                    f"archive contains a special file: {member.name}")
            entry = declared.get(member.name)
            if entry is None:
                raise RuntimeError(f"unexpected archive member: {member.name}")
            if entry["type"] == "dir":
                if not member.isdir():
                    raise RuntimeError(f"expected a directory: {member.name}")
                found.add(member.name)
                continue
            if not member.isreg():
                raise RuntimeError(
                    f"expected a regular file: {member.name}")
            fh = tar.extractfile(member)
            h = hashlib.sha256()
            size = 0
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
                size += len(chunk)
            if size != entry["size"] or h.hexdigest() != entry["sha256"]:
                raise RuntimeError(
                    f"content hash mismatch for {member.name}: the source "
                    f"changed while archiving, or the archive was modified")
            found.add(member.name)
    missing = set(declared) - found
    if missing:
        raise RuntimeError(
            f"manifest lists {len(missing)} member(s) not in the archive")


def vault_passphrase(prompt=None):
    """Env passphrase, else an interactive prompt. None when unavailable."""
    pw = os.environ.get("VNC_WATCH_VAULT_PASSPHRASE", "")
    if pw:
        return pw
    if prompt is None:
        prompt = sys.stdin.isatty()
    if not prompt:
        return None
    import getpass
    try:
        return getpass.getpass("Vault passphrase (not stored): ") or None
    except (EOFError, KeyboardInterrupt):
        return None


def vault_archives():
    """[(path, size, mtime)] oldest first."""
    try:
        names = os.listdir(VAULT_DIR)
    except OSError:
        return []
    out = []
    for name in names:
        if not name.endswith(VAULT_SUFFIXES):
            continue
        path = os.path.join(VAULT_DIR, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        out.append((path, st.st_size, st.st_mtime))
    return sorted(out, key=lambda item: item[2])


def _vault_list_names(archive, passphrase, backend=None):
    """MAC-verify then decrypt the archive and return its member names."""
    backend = _crypto_backend(backend)
    if backend is None:
        raise RuntimeError("neither gpg nor openssl is installed")
    try:
        os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
    except OSError:
        pass
    work = tempfile.mkdtemp(prefix=".vault-", dir=VAULT_DIR)
    try:
        plain = _vault_open(backend, passphrase, archive, work)
        with tarfile.open(plain, "r") as tar:
            return [m.name for m in tar.getmembers()]
    finally:
        shutil.rmtree(work, ignore_errors=True)


def vault_store(paths, passphrase, backend=None):
    """Encrypt `paths` into one verified archive; return the archive path.

    The archive is written, decrypted once, and every member re-hashed against
    the manifest. Raises RuntimeError on any failure, in which case the archive
    is removed and the caller must keep every original (fail closed).
    """
    paths = [p for p in paths if os.path.lexists(p)]
    if not paths:
        raise RuntimeError("nothing to archive")
    backend = _crypto_backend(backend)
    if backend is None:
        raise RuntimeError("neither gpg nor openssl is installed")
    if not passphrase:
        raise RuntimeError("a vault passphrase is required")
    try:
        os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
        try:
            os.chmod(VAULT_DIR, 0o700)
        except OSError:
            pass
    except OSError as exc:
        raise RuntimeError(f"cannot create {VAULT_DIR}: {exc}")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    out = os.path.join(VAULT_DIR, f"vnc-watch-{stamp}"
                       + (".tar.gpg" if backend == "gpg" else ".tar.enc"))
    work = tempfile.mkdtemp(prefix=".vault-", dir=VAULT_DIR)
    try:
        entries, skipped = _collect_entries(paths)
        for s in skipped:
            log_alert(f"vault: skipped {s}")
        if not entries:
            raise RuntimeError("nothing to archive")
        plain = os.path.join(work, "plain.tar")
        _write_plain_tar(plain, entries)
        _vault_seal(backend, passphrase, plain, out)
        plain2 = _vault_open(backend, passphrase, out, work)
        _vault_verify_plain(plain2)
        _unlink(plain2)
        return out
    except BaseException:
        _unlink(out)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _safe_member_name(name):
    """Normalize an archive member path; reject escapes and absolute paths."""
    if name.startswith(("/", os.sep)) or re.match(r"^[A-Za-z]:", name):
        raise RuntimeError(f"absolute archive member: {name}")
    norm = os.path.normpath(name)
    if norm in (".", "") or norm.startswith(".." + os.sep) or norm == ".." \
            or os.path.isabs(norm):
        raise RuntimeError(f"unsafe archive member: {name}")
    return norm


def _first_symlink_parent(path, home):
    """Return the first symlinked path component under `home`, or None."""
    rel = os.path.relpath(path, home)
    if rel in (".", ""):
        return None
    cur = home
    for part in rel.split(os.sep):
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return cur
    return None


def _extract_staging(tar, staging):
    """Extract archive members into `staging`, rejecting unsafe entries."""
    seen = set()
    for member in tar.getmembers():
        if member.name == VAULT_MANIFEST:
            continue
        rel = _safe_member_name(member.name)
        if rel in seen:
            raise RuntimeError(f"duplicate archive member: {member.name}")
        seen.add(rel)
        dest = os.path.join(staging, rel)
        if member.isdir():
            os.makedirs(dest, exist_ok=True)
            continue
        if member.issym() or member.islnk():
            raise RuntimeError(f"refusing link member: {member.name}")
        if not member.isreg():
            raise RuntimeError(f"refusing special member: {member.name}")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        src = tar.extractfile(member)
        with open(dest, "wb") as out:
            shutil.copyfileobj(src, out, _CHUNK)
        try:
            os.chmod(dest, member.mode & 0o777)
        except OSError:
            pass


def _merge_staging(staging, home, entries, restored, conflicts):
    """Move staged members into home without clobbering anything."""
    for entry in sorted(entries, key=lambda e: e["rel"].count(os.sep)):
        rel = entry["rel"]
        dest = os.path.join(home, rel)
        bad = _first_symlink_parent(os.path.dirname(dest), home)
        if bad is not None:
            conflicts.append((rel, f"destination parent is a symlink: {bad}"))
            continue
        if entry["type"] == "dir":
            if os.path.lexists(dest) and not os.path.isdir(dest):
                conflicts.append((rel, "a non-directory already exists"))
                continue
            try:
                os.makedirs(dest, exist_ok=True)
            except OSError as exc:
                conflicts.append((rel, str(exc)))
            continue
        src = os.path.join(staging, rel)
        if os.path.lexists(dest):
            conflicts.append((rel, "already exists (left untouched)"))
            continue
        try:
            os.link(src, dest)                       # no-clobber
        except FileExistsError:
            conflicts.append((rel, "already exists (left untouched)"))
            continue
        except OSError:
            try:
                fd = os.open(dest,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             entry["mode"] & 0o777)
            except FileExistsError:
                conflicts.append((rel, "already exists (left untouched)"))
                continue
            with os.fdopen(fd, "wb") as out, open(src, "rb") as f:
                shutil.copyfileobj(f, out, _CHUNK)
        restored.append(rel)


def vault_verify(archive="latest", passphrase=None, backend=None):
    """Verify an archive's MAC and every member hash without restoring it."""
    archives = vault_archives()
    if archive in (None, "", "latest"):
        if not archives:
            raise RuntimeError("no vault archive found")
        archive = archives[-1][0]
    if not os.path.isfile(archive):
        raise RuntimeError(f"archive not found: {archive}")
    pw = passphrase or vault_passphrase()
    if not pw:
        raise RuntimeError("a vault passphrase is required")
    backend = _crypto_backend(backend)
    if backend is None:
        raise RuntimeError("neither gpg nor openssl is installed")
    try:
        os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
    except OSError:
        pass
    work = tempfile.mkdtemp(prefix=".vault-", dir=VAULT_DIR)
    try:
        plain = _vault_open(backend, pw, archive, work)
        _vault_verify_plain(plain)
        with tarfile.open(plain, "r") as tar:
            members = [m.name for m in tar.getmembers()
                       if m.name != VAULT_MANIFEST]
        return {"archive": archive, "members": members}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def vault_restore(archive="latest", passphrase=None, backend=None):
    """Verify, then restore an archive into home without clobbering.

    Returns {'restored': [rel, ...], 'conflicts': [(rel, reason), ...]}. The
    archive is MAC-checked and every member re-hashed before anything is
    extracted; extraction goes to a staging directory and members are moved
    into place with no-clobber (existing files are never overwritten).
    """
    archives = vault_archives()
    if archive in (None, "", "latest"):
        if not archives:
            raise RuntimeError("no vault archive found")
        archive = archives[-1][0]
    if not os.path.isfile(archive):
        raise RuntimeError(f"archive not found: {archive}")
    pw = passphrase or vault_passphrase()
    if not pw:
        raise RuntimeError("a vault passphrase is required")
    backend = _crypto_backend(backend)
    if backend is None:
        raise RuntimeError("neither gpg nor openssl is installed")
    try:
        os.makedirs(VAULT_DIR, mode=0o700, exist_ok=True)
    except OSError:
        pass
    home = os.path.realpath(os.path.expanduser("~"))
    work = tempfile.mkdtemp(prefix=".vault-", dir=VAULT_DIR)
    staging = tempfile.mkdtemp(prefix=".restore-", dir=home)
    restored = []
    conflicts = []
    try:
        plain = _vault_open(backend, pw, archive, work)
        _vault_verify_plain(plain)
        with tarfile.open(plain, "r") as tar:
            entries = _parse_manifest(tar).get("entries", [])
            _extract_staging(tar, staging)
        _merge_staging(staging, home, entries, restored, conflicts)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(staging, ignore_errors=True)
    log_alert(f"vault restore: {len(restored)} restored, "
              f"{len(conflicts)} conflict(s) from {archive}")
    return {"restored": restored, "conflicts": conflicts}


# ------------------------------------------------------------ hotkey setup
SHORTCUT_PATH = ("/org/gnome/settings-daemon/plugins/media-keys/"
                 "custom-keybindings/vnc-watch-lockdown/")
SHORTCUT_BASE = "org.gnome.settings-daemon.plugins.media-keys"
SHORTCUT_SCHEMA = SHORTCUT_BASE + ".custom-keybinding:" + SHORTCUT_PATH


def _gsettings(*args):
    try:
        r = subprocess.run(["gsettings", *args], capture_output=True,
                           text=True, timeout=5)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


def shortcut_command(install=True, binding="<Control><Alt><Shift>l"):
    """Install or remove a GNOME custom shortcut for `lockdown`."""
    rc, out, err = _gsettings("get", SHORTCUT_BASE, "custom-keybindings")
    if rc != 0:
        print(f"gsettings unavailable: {err}")
        return 1
    try:
        paths = ast.literal_eval(out.replace("@as ", "").strip() or "[]")
    except (ValueError, SyntaxError):
        paths = []
    paths = [p for p in paths if isinstance(p, str)]

    if install:
        if SHORTCUT_PATH not in paths:
            paths.append(SHORTCUT_PATH)
        value = "[" + ", ".join(f"'{p}'" for p in paths) + "]"
        rc, _, err = _gsettings("set", SHORTCUT_BASE, "custom-keybindings", value)
        if rc != 0:
            print(f"could not set the keybinding list: {err}")
            return 1
        cmd = f"{sys.executable} {os.path.abspath(__file__)} lockdown"
        for key, val in (("name", "vnc-watch lockdown"),
                         ("command", cmd), ("binding", binding)):
            rc, _, err = _gsettings("set", SHORTCUT_SCHEMA, key, val)
            if rc != 0:
                print(f"could not set {key}: {err}")
                return 1
        print(f"installed: {binding} -> {cmd}")
        print("It closes any VNC/RDP session and locks the screen.")
        return 0

    if SHORTCUT_PATH in paths:
        paths.remove(SHORTCUT_PATH)
        value = "[" + ", ".join(f"'{p}'" for p in paths) + "]"
        rc, _, err = _gsettings("set", SHORTCUT_BASE, "custom-keybindings", value)
        if rc != 0:
            print(f"could not update the keybinding list: {err}")
            return 1
        print("removed the vnc-watch shortcut")
    else:
        print("shortcut was not installed")
    return 0


def lockdown(lock=True):
    """Evict remote access and lock the screen. The only real 'take control'.

    X11 gives no way to revoke one client's input while keeping your own:
    x11vnc injects through the XTEST device, and the server refuses to let an
    unprivileged client disable that device (BadAccess). Ending the session is
    therefore the mechanism; locking makes their input hit the lock screen.
    """
    out = {"closed": None, "locked": None, "how": ""}
    # Eviction is local and instant; lock immediately after, before any
    # network call, so a slow Discord webhook cannot delay the lock.
    res = close_vnc(apply=True)
    what, verified = "none", False
    if res["killed"]:
        what, verified = "vnc", res["verified"]
    else:
        rdp = close_rdp(apply=True)
        if rdp["stopped"]:
            what, verified = "rdp", True
    out["closed"] = {"what": what, "verified": verified, "detail": res}
    log_alert(f"lockdown: remote={what} verified={verified}")
    if lock:
        ok, how = lock_session()
        out["locked"], out["how"] = ok, how
        log_alert(f"lockdown: lock={'ok' if ok else 'failed'} ({how})")
    remote_send_sync(*remote_message(
        "action", f"lockdown: remote={what} verified={verified} "
                  f"locked={out['locked']}"))
    return out


def run_lockdown(lock=True):
    print("\n== lockdown ==\n")
    res = lockdown(lock=lock)
    c = res["closed"]
    print(f"  remote : {c['what']} "
          f"({'closed' if c['verified'] else 'nothing to close'})")
    if lock:
        print(f"  screen : {'locked via ' + res['how'] if res['locked'] else res['how']}")
    print()
    return 0 if c["verified"] else 1


def close_remote_view():
    """Close x11vnc if it is up, else stop the user's RDP service."""
    res = close_vnc(apply=True)
    if res["killed"]:
        pids = ",".join(str(s["pid"]) for s in res["killed"])
        log_alert(f"action=close_vnc pids={pids} "
                  f"outcome={'ok' if res['verified'] else 'unverified'}")
        remote_send_sync(*remote_message(
            "action", f"close_vnc pids={pids} "
                      f"{'ok' if res['verified'] else 'unverified'}"))
        return {"what": "vnc", "verified": res["verified"], "detail": res}
    rdp = close_rdp(apply=True)
    if rdp["stopped"]:
        log_alert("action=close_rdp outcome=ok")
        remote_send_sync(*remote_message("action", "close_rdp ok"))
        return {"what": "rdp", "verified": True, "detail": rdp}
    log_alert("action=close_remote outcome=nothing-to-close")
    return {"what": "none", "verified": False, "detail": res}


# ----------------------------------------------------------- action window
POPUP_LOCK = os.path.join(STATE_DIR, "popup.lock")
POPUP_COOLDOWN = 120.0
POPUP_TIMEOUT = _env_num("VNC_WATCH_POPUP_TIMEOUT", 60, int)
_last_popup = 0.0


def popup_available():
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk  # noqa: F401
        return True
    except Exception:
        return False


def trigger_popup(reason, detail=""):
    """Start the action window as a detached process. Never blocks the daemon."""
    global _last_popup
    if time.monotonic() - _last_popup < POPUP_COOLDOWN:
        return False
    if not popup_available():
        log_alert("action window unavailable (no GTK or display); "
                  "notification only")
        return False
    try:
        fd = os.open(POPUP_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        log_alert(f"action window skipped: lock open failed: {exc}")
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)                      # a window is already open
        return False
    env = dict(os.environ)
    env.setdefault("DISPLAY", ":0")
    try:
        argv = [sys.executable, os.path.abspath(__file__), "popup",
                "--reason", reason, "--detail", detail,
                "--timeout", str(POPUP_TIMEOUT)]
        if os.environ.get("VNC_WATCH_POPUP_AUTO", "1") == "0":
            argv.append("--no-auto")
        subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(fd,),
            start_new_session=True, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        os.close(fd)
        log_alert(f"action window failed to launch: {exc}")
        return False
    os.close(fd)                          # the child keeps the lock
    _last_popup = time.monotonic()
    log_alert(f"action window opened: {reason}")
    return True


def run_popup(reason, detail="", timeout=60, auto=True):
    """Show the window; return one of close+wipe / wipe / nothing."""
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, GLib

    locked, why = active_lock_window()
    state = {"choice": None, "left": int(timeout)}

    win = Gtk.Window(title="Remote viewing detected")
    win.set_default_size(520, 240)
    win.set_position(Gtk.WindowPosition.CENTER)
    win.set_keep_above(True)
    win.set_urgency_hint(True)
    win.connect("destroy", Gtk.main_quit)

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    box.set_border_width(18)
    win.add(box)

    head = Gtk.Label()
    head.set_markup(f"<b><span size='large'>{reason}</span></b>")
    head.set_xalign(0)
    box.pack_start(head, False, False, 0)

    if detail:
        d = Gtk.Label(label=detail)
        d.set_xalign(0)
        d.set_line_wrap(True)
        d.set_selectable(True)
        box.pack_start(d, False, False, 0)

    auto_label = Gtk.Label()
    auto_label.set_xalign(0)
    auto_label.set_line_wrap(True)
    box.pack_start(auto_label, False, False, 0)

    def decide(choice):
        if state["choice"] is None:
            state["choice"] = choice
        win.destroy()

    def tick():
        state["left"] -= 1
        if state["choice"] is not None:
            return False
        if state["left"] <= 0:
            if locked or not auto:
                log_alert("action window timeout; no automatic action"
                          + (f" (lock window: {why})" if locked else ""))
                decide("nothing")
            else:
                log_alert("action window timeout: applying close+wipe")
                decide("close+wipe")
            return False
        if not locked:
            auto_label.set_markup(f"<b>Auto in {state['left']} s:</b> close the "
                            f"connection and wipe browser + Discord data.")
        return True

    if locked:
        auto_label.set_markup(f"<b>Campus lock window active</b> ({why}). "
                        f"Automatic action is disabled; choose manually.")
    elif not auto:
        auto_label.set_markup("<b>Preview:</b> no automatic action will run.")
    else:
        auto_label.set_markup(f"<b>Auto in {state['left']} s:</b> close the "
                        f"connection and wipe browser + Discord data.")
    GLib.timeout_add(1000, tick)

    def confirm(text):
        dlg = Gtk.MessageDialog(transient_for=win, flags=0,
                                message_type=Gtk.MessageType.WARNING,
                                buttons=Gtk.ButtonsType.OK_CANCEL, text=text)
        dlg.format_secondary_text("This cannot be undone.")
        ok = dlg.run() == Gtk.ResponseType.OK
        dlg.destroy()
        return ok

    def on_close_wipe(_b):
        if confirm("Close the connection and delete browser + Discord data?"):
            decide("close+wipe")

    def on_wipe(_b):
        if confirm("Keep the connection open and delete browser + Discord "
                   "data?"):
            decide("wipe")

    def on_nothing(_b):
        decide("nothing")

    row = Gtk.ButtonBox(orientation=Gtk.Orientation.HORIZONTAL)
    row.set_layout(Gtk.ButtonBoxStyle.EXPAND)
    row.set_spacing(8)
    b1 = Gtk.Button(label="Close + wipe")
    b1.get_style_context().add_class("suggested-action")
    b1.connect("clicked", on_close_wipe)
    b2 = Gtk.Button(label="Keep connection, wipe data")
    b2.connect("clicked", on_wipe)
    b3 = Gtk.Button(label="Do nothing")
    b3.connect("clicked", on_nothing)
    for b in (b1, b2, b3):
        row.add(b)
    box.pack_end(row, False, False, 0)

    win.show_all()
    Gtk.main()
    return state["choice"] or "nothing"


def run_popup_command(reason, detail="", timeout=60, auto=True):
    choice = run_popup(reason, detail, timeout, auto=auto)
    print(f"choice: {choice}")
    if choice == "nothing":
        log_alert(f"popup reason={reason!r} choice=nothing")
        return 0
    if choice in ("close+wipe", "close"):
        closed = close_remote_view()
        print(f"closed: {closed['what']} verified={closed['verified']}")
    if choice in ("close+wipe", "wipe"):
        wipe = wipe_private_data(apply=True)
        print(f"wiped : {len(wipe['items'])} item(s), "
              f"{wipe['total'] / 1048576:.1f} MB, "
              f"{len(wipe['errors'])} error(s)")
        for err in wipe["errors"][:5]:
            print(f"  error: {err}")
    log_alert(f"popup reason={reason!r} choice={choice}")
    notify("vnc-watch", f"Chosen: {choice}", "viewer", urgent=False)
    remote_send_sync(*remote_message("action",
                                    f"popup choice={choice} reason={reason}"))
    return 0


def cpu_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            f = fh.read().rsplit(") ", 1)[1].split()
        return int(f[11]) + int(f[12])
    except (OSError, IndexError, ValueError):
        return None


def x_client_count():
    try:
        with open("/proc/net/unix", errors="replace") as fh:
            lines = fh.readlines()[1:]
    except OSError:
        return None
    n = 0
    for line in lines:
        parts = line.split()
        # Num RefCount Protocol Flags Type St Inode Path   (St is "03", not "0003")
        if len(parts) >= 8 and parts[5] in ("03", "0003") \
                and parts[7].endswith("X11-unix/X0"):
            n += 1
    return n


def autorepeat_on():
    try:
        out = subprocess.run(["xset", "q"], capture_output=True, text=True,
                             timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"auto repeat:\s+(on|off)", out)
    return None if not m else m.group(1) == "on"


def xtest_ids():
    try:
        out = subprocess.run(["xinput", "list"], capture_output=True,
                             text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    ids = {}
    for line in out.splitlines():
        m = re.search(r"id=(\d+)", line)
        if not m:
            continue
        if "Virtual core XTEST pointer" in line:
            ids[int(m.group(1))] = "pointer"
        elif "Virtual core XTEST keyboard" in line:
            ids[int(m.group(1))] = "keyboard"
    return ids


def portal_status():
    print("== portal / remote desktop ==")
    for label, cmd in (
        ("rdp/vnc (grdctl)", ["grdctl", "status"]),
        ("dbus screen/remote ifaces", ["busctl", "--user", "list"]),
        ("listeners on watched ports", ["ss", "-tln"]),
    ):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            body = (r.stdout or r.stderr).strip()
        except (OSError, subprocess.SubprocessError) as exc:
            body = f"(unavailable: {exc})"
            print(f"-- {label}\n{body}")
            continue
        if label.startswith("dbus"):
            names = [l.split()[0] for l in body.splitlines()
                     if "ScreenCast" in l or "RemoteDesktop" in l]
            body = ", ".join(names) or "none"
        elif label.startswith("listeners"):
            body = "\n".join(l for l in body.splitlines()
                             if re.search(r":(3389|590[0-9]|11100)\b", l)) or "none"
        print(f"-- {label}\n{body or '(no output)'}")
    return 0


# ------------------------------------------------------- session logins
# /var/run/utmp is world-readable (0644 here), so new interactive logins can
# be seen without root. loginctl adds remote/virtual sessions that utmp may
# not record, and needs no privilege either.
UTMP_FILE = os.environ.get("VNC_WATCH_UTMP", "/var/run/utmp")
UTMP_SIZE = 384
UTMP_USER_PROCESS = 7


def _cstr(raw):
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def utmp_sessions():
    """[{user,line,host,start}] for active USER_PROCESS entries, or None.

    Fixed offsets for glibc's 384-byte struct utmp on Linux/x86_64; parsing it
    as a packed 382-byte struct misaligns every record after the first.
    """
    try:
        with open(UTMP_FILE, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    out = []
    for off in range(0, len(data) - UTMP_SIZE + 1, UTMP_SIZE):
        ut_type = struct.unpack_from("<h", data, off)[0]
        if ut_type != UTMP_USER_PROCESS:
            continue
        line = _cstr(data[off + 8:off + 40])
        user = _cstr(data[off + 44:off + 76])
        host = _cstr(data[off + 76:off + 332])
        start = struct.unpack_from("<i", data, off + 340)[0]
        out.append({"key": ("utmp", line, user, host, start),
                    "user": user, "line": line, "host": host,
                    "start": start})
    return out


def loginctl_sessions():
    """[{sid,user,uid,seat}] from loginctl, or None when unavailable."""
    try:
        r = subprocess.run(["loginctl", "list-sessions", "--no-legend",
                            "--no-pager"], capture_output=True, text=True,
                           timeout=4)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        out.append({"key": ("sid", parts[0]), "sid": parts[0],
                    "uid": parts[1], "user": parts[2],
                    "seat": parts[3] if len(parts) > 3 else "-"})
    return out


# -------------------------------------------------------------- ssh subsystem
# SSH is its own subsystem: its own event kinds, wording and state. It never
# feeds VIEWER_TIERS and never changes REMOTE_PORTS. Everything here is
# unprivileged; auth.log/btmp/journal are optional and only used when readable.
SSH_PORT = 22
PROC_ROOT = os.environ.get("VNC_WATCH_PROC", "/proc")
WTMP_FILE = os.environ.get("VNC_WATCH_WTMP", "/var/log/wtmp")
UTMP_RECORD_SIZE = _env_num("VNC_WATCH_UTMP_SIZE", 384, int)
SSH_SEEN_MAX = 2000
SSH_WEBHOOK_MAX = _env_num("VNC_WATCH_SSH_WEBHOOK_MAX", 20, int)
SSH_WEBHOOK_COOLDOWN = _env_num("VNC_WATCH_SSH_WEBHOOK_COOLDOWN", 30.0, float)
# Command capture is OFF by default. When enabled, only a redacted summary is
# ever stored: secrets masked, script bodies replaced, no /proc/*/environ.
SSH_CMDLINE = os.environ.get("VNC_WATCH_SSH_CMDLINE", "") == "1"
# Client-side detection (this host connecting OUT to a remote :22/:5900/...).
# Separate, gated, local-only signal: never feeds VIEWER_TIERS or REMOTE_PORTS.
# Disable with VNC_WATCH_SSH_OUTBOUND=0.
SSH_OUTBOUND = os.environ.get("VNC_WATCH_SSH_OUTBOUND", "1") != "0"
# Service ports whose *remote* end marks a connection as outbound. Kept distinct
# from REMOTE_PORTS (which stays inbound-only) so the two never blur.
OUTBOUND_PORTS = set(REMOTE_PORTS) | {SSH_PORT}

AUTOMATED_EXES = {"scp", "sftp", "rsync", "ansible", "ansible-playbook",
                  "git-upload-pack", "git-receive-pack", "nc", "ncat", "tar"}
SECRET_FLAGS = ("password", "passwd", "pass", "token", "secret", "api-key",
                "apikey", "auth", "private-key", "passphrase", "pin",
                "client-secret", "access-token", "refresh-token")
SCRIPT_FLAGS = {"-c", "--command", "--eval"}
# Privilege-escalation helpers. A user-owned process whose effective uid differs
# from the session uid is escalation; a root process under a non-root session is
# root command execution. The privileged pre-auth sshd runs as root by design and
# is a service anchor, not escalation.
ESCALATORS = {"sudo", "su", "doas", "pkexec", "runuser"}
SERVICE_ANCHORS = {"sshd", "sshd-session"}
# systemctl verbs: read-only inspection vs state change. Anything else is left
# "unknown" rather than guessed at.
SERVICE_VERBS_INSPECT = {"show", "status", "cat", "is-active", "is-enabled",
                         "is-failed", "list-units", "list-unit-files",
                         "list-sockets", "list-timers", "list-dependencies",
                         "get-default", "show-environment", "help"}
SERVICE_VERBS_CHANGE = {"start", "stop", "restart", "reload", "reload-or-restart",
                        "try-restart", "enable", "disable", "mask", "unmask",
                        "preset", "set-default", "set-property", "edit",
                        "daemon-reload", "daemon-reexec", "kill", "reset-failed"}

_ssh_wh_last = {}
_ssh_wh_times = collections.deque()


def _read(path, binary=False):
    try:
        with open(path, "rb" if binary else "r") as fh:
            return fh.read()
    except OSError:
        return None


def ssh_source_report():
    """Which SSH sources are readable right now (never requests privilege)."""
    def ok(p):
        return os.access(p, os.R_OK)
    return {
        "ss": shutil.which("ss") is not None,
        "loginctl": shutil.which("loginctl") is not None,
        "utmp": ok(UTMP_FILE),
        "wtmp": ok(WTMP_FILE),
        "proc": ok(os.path.join(PROC_ROOT, "1", "stat")),
        "auth_log": ok("/var/log/auth.log"),
        "btmp": ok("/var/log/btmp"),
    }


def ssh_established():
    """[(peer, peer_port, local_port)] for established inbound TCP to :22, or None."""
    try:
        out = subprocess.run(["ss", "-H", "-tn", "state", "established"],
                             capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    found = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        try:
            lport = int(p[2].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
        if lport != SSH_PORT:
            continue
        host, rport = norm_addr(p[3])
        found.append((host, rport, lport))
    return found


def outbound_peers():
    """Client-side established TCP connections to a remote monitored port.

    Returns [{rport, rhost, lport, lhost}] or None.

    Server-side vs client-side is inferred from ports, not from process or user
    ownership. A local socket whose own port is a monitored service port is
    treated as the server side *only when a listener is actually bound to that
    port* (queried via ss). If no such listener exists, a local socket on a
    service port is anomalous and is reported rather than silently dropped.

    Residual limitation: if a host both listens on a service port and a process
    also uses that same port as a *source* port (explicit bind or a port range
    that includes it), that client-side socket is still masked as server-side.
    This is a port-match OBSERVED signal only: it never feeds VIEWER_TIERS and
    never touches REMOTE_PORTS. It carries no process or user attribution.
    """
    if not SSH_OUTBOUND:
        return []
    try:
        out = subprocess.run(["ss", "-H", "-tn", "state", "established"],
                             capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    listen = listening_ports()          # None when unavailable
    found = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        rhost, rport = norm_addr(p[3])
        lhost, lport = norm_addr(p[2])
        try:
            rp, lp = int(rport), int(lport)
        except (IndexError, ValueError):
            continue
        if rp not in OUTBOUND_PORTS:
            continue
        # Server side only when the local service port is actually listening.
        # With listener info unavailable, stay conservative and skip it.
        if lp in OUTBOUND_PORTS and (listen is None or lp in listen):
            continue
        found.append({"rport": rp, "rhost": rhost,
                      "lport": lp, "lhost": lhost})
    return found


def ssh_listening():
    """True/False/None for a listener on :22."""
    ports = listening_ports()
    if ports is None:
        return None
    return SSH_PORT in ports


def loginctl_detail(sid):
    try:
        r = subprocess.run(["loginctl", "show-session", str(sid),
                            "-p", "User", "-p", "Remote", "-p", "RemoteHost",
                            "-p", "Service", "-p", "Leader", "-p", "TTY"],
                           capture_output=True, text=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    d = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        d[k.strip()] = v.strip()
    return d


def ssh_sessions():
    """Enriched remote sessions, or None when loginctl is unavailable.

    loginctl session id, POSIX process sid and Leader are distinct: the event
    keeps `loginctl_sid` and `leader_pid`; process correlation uses the session
    cgroup or the Leader PID, never the loginctl id as a POSIX sid.
    """
    base = loginctl_sessions()
    if base is None:
        return None
    utmp = utmp_sessions() or []
    by_line = {u["line"]: u for u in utmp if u.get("line")}
    out = []
    for s in base:
        d = loginctl_detail(s["sid"]) or {}
        remote = (d.get("Remote") == "yes" or bool(d.get("RemoteHost"))
                  or d.get("Service") == "sshd")
        if not remote:
            continue
        tty = d.get("TTY") or ""
        u = by_line.get(tty)
        if u is None and d.get("RemoteHost"):
            u = next((x for x in utmp
                      if x.get("user") == s["user"]
                      and x.get("host") == d.get("RemoteHost")), None)
        leader = d.get("Leader", "")
        out.append({
            "kind": "ssh-session",
            "key": f"sess:{s['sid']}",
            "loginctl_sid": s["sid"],
            "account": s["user"],
            "uid": s["uid"],
            "leader_pid": int(leader) if leader.isdigit() else None,
            "service": d.get("Service") or "sshd",
            "remote_host": d.get("RemoteHost") or (u["host"] if u else ""),
            "line": tty or (u["line"] if u else ""),
            "start": u["start"] if u else None,
            "evidence": "OBSERVED",
        })
    return out


def _stat_fields(pid):
    raw = _read(os.path.join(PROC_ROOT, pid, "stat"))
    if not raw:
        return None
    try:
        r = raw.rsplit(")", 1)[1].split()
        # f3=state r[0], f4=ppid r[1], f5=pgrp r[2], f6=session r[3],
        # f22=starttime r[19]
        return {"ppid": int(r[1]), "process_sid": int(r[3]),
                "start_ticks": int(r[19])}
    except (IndexError, ValueError):
        return None


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _proc_ids(pid):
    """(real, effective, saved, fs) uids from /proc/<pid>/status, or None.

    The Uid line is world-readable, so another user's effective uid is still
    attributable. A vanished process or a denied read returns None — unknown,
    and never treated as root."""
    raw = _read(os.path.join(PROC_ROOT, pid, "status"))
    if not raw:
        return None
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            f = line.split()
            try:
                return tuple(int(x) for x in f[1:5])
            except (ValueError, IndexError):
                return None
    return None


def _session_scope(pid):
    cg = _read(os.path.join(PROC_ROOT, pid, "cgroup")) or ""
    m = re.search(r"/session-([0-9A-Za-z]+)\.scope", cg)
    return m.group(1) if m else None


def _exe_name(pid):
    try:
        return os.path.basename(os.readlink(os.path.join(PROC_ROOT, pid, "exe")))
    except OSError:
        return (_read(os.path.join(PROC_ROOT, pid, "comm")) or "").strip() or "?"


def _redact_argv(argv):
    """Mask likely secrets; mask script bodies. Returns a safe token list."""
    out, mask_next, script_next = [], False, False
    for a in argv:
        if mask_next:
            out.append("***REDACTED***")
            mask_next = False
            continue
        if script_next:
            out.append("***SCRIPT***")
            script_next = False
            continue
        if a in SCRIPT_FLAGS:
            out.append(a)
            script_next = True
            continue
        low = a.lower()
        if a.startswith("-"):
            name = low.split("=", 1)[0].lstrip("-")
            if any(s in name for s in SECRET_FLAGS):
                if "=" in a:
                    out.append(a.split("=", 1)[0] + "=***REDACTED***")
                else:
                    out.append(a)
                    mask_next = True
                continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a):
            key = a.split("=", 1)[0].upper()
            if any(s in key for s in ("PASS", "TOKEN", "SECRET", "KEY", "AUTH")):
                out.append(a.split("=", 1)[0] + "=***REDACTED***")
                continue
        if re.search(r"(?i)bearer\s+\S+", a):
            out.append(re.sub(r"(?i)(bearer\s+)\S+", r"\1***REDACTED***", a))
            continue
        if re.match(r"^(ghp_|gho_|github_pat_|xox[abprs]-|AKIA|ASIA|sk-|eyJ)", a):
            out.append("***REDACTED***")
            continue
        out.append(a[:200])
    return out


def _safe_cmdline(pid):
    if not SSH_CMDLINE:
        return None
    raw = _read(os.path.join(PROC_ROOT, pid, "cmdline"), binary=True)
    if raw is None:
        return None
    parts = [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]
    return _redact_argv(parts) if parts else None


def _proc_argv(pid):
    """argv for classification ONLY. Never stored, logged, or transmitted.

    Read unprivileged, consumed by the classifiers below, and discarded. They
    return a fixed enum (an action word or an automation class), so raw
    arguments — and any secret inside them — cannot reach an event, the state
    file, the audit log, or a webhook payload."""
    raw = _read(os.path.join(PROC_ROOT, pid, "cmdline"), binary=True)
    if not raw:
        return []
    return [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]


def _systemctl_verb(argv):
    """The first bare token after 'systemctl' (its subcommand), or None."""
    for a in argv[1:]:
        if a.startswith("-"):
            continue
        return a
    return None


def _command_action(exe, argv):
    """Classify a process as inspect / configure / execute / unknown.

    Returns only a fixed action word derived from argv; argv itself is never
    returned or recorded."""
    if exe == "systemctl" and argv:
        v = _systemctl_verb(argv)
        if v in SERVICE_VERBS_INSPECT:
            return "inspect"
        if v in SERVICE_VERBS_CHANGE:
            return "configure"
        return "unknown"
    if exe in VNC_SERVER_COMMS:
        return "execute"
    # A server name inside a wrapped shell body (`sh -c '... x11vnc ...'`) is
    # still server execution; tokenize each argv element to see it.
    for a in argv:
        for tok in a.replace("\t", " ").split():
            if os.path.basename(tok) in VNC_SERVER_COMMS:
                return "execute"
    return "unknown"


def _automation_flavor(exe, argv):
    """Non-accusatory automation class for one process.

    'automation' for a known transport/automation binary.
    'ansible-become-compatible' when a privilege escalator is invoked with the
    non-interactive become shape (stdin password + non-interactive, i.e.
    `sudo -n -S ...`), the pattern Ansible's become plugin produces. This is a
    recognition, not a verdict — severity stays informational.
    'interactive' otherwise."""
    if exe in AUTOMATED_EXES:
        return "automation"
    if exe in ESCALATORS and argv:
        has_stdin = "-S" in argv or "--stdin" in argv
        non_interactive = "-n" in argv or "--non-interactive" in argv
        if has_stdin and non_interactive:
            return "ansible-become-compatible"
    return "interactive"


def ssh_processes(loginctl_sid, session_uid=None, session_account=None):
    """Processes in this logind session's cgroup, correlated and enriched.

    Identity stays loginctl_sid:pid:start_ticks, so a repeated poll is stable
    while a later run of the same executable is a new event. Adds real/effective
    uid, escalation against the session uid, the parent link within the session,
    and per-process automation/action classes. /proc is a point-in-time
    snapshot, never a command history; a vanished, recycled or unreadable
    process is skipped or left unknown rather than guessed at.
    """
    try:
        pids = [p for p in os.listdir(PROC_ROOT) if p.isdigit()]
    except OSError:
        return None
    want = str(loginctl_sid)
    sid_int = _as_int(session_uid)
    raw = []
    for pid in pids:
        if _session_scope(pid) != want:
            continue
        st = _stat_fields(pid)
        if not st:
            continue
        raw.append((pid, st, _exe_name(pid), _proc_ids(pid)))

    by_pid = {pid: (st, exe) for pid, st, exe, _ids in raw}
    out = []
    for pid, st, exe, ids in raw:
        # Re-read the start time: a pid recycled between listing and reading is
        # a different process and is dropped, never merged into this one.
        st2 = _stat_fields(pid)
        if not st2 or st2["start_ticks"] != st["start_ticks"]:
            continue
        uid, euid = (ids[0], ids[1]) if ids else (None, None)
        chain, seen, cur = [], set(), st["ppid"]
        while cur and cur not in seen:
            seen.add(cur)
            nxt = by_pid.get(str(cur))
            if nxt is None:
                break
            chain.append(nxt[1])
            cur = nxt[0]["ppid"]
        escalators = []
        for e in [exe] + chain:
            if e in ESCALATORS and e not in escalators:
                escalators.append(e)
        escalated = (uid is not None and euid is not None and sid_int is not None
                     and uid == sid_int and euid != sid_int)
        root = (euid == 0 and sid_int not in (0, None)
                and exe not in SERVICE_ANCHORS)
        argv = _proc_argv(pid)
        out.append({
            "kind": "ssh-command",
            "key": f"{want}:{pid}:{st['start_ticks']}",
            "identity": f"{want}:{pid}:{st['start_ticks']}",
            "loginctl_sid": want,
            "account": session_account,
            "pid": int(pid),
            "ppid": st["ppid"],
            "process_sid": st["process_sid"],
            "start_ticks": st["start_ticks"],
            "exe": exe,
            "uid": uid,
            "euid": euid,
            "parent_exe": chain[0] if chain else None,
            "depth": len(chain),
            "escalated": bool(escalated),
            "root": bool(root),
            "escalators": escalators,
            "automation": _automation_flavor(exe, argv),
            "action": _command_action(exe, argv),
            "cmd_redacted": _safe_cmdline(pid),
            "evidence": "OBSERVED",
        })
    return out


def ssh_activity(session, procs):
    """One grouped event for a session's correlated process activity.

    Metadata only: derived classes and executable names, never argv. This is the
    single structured alert for a session; the per-process ssh-command events
    stay in the local audit log."""
    sid = session.get("loginctl_sid")
    procs = list(procs or [])
    escalated = any(p.get("escalated") for p in procs)
    root_exec = any(p.get("root") for p in procs)
    actions = sorted({p.get("action") for p in procs
                      if p.get("action") and p.get("action") != "unknown"})
    flav = "interactive"
    if any(p.get("automation") == "ansible-become-compatible" for p in procs):
        flav = "ansible-become-compatible"
    elif any(p.get("automation") == "automation" for p in procs):
        flav = "automation"
    labels = []
    for p in procs:
        lbl = f"{p.get('exe')}:{p.get('action')}"
        if p.get("escalated"):
            lbl += ":escalated"
        if p.get("root"):
            lbl += ":root"
        labels.append(lbl)
    return {
        "kind": "ssh-session-activity",
        "key": f"sessact:{sid}:" + ":".join(sorted(
            p.get("identity", "") for p in procs)),
        "loginctl_sid": sid,
        "leader_pid": session.get("leader_pid"),
        "escalated": bool(escalated),
        "root_exec": bool(root_exec),
        "automation": flav,
        "actions": actions,
        "process_count": len(procs),
        "proc_labels": labels,
        "evidence": "OBSERVED",
    }


def wtmp_new_records(state):
    """(records, newstate, note). Only whole records past the stored offset.

    Validates the configured record size against the file before trusting it;
    on an unsupported layout it returns note='unsupported' rather than guessing.
    Never classifies a record as SSH: USER_PROCESS with a remote host is kept
    as historical, remote-login evidence only.
    """
    try:
        st = os.stat(WTMP_FILE)
    except OSError:
        return None, state, "unavailable"
    size = UTMP_RECORD_SIZE
    if size <= 0 or st.st_size % size != 0:
        return None, state, f"unsupported ({st.st_size} % {size})"
    prev = state or {}
    note = None
    offset = prev.get("offset", 0) if prev.get("inode") == st.st_ino else 0
    if prev and prev.get("inode") not in (None, st.st_ino):
        note = "rotated"
    elif offset > st.st_size:
        note = "truncated"
        offset = 0
    try:
        with open(WTMP_FILE, "rb") as fh:
            fh.seek(offset)
            data = fh.read()
    except OSError:
        return None, state, "unreadable"
    whole = len(data) - (len(data) % size)
    data = data[:whole]
    out = []
    for off in range(0, whole, size):
        ut_type = struct.unpack_from("<h", data, off)[0]
        if ut_type != UTMP_USER_PROCESS:
            continue
        user = _cstr(data[off + 44:off + 76])
        host = _cstr(data[off + 76:off + 332]) if size >= 332 else ""
        line = _cstr(data[off + 8:off + 40])
        if not host or host in (":0", ":1"):
            continue
        out.append({"user": user, "host": host, "line": line})
    newstate = {"inode": st.st_ino, "offset": offset + whole, "size": st.st_size}
    return out, newstate, note


def x11vnc_service_state():
    try:
        r = subprocess.run(["systemctl", "show", "x11vnc.service",
                            "-p", "ActiveState", "-p", "UnitFileState"],
                           capture_output=True, text=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    d = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        if k:
            d[k] = v
    return d or None


def ssh_key_state():
    """Size+mtime of this user's authorized_keys files (change detection)."""
    out = {}
    for rel in ("~/.ssh/authorized_keys", "~/.ssh/authorized_keys2"):
        p = os.path.expanduser(rel)
        try:
            st = os.stat(p)
            out[rel] = [st.st_size, int(st.st_mtime)]
        except OSError:
            out[rel] = None
    return out


def ssh_severity(ev):
    k = ev.get("kind")
    if ev.get("evidence") == "AUTHENTICATED":
        return "warning"
    if k == "ssh-session":
        return "info"
    if k == "ssh-connection":
        return "warning"
    if k == "ssh-session-activity":
        if ev.get("escalated") or ev.get("root_exec"):
            return "warning"
        if set(ev.get("actions") or ()) & {"configure", "execute"}:
            return "warning"
        return "info"
    if k == "ssh-command":
        a = ev.get("automation")
        return "info" if a in ("automated", "automation",
                               "ansible-become-compatible") else "warning"
    return "info"


def _ssh_audit_line(ev):
    k = ev.get("kind")
    if k == "ssh-x11vnc":
        return (f"ssh x11vnc service: {ev.get('from')} -> {ev.get('to')} "
                f"(service observation; cause unknown)")
    if k == "ssh-history":
        return f"ssh history: {ev.get('account')} from {ev.get('host')} ({ev.get('line')})"
    if k == "outbound":
        return (f"outbound tcp: {ev.get('lhost')}:{ev.get('lport')} -> "
                f"{ev.get('rhost')}:{ev.get('rport')} "
                f"(observed TCP to monitored dest port {ev.get('rport')})")
    who = f"{ev.get('account') or 'unknown'} from {ev.get('remote_host') or ev.get('peer') or '?'}"
    extra = ""
    if k == "ssh-command":
        extra = (f" exe={ev.get('exe')} pid={ev.get('pid')} "
                 f"start={ev.get('start_ticks')} action={ev.get('action')}")
        if ev.get("escalated"):
            extra += " escalated"
        if ev.get("root"):
            extra += " root"
        if ev.get("cmd_redacted"):
            extra += " cmd=" + " ".join(ev["cmd_redacted"])[:200]
    elif k == "ssh-session-activity":
        bits = []
        if ev.get("escalated"):
            bits.append("privilege-escalation")
        if ev.get("root_exec"):
            bits.append("root-execution")
        if ev.get("automation") and ev.get("automation") != "interactive":
            bits.append(ev["automation"])
        if ev.get("actions"):
            bits.append("actions=" + ",".join(ev["actions"]))
        procs = " ".join(ev.get("proc_labels") or [])
        extra = " (" + ", ".join(bits) + ")" if bits else ""
        if procs:
            extra += " [" + procs[:200] + "]"
    return f"{k}: {who}{extra} [evidence {ev.get('evidence')}]"


def ssh_remote_message(ev):
    """Metadata-only payload. Never includes argv, script bodies or env."""
    k = ev.get("kind")
    lines = []
    if k == "ssh-x11vnc":
        lines += [f"service: {ev.get('service')}",
                  f"change: {ev.get('from')} -> {ev.get('to')}",
                  "cause: unknown",
                  f"evidence: {ev.get('evidence')} (systemctl show)"]
        title = "vnc-watch: SERVICE STATE OBSERVATION"
    else:
        lines += [f"event: {k}",
                  "account: " + (ev.get("account") or "unknown")
                  + (f" (uid {ev['uid']})" if ev.get("uid") else ""),
                  "source: " + (ev.get("remote_host") or ev.get("peer") or "unknown")]
        if ev.get("loginctl_sid"):
            lines.append(f"session: loginctl {ev['loginctl_sid']}"
                         + (f" ({ev.get('line')}, {ev.get('service')})"
                            if ev.get("line") else ""))
        else:
            lines.append("session: none correlated")
        lines.append(f"evidence: {ev.get('evidence')}")
        if k == "ssh-command":
            lines += [f"executable: {ev.get('exe')}",
                      f"process: pid {ev.get('pid')} ppid {ev.get('ppid')} "
                      f"start_ticks {ev.get('start_ticks')}",
                      f"action: {ev.get('action')}",
                      f"automation: {ev.get('automation')}"]
        elif k == "ssh-session-activity":
            lines += [f"escalation: {'yes' if ev.get('escalated') else 'no'}",
                      f"root execution: {'yes' if ev.get('root_exec') else 'no'}",
                      f"automation: {ev.get('automation')}",
                      f"actions: {', '.join(ev.get('actions') or []) or 'none'}",
                      f"processes: {ev.get('process_count')}"]
        title = "vnc-watch: SSH " + k.split("-", 1)[1].upper()
    lines.append("note: metadata only; does not identify the operator")
    lines.append(f"time: {datetime.now():%Y-%m-%d %H:%M:%S %Z}")
    return title, "\n".join(lines)


def _ssh_should_webhook(ev):
    k = ev.get("kind")
    if k not in ("ssh-session", "ssh-connection", "ssh-command",
                 "ssh-session-activity", "ssh-x11vnc"):
        return False
    # Only bocal (or an unattributed connection/service observation) leaves the
    # machine. Another account's activity stays local unless explicitly allowed.
    return ev.get("account") in (None, "bocal")


def ssh_emit(ev, notify_local=True, webhook=True):
    """Audit always; local notify + webhook are best-effort and independent.

    Per-process ssh-command events are logged only (webhook=False): the grouped
    ssh-session-activity event is the single structured alert that leaves the
    machine. An outbound client connection to a remote SSH port is local-audit
    only by policy — ordinary `git`/`scp` over SSH is not a security event."""
    log_alert(_ssh_audit_line(ev))
    k = ev.get("kind")
    quiet = (k == "outbound" and _as_int(ev.get("rport")) == SSH_PORT)
    if notify_local and not quiet and k in ("ssh-session", "ssh-connection",
                                            "ssh-x11vnc", "outbound",
                                            "ssh-session-activity"):
        notify("SSH watch", _ssh_audit_line(ev), k,
               ssh_severity(ev) in ("warning", "critical"))
    if not webhook or quiet or not _ssh_should_webhook(ev):
        return
    if k == "ssh-command":
        key = f"cmd:{ev.get('account')}:{ev.get('exe')}"
    elif k == "ssh-session":
        key = f"sess:{ev.get('loginctl_sid')}"
    elif k == "ssh-session-activity":
        key = f"act:{ev.get('loginctl_sid')}"
    elif k == "ssh-connection":
        key = f"conn:{ev.get('peer')}:{ev.get('peer_port')}"
    else:
        key = f"x11vnc:{ev.get('from')}:{ev.get('to')}"
    now = time.monotonic()
    last = _ssh_wh_last.get(key)
    if last is not None and now - last < SSH_WEBHOOK_COOLDOWN:
        log_alert(f"ssh webhook cooled down: {key}")
        return
    _ssh_wh_last[key] = now
    while _ssh_wh_times and now - _ssh_wh_times[0] > 60:
        _ssh_wh_times.popleft()
    if len(_ssh_wh_times) >= SSH_WEBHOOK_MAX:
        log_alert(f"ssh webhook rate-limited: dropped {k} ({ev.get('account')})")
        return
    _ssh_wh_times.append(now)
    title, text = ssh_remote_message(ev)
    if not remote_alert(title, text):
        log_alert(f"ssh webhook not sent ({k}): no channel configured or queue full")


def ssh_scan():
    """One point-in-time snapshot of the SSH surface (used by watch and audit)."""
    return {
        "sessions": ssh_sessions(),
        "connections": ssh_established(),
        "outbound": outbound_peers(),
        "listening": ssh_listening(),
        "x11vnc": x11vnc_service_state(),
        "xclients": x_client_count(),
        "keys": ssh_key_state(),
        "sources": ssh_source_report(),
    }


def ssh_audit_section():
    """Human-readable SSH block for `audit` / `ssh` commands."""
    print("\n== SSH (separate subsystem, unprivileged) ==")
    src = ssh_source_report()
    print("  sources: " + ", ".join(
        f"{k}={'ok' if v else 'no'}" for k, v in sorted(src.items())))
    sess = ssh_sessions()
    if sess is None:
        print("  sessions: unavailable (loginctl)")
    elif not sess:
        print("  sessions: none remote")
    else:
        for s in sess:
            print(f"  session {s['loginctl_sid']}: {s['account']} "
                  f"from {s['remote_host'] or '?'} "
                  f"({s['service']}, {s['line'] or '-'})")
            procs = ssh_processes(s["loginctl_sid"], s.get("uid"),
                                  s.get("account")) or []
            for p in procs:
                marks = []
                if p["uid"] is not None:
                    marks.append(f"uid {p['uid']}/euid {p['euid']}")
                if p["escalated"]:
                    marks.append("escalated")
                if p["root"]:
                    marks.append("root")
                print(f"    proc {p['pid']} {p['exe']} "
                      f"({p['action']}/{p['automation']}"
                      + (", " + ", ".join(marks) if marks else "")
                      + f", start {p['start_ticks']})")
    conns = ssh_established()
    if conns is None:
        print("  connections: unavailable (ss)")
    else:
        for peer, rport, lport in conns:
            print(f"  tcp :{lport} <- {peer}:{rport} (established)")
    print("\n  == outbound (client-side; observed TCP to monitored dest ports) ==")
    outs = outbound_peers()
    if outs is None:
        print("  unavailable (ss)")
    elif not outs:
        print("  none")
    else:
        for o in outs:
            print(f"  {o['lhost']}:{o['lport']} -> {o['rhost']}:{o['rport']} "
                  f"(dest port {o['rport']}; observed TCP only)")
    x = x11vnc_service_state()
    if x:
        print(f"  x11vnc.service: {x.get('ActiveState')} "
              f"(unit {x.get('UnitFileState')})")
    if not src.get("auth_log"):
        print("  auth.log: unavailable (needs adm) - login method/key not read")
    if not src.get("btmp"):
        print("  btmp: unavailable (needs root/utmp) - failed logins not read")
    return 0


# ------------------------------------------------------------- state file
def snapshot(conns, sockets, listeners, extra):
    now = time.monotonic()
    items = []
    for c in conns[-40:]:
        dur = c["dur"] if c["closed"] else now - c["mono"]
        t, verdict = tier({**c, "dur": dur})
        items.append({
            "peer": c["peer"], "port": c["port"], "source": c["source"],
            "start": c["start"], "end": c["end"], "closed": c["closed"],
            "duration_s": round(dur, 1), "tier": t, "verdict": verdict,
            "correlated": c["correlated"],
        })
    return {
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pid": os.getpid(),
        "connections": items,
        "sockets": [{"port": p, "peer": peer, "remote_port": rp,
                     "since_s": round(now - t0, 1)}
                    for (p, peer, rp), t0 in sorted(sockets.items())],
        "listeners": sorted(p for p in listeners if p in REMOTE_PORTS)
        if listeners is not None else None,
        "ack": read_json(ACK_FILE),
        **extra,
    }


def write_state(obj):
    try:
        write_json_atomic(STATE_FILE, obj)
    except OSError as exc:
        print(f"state write failed: {exc}", flush=True)


# --------------------------------------------------------------------- live
def follow_live(args):
    moved = ensure_state_dir()
    if moved:
        log_alert(f"migrated {len(moved)} state file(s) into {STATE_DIR}")
        for old, new in moved:
            print(f"migrated {old} -> {new}", flush=True)

    lock_fd, lock_err = acquire_watch_lock()
    if lock_err:
        print(f"not starting: {lock_err}", flush=True)
        return 2

    try:
        tail = Tail(LOG, from_end=True)
    except OSError as exc:
        print(f"unavailable: cannot read {LOG}: {exc}\n(socket watch still runs)")
        tail = None

    pid = x11vnc_pid()
    ticks = cpu_ticks(pid) if pid else None
    cpu_load = collections.deque(maxlen=3)

    xinput_proc = None
    xi_tail = None
    xi_next_try = 0.0
    xtest = {}

    def reap_stale_xinput():
        """Kill our own leftover `xinput test-xi2` writers.

        SIGTERM does not run our finally block, so a restart would otherwise
        leave an orphan appending to the capped log at full speed.
        """
        me = os.getuid()
        killed = 0
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return 0
        for pid in pids:
            try:
                if os.stat(f"/proc/{pid}").st_uid != me:
                    continue
                with open(f"/proc/{pid}/comm") as fh:
                    if fh.read().strip() != "xinput":
                        continue
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
            except OSError:
                continue
            if "test-xi2" not in cmd:
                continue
            try:
                os.kill(int(pid), 15)
                killed += 1
            except OSError:
                pass
        return killed

    def start_xinput():
        """Run xinput test-xi2 into a file: pipes block-buffer and hide errors.

        Returns the Popen, or None if the log cannot be opened (full or
        unwritable state volume) so the caller can disable input-watch
        instead of crashing the daemon.
        """
        cmd = ["xinput", "test-xi2", "--root"]
        if shutil.which("stdbuf"):
            cmd = ["stdbuf", "-oL"] + cmd
        try:
            os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
            open(XI_LOG, "ab").close()
            out = open(XI_LOG, "ab", buffering=0)
            err = open(XI_LOG + ".err", "ab", buffering=0)
        except OSError as exc:
            log_alert(f"input-watch unavailable: cannot open {XI_LOG}: {exc}")
            return None
        try:
            return subprocess.Popen(cmd, stdout=out, stderr=err,
                                    stdin=subprocess.DEVNULL)
        except OSError as exc:
            log_alert(f"input-watch unavailable: cannot start xinput: {exc}")
            return None
        finally:
            out.close()
            err.close()

    last_rot_log = 0.0
    if args.input_watch:
        xtest = xtest_ids()
        if xtest:
            stale = reap_stale_xinput()
            if stale:
                print(f"reaped {stale} stale xinput writer(s)", flush=True)
                log_alert(f"reaped {stale} stale xinput writer(s) at startup")
            xinput_proc = start_xinput()
            if xinput_proc is not None:
                xi_tail = Tail(XI_LOG, from_end=True)

    samples = collections.deque(maxlen=15)
    n0 = x_client_count()
    if n0 is not None:
        samples.append(n0)
    # None means "unknown", not "no listeners": seeding an empty baseline would
    # make every existing service listener look new the first time ss works.
    ports0 = listening_ports()
    known_ports = ports0

    print(f"script mtime     : {datetime.fromtimestamp(os.path.getmtime(__file__)):%Y-%m-%d %H:%M:%S} ({__file__})")
    print(f"state dir        : {STATE_DIR}")
    print(f"x11vnc pid       : {pid if pid else 'unavailable'}")
    print(f"X clients now    : {n0 if n0 is not None else 'unavailable'}")
    print(f"autorepeat       : "
          f"{'on' if autorepeat_on() else 'off/unavailable'}"
          f" (supporting signal only)")
    if xi_tail:
        iw = f"on, XTEST ids={sorted(xtest)}, log cap {XI_LOG_MAX} B"
    else:
        iw = "off" if not args.input_watch else "requested, unavailable"
    print(f"input-watch      : {iw}")
    print("watching :5900 (VNC), :3389 (RDP)  (Ctrl-C to stop)\n")

    conns = []                      # log-derived, newest last
    uncorrelated = collections.deque(maxlen=10)
    sockets = {}                    # (port, peer, rport) -> monotonic first seen
    recent = collections.deque(maxlen=20)
    last_pid_check = time.monotonic()
    autorepeat_state = autorepeat_on()
    last_state_write = 0.0
    last_login_check = time.monotonic()
    me = os.environ.get("USER") or str(os.getuid())
    try:
        utmp_seen = {s["key"] for s in (utmp_sessions() or [])}
    except Exception:
        utmp_seen = set()
    try:
        sid_seen = {s["key"] for s in (loginctl_sessions() or [])}
    except Exception:
        sid_seen = set()

    # --- SSH subsystem: seed from persisted state so a restart never re-alerts
    prev_state = read_json(STATE_FILE) or {}
    prev_ssh = prev_state.get("ssh") or {}
    ssh_seen = set(prev_ssh.get("seen") or [])
    ssh_sessions_seen = set(prev_ssh.get("sessions_seen") or [])
    wtmp_state = prev_ssh.get("wtmp") or {}
    x11vnc_prev = prev_ssh.get("x11vnc")
    xclient_base = prev_ssh.get("xclients")
    key_prev = prev_ssh.get("keys") or {}
    ssh_state = ssh_scan()
    ssh_sources = ssh_state["sources"]
    ssh_prev_listen = ssh_state["listening"]
    log_alert("ssh sources: " + ", ".join(
        f"{k}={'ok' if v else 'unavailable'}"
        for k, v in sorted(ssh_sources.items())))
    if not wtmp_state:
        try:
            stt = os.stat(WTMP_FILE)
            if UTMP_RECORD_SIZE > 0 and stt.st_size % UTMP_RECORD_SIZE == 0:
                wtmp_state = {"inode": stt.st_ino, "offset": stt.st_size,
                              "size": stt.st_size}
                log_alert(f"ssh history: wtmp baseline {stt.st_size} bytes "
                          f"({stt.st_size // UTMP_RECORD_SIZE} records not "
                          f"replayed)")
            else:
                log_alert("ssh history unavailable: wtmp format unsupported")
        except OSError as exc:
            log_alert(f"ssh history unavailable: {exc}")
    for s in (ssh_state["sessions"] or []):
        ssh_seen.add(s["key"])
        if s["loginctl_sid"] in ssh_sessions_seen:
            continue
        ssh_sessions_seen.add(s["loginctl_sid"])
        log_alert(f"ssh pre-existing: {s['account']} from "
                  f"{s['remote_host'] or '?'} (session {s['loginctl_sid']}, "
                  f"{s['service']}) - surfaced, not alerted")
        for p in (ssh_processes(s["loginctl_sid"], s.get("uid"),
                                s.get("account")) or []):
            ssh_seen.add(p["identity"])
    for peer, rport, lport in (ssh_state["connections"] or []):
        ssh_seen.add(f"conn:{peer}:{rport}:{lport}")
    for o in (ssh_state["outbound"] or []):
        ssh_seen.add(f"out:{o['lhost']}:{o['lport']}:{o['rhost']}:{o['rport']}")
    if ssh_state["sessions"] is None:
        log_alert("ssh source unavailable: loginctl (session detection off)")
    if ssh_state["connections"] is None:
        log_alert("ssh source unavailable: ss (connection detection off)")
    last_ssh_check = time.monotonic()
    dirty = True

    def note(msg):
        recent.append(f"{datetime.now():%H:%M:%S} {msg}")

    # SIGTERM/SIGHUP must still run the cleanup block (close the tail, stop the
    # xinput child, release the lock). Default signal disposition skips
    # `finally`, which is why orphaned xinput writers had to be reaped at start.
    def _graceful(signum, frame):
        raise KeyboardInterrupt

    saved_signals = {}
    for _sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            saved_signals[_sig] = signal.signal(_sig, _graceful)
        except (OSError, ValueError):
            pass

    try:
        while True:
            now = time.monotonic()
            # 1) drain the log in a burst, then move on (no socket starvation)
            if tail:
                for line in tail.readlines():
                    ev = parse_line(line)
                    if not ev:
                        continue
                    stamp, kind, payload = ev
                    if kind == "got":
                        conns.append(new_conn(payload, stamp))
                        dirty = True
                        print(f"[{stamp}] connect from {payload}", flush=True)
                        note(f"connect {payload}")
                    elif kind == "gone":
                        c = close_conn(conns, payload)
                        if c is None:
                            print(f"[{stamp}] gone from {payload} with no open "
                                  f"connection", flush=True)
                            continue
                        dirty = True
                        c["end"] = stamp
                        c["dur"] = time.monotonic() - c["mono"]
                        t, verdict = tier(c)
                        print(f"[{stamp}]   {payload} closed after "
                              f"{c['dur']:.1f}s -> {t}", flush=True)
                        note(f"{payload} closed {t}")
                        if t == "CONFIRMED RFB SESSION":
                            alert("viewer", f"{t}: {payload} attached "
                                            f"{c['dur']:.1f}s since {c['start']}")
                            trigger_popup(
                                "VNC viewer attached",
                                f"{payload} - RFB handshake completed, "
                                f"session {c['dur']:.1f}s")
                        elif t == "PROBABLE":
                            alert("viewer", f"{t}: {payload} attached "
                                            f"{c['dur']:.1f}s since {c['start']} "
                                            f"(protocol only, no handshake seen)")
                            trigger_popup(
                                "VNC viewer attached (probable)",
                                f"{payload} - RFB version exchanged, no "
                                f"handshake observed")
                        elif t == "SUSPICIOUS":
                            alert("socket", f"held VNC socket from {payload} "
                                            f"for {c['dur']:.0f}s, no handshake",
                                  urgent=False)
                    elif kind in ("strong", "medium", "normal", "ws"):
                        c, peer = open_target(conns)
                        if c is None:
                            c = None
                            uncorrelated.append((stamp, kind, payload))
                            print(f"[{stamp}]   uncorrelated {kind}: "
                                  f"{payload[:60]}", flush=True)
                            log_alert(f"uncorrelated {kind}: more than one "
                                      f"connection open, not attributed")
                            dirty = True
                            continue
                        c[kind] = True
                        dirty = True
                        print(f"[{stamp}]   {kind}: {peer} {payload[:60]}",
                              flush=True)
                        if kind == "ws":
                            # rejected websocket probe: informational only
                            log_alert(f"websocket handshake from {peer} "
                                      f"(rejected) - informational")
                            note(f"websocket probe from {peer}")

            # 2) live sockets: one notification per new peer
            current = {}
            peers_now = socket_peers()
            if peers_now is None:
                print("unavailable: ss socket snapshot failed", flush=True)
                peers_now = []
            for port, peer, rport in peers_now:
                key = (port, peer, rport)
                current[key] = sockets.get(key, time.monotonic())
                if key not in sockets:
                    svc = {3389: "RDP", 5900: "VNC"}.get(port, f"port {port}")
                    print(f"!!! LIVE {svc} {peer}:{rport} <- local :{port}",
                          flush=True)
                    note(f"{svc} connection {peer}")
                    alert("socket", f"open {svc} connection from {peer} "
                                    f"(local :{port})")
                    trigger_popup(
                        f"{svc} connection open",
                        f"{peer}:{rport} -> this machine's :{port}")
                dirty = True
            sockets = current

            # 3) XTEST input: supporting signal, never part of the tier
            if xi_tail:
                for ln in xi_tail.readlines():
                    m = DEVLINE.search(ln)
                    if m and int(m.group(1)) in xtest:
                        alert("xtest",
                              f"XTEST-injected {xtest[int(m.group(1))]} input "
                              f"(supporting signal, source ambiguous)")

            # 3b) cap the XTEST dump every loop, so a burst cannot overshoot
            #     the cap by seconds worth of events before it is rotated.
            if xi_tail and xinput_proc is not None:
                try:
                    size = os.path.getsize(XI_LOG)
                except OSError:
                    size = 0
                if size > XI_LOG_MAX:
                    if xinput_proc.poll() is None:
                        xinput_proc.terminate()
                        try:
                            xinput_proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            xinput_proc.kill()
                    try:
                        os.truncate(XI_LOG, 0)
                    except OSError as exc:
                        print(f"xi log truncate failed: {exc}", flush=True)
                    xinput_proc = start_xinput()
                    xi_tail = (Tail(XI_LOG, from_end=True)
                               if xinput_proc is not None else None)
                    if now - last_rot_log >= 600:
                        last_rot_log = now
                        log_alert(f"xinput log rotated at {XI_LOG_MAX} bytes")
                    print(f"xinput log rotated (was {size} B)", flush=True)

            # 4) periodic checks
            if now - last_pid_check >= 2:
                # 4a) autorepeat flips off when x11vnc accepts a client
                ar = autorepeat_on()
                if ar is not None and autorepeat_state is not None \
                        and ar != autorepeat_state:
                    autorepeat_state = ar
                    if not ar:
                        alert("autorepeat", "X key autorepeat turned OFF "
                                            "(supporting signal: x11vnc accepts "
                                            "a client when it does this)",
                              urgent=False)

                # 4b) new listener on a remote-viewing port
                ports = listening_ports()
                if ports is not None:
                    if known_ports is None:
                        known_ports = ports   # first good read: baseline only
                        new = set()
                    else:
                        new = {p for p in ports - known_ports
                               if p in REMOTE_PORTS}
                        known_ports = ports
                    for p in new:
                        alert("port", f"new listener on remote-viewing port {p}")

                # 4b2) new interactive / remote sessions
                if now - last_login_check >= 10:
                    last_login_check = now
                    us = utmp_sessions()
                    if us is not None:
                        for s in us:
                            if s["key"] in utmp_seen:
                                continue
                            utmp_seen.add(s["key"])
                            where = s["host"] or "local console"
                            alert("login",
                                  f"new session: {s['user']} on {s['line']} "
                                  f"from {where}",
                                  urgent=(s["user"] != me),
                                  key=f"login:{s['key']}")
                            note(f"login {s['user']}@{s['line']} {where}")
                    ls = loginctl_sessions()
                    if ls is not None:
                        for s in ls:
                            if s["key"] in sid_seen:
                                continue
                            sid_seen.add(s["key"])
                            alert("login",
                                  f"new loginctl session {s['sid']}: "
                                  f"{s['user']} seat {s['seat']}",
                                  urgent=(s["user"] != me),
                                  key=f"login:{s['key']}")
                            note(f"session {s['sid']} {s['user']}")

                # 4b3) SSH subsystem: separate kinds, never VNC/RDP tiers
                if now - last_ssh_check >= 5:
                    last_ssh_check = now
                    snap = ssh_scan()
                    ssh_state = snap
                    sess_now = snap["sessions"]
                    if sess_now is not None:
                        for s in sess_now:
                            if s["key"] in ssh_seen:
                                continue
                            ssh_seen.add(s["key"])
                            ssh_emit(dict(s))
                        for s in sess_now:
                            fresh = [p for p in (ssh_processes(
                                s["loginctl_sid"], s.get("uid"),
                                s.get("account")) or [])
                                if p["identity"] not in ssh_seen]
                            for p in fresh:
                                ssh_seen.add(p["identity"])
                                # per-process detail: local audit log only
                                ssh_emit(dict(p, remote_host=s["remote_host"],
                                              service=s["service"],
                                              line=s.get("line")),
                                         notify_local=False, webhook=False)
                            if fresh:
                                act = ssh_activity(s, fresh)
                                ssh_emit(dict(act, account=s["account"],
                                              uid=s["uid"],
                                              remote_host=s["remote_host"],
                                              service=s["service"],
                                              line=s.get("line")))
                    known_peers = {s["remote_host"] for s in (sess_now or [])
                                   if s["remote_host"]}
                    if snap["connections"] is not None:
                        for peer, rport, lport in snap["connections"]:
                            key = f"conn:{peer}:{rport}:{lport}"
                            if key in ssh_seen:
                                continue
                            ssh_seen.add(key)
                            if peer in known_peers:
                                continue
                            ssh_emit({"kind": "ssh-connection",
                                      "evidence": "OBSERVED", "account": None,
                                      "peer": peer, "peer_port": rport,
                                      "local_port": lport,
                                      "remote_host": peer})
                    if snap["outbound"] is not None:
                        for o in snap["outbound"]:
                            key = (f"out:{o['lhost']}:{o['lport']}:"
                                   f"{o['rhost']}:{o['rport']}")
                            if key in ssh_seen:
                                continue
                            ssh_seen.add(key)
                            ssh_emit({"kind": "outbound",
                                      "evidence": "OBSERVED", "account": None,
                                      "lhost": o["lhost"], "lport": o["lport"],
                                      "rhost": o["rhost"], "rport": o["rport"]})
                    if snap["listening"] is not None:
                        if ssh_prev_listen is not None \
                                and snap["listening"] != ssh_prev_listen:
                            ssh_emit({"kind": "ssh-daemon",
                                      "evidence": "OBSERVED", "account": None,
                                      "from": ssh_prev_listen,
                                      "to": snap["listening"]},
                                     notify_local=False)
                        ssh_prev_listen = snap["listening"]
                    if snap["x11vnc"] and x11vnc_prev \
                            and snap["x11vnc"] != x11vnc_prev:
                        ssh_emit({"kind": "ssh-x11vnc",
                                  "evidence": "OBSERVED",
                                  "service": "x11vnc.service",
                                  "from": x11vnc_prev.get("ActiveState"),
                                  "to": snap["x11vnc"].get("ActiveState")})
                    if snap["x11vnc"]:
                        x11vnc_prev = snap["x11vnc"]
                    c = snap["xclients"]
                    if c is not None and xclient_base is not None \
                            and c > xclient_base + 2:
                        ssh_emit({"kind": "ssh-xclient",
                                  "evidence": "OBSERVED", "account": None,
                                  "count": c, "baseline": xclient_base},
                                 notify_local=False)
                    if c is not None:
                        xclient_base = c
                    ks = snap["keys"]
                    for rel, st in ks.items():
                        if key_prev.get(rel) != st and key_prev.get(rel) is not None:
                            log_alert(f"ssh key file changed: {rel} "
                                      f"{key_prev.get(rel)} -> {st}")
                    key_prev = ks
                    recs, wtmp_state, wnote = wtmp_new_records(wtmp_state)
                    if wnote in ("rotated", "truncated", "unsupported"):
                        log_alert(f"ssh wtmp {wnote}")
                    if recs:
                        log_alert(f"ssh history: {len(recs)} new remote login "
                                  f"record(s): " + ", ".join(
                                      f"{r['user']}@{r['host']}"
                                      for r in recs[:5]))
                    if len(ssh_seen) > SSH_SEEN_MAX:
                        ssh_seen = set(list(ssh_seen)[-SSH_SEEN_MAX:])

                # 4c) CPU: neutral observation, log only, never notify
                if pid and ticks is not None:
                    cur = cpu_ticks(pid)
                    if cur is not None:
                        cpu_load.append((cur - ticks) / os.sysconf("SC_CLK_TCK"))
                        if len(cpu_load) == 3 and min(cpu_load) > 1.0:
                            log_alert(f"x11vnc CPU use: "
                                      f"{sum(cpu_load):.1f}s in 6s "
                                      f"(supporting signal only)")
                            cpu_load.clear()
                        ticks = cur

                # 4d) X client count, opt-in
                if args.x_watch:
                    n = x_client_count()
                    if n is not None:
                        samples.append(n)
                        if len(samples) >= 5:
                            base = sorted(samples)[len(samples) // 2]
                            if n > base + 8:
                                alert("xclients", f"X clients {base} -> {n} "
                                                  f"(bridge/app launch, "
                                                  f"supporting signal only)",
                                      urgent=False)

                # 4e) re-resolve x11vnc pid after a service restart
                if now - last_pid_check >= 30:
                    last_pid_check = now
                    fresh = x11vnc_pid()
                    if fresh != pid:
                        pid, ticks = fresh, (cpu_ticks(fresh) if fresh else None)

                # 4f) restart xinput if it died; explain why in the log
                if xi_tail and xinput_proc is not None \
                        and xinput_proc.poll() is not None:
                    if now >= xi_next_try:
                        rc = xinput_proc.returncode
                        print(f"xinput exited (rc={rc}), restarting", flush=True)
                        log_alert(f"xinput test-xi2 exited rc={rc}; restarting")
                        xinput_proc = start_xinput()
                        if xinput_proc is None:
                            xi_tail = None      # start_xinput logged the reason
                        else:
                            xi_tail = Tail(XI_LOG, from_end=True)
                            xi_next_try = now + 10

            # 4g) publish state for the menu
            if dirty or now - last_state_write >= 5:
                sx = x11vnc_pid()
                write_state(snapshot(
                    conns, sockets, listening_ports(),
                    {"input_watch": bool(xtest),
                     "xi_log_bytes": safe_size(XI_LOG),
                     "unavailable": {
                         "x11vnc": sx is None,
                         "autorepeat": autorepeat_state is None,
                         "xtest": not xtest,
                     },
                     "ssh": {
                         "sources": ssh_sources,
                         "seen": sorted(ssh_seen)[-SSH_SEEN_MAX:],
                         "sessions_seen": sorted(ssh_sessions_seen),
                         "wtmp": wtmp_state,
                         "x11vnc": x11vnc_prev,
                         "xclients": xclient_base,
                         "keys": key_prev,
                         "outbound": (ssh_state["outbound"] or []),
                         "sessions": [
                             {k: s.get(k) for k in
                              ("loginctl_sid", "account", "uid",
                               "remote_host", "service", "line")}
                             for s in (ssh_state["sessions"] or [])],
                     },
                     "recent": list(recent)}))
                last_state_write = now
                dirty = False

            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\nstopped")
        return 0
    finally:
        for _sig, _prev in saved_signals.items():
            try:
                signal.signal(_sig, _prev)
            except (OSError, ValueError):
                pass
        if tail:
            tail.close()
        if xi_tail:
            xi_tail.close()
        if xinput_proc and xinput_proc.poll() is None:
            xinput_proc.terminate()
            try:
                xinput_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                xinput_proc.kill()
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


# -------------------------------------------------------------------- menu
# One table is the single source of truth. BROWSER_ROOTS and BROWSER_COMMS are
# derived from it so a browser can never be detectable but unhandled, or
# handled but undetectable (see browser_config_ok).
BROWSERS = [
    {"name": "firefox", "family": "firefox",
     "roots": [("firefox (native)", "~/.mozilla/firefox"),
               ("firefox (snap)", "~/snap/firefox/common/.mozilla/firefox"),
               ("firefox (flatpak)",
                "~/.var/app/org.mozilla.firefox/.mozilla/firefox")],
     "comms": ["firefox"], "flatpak_ids": ["org.mozilla.firefox"]},
    {"name": "chromium", "family": "chromium",
     "roots": [("chromium (native)", "~/.config/chromium"),
               ("chromium (snap)", "~/snap/chromium/common/chromium"),
               ("chromium (flatpak)",
                "~/.var/app/org.chromium.Chromium/config/chromium")],
     "comms": ["chromium", "chromium-browse"],
     "flatpak_ids": ["org.chromium.Chromium"]},
    {"name": "google-chrome", "family": "chromium",
     "roots": [("chrome (native)", "~/.config/google-chrome"),
               ("chrome (flatpak)",
                "~/.var/app/com.google.Chrome/config/google-chrome")],
     "comms": ["chrome"], "flatpak_ids": ["com.google.Chrome"]},
    {"name": "brave", "family": "chromium",
     "roots": [("brave (native)", "~/.config/BraveSoftware/Brave-Browser"),
               ("brave (flatpak)",
                "~/.var/app/com.brave.Browser/config/BraveSoftware/"
                "Brave-Browser")],
     "comms": ["brave"], "flatpak_ids": ["com.brave.Browser"]},
    {"name": "edge", "family": "chromium",
     "roots": [("edge (native)", "~/.config/microsoft-edge"),
               ("edge (flatpak)",
                "~/.var/app/com.microsoft.Edge/config/microsoft-edge")],
     "comms": ["msedge"], "flatpak_ids": ["com.microsoft.Edge"]},
    {"name": "vivaldi", "family": "chromium",
     "roots": [("vivaldi (native)", "~/.config/vivaldi"),
               ("vivaldi (flatpak)",
                "~/.var/app/com.vivaldi.Vivaldi/config/vivaldi")],
     "comms": ["vivaldi-bin", "vivaldi"],
     "flatpak_ids": ["com.vivaldi.Vivaldi"]},
    {"name": "opera", "family": "opera",
     "roots": [("opera (native)", "~/.config/opera"),
               ("opera (flatpak)",
                "~/.var/app/com.opera.Opera/config/opera")],
     "comms": ["opera"], "flatpak_ids": ["com.opera.Opera"]},
]
BROWSER_ROOTS = [(label, rel) for b in BROWSERS for label, rel in b["roots"]]
BROWSER_COMMS = {c for b in BROWSERS for c in b["comms"]}
PROFILE_FILES = ["History", "Cookies", "Login Data", "Web Data", "Bookmarks",
                 "Preferences", "places.sqlite", "cookies.sqlite",
                 "logins.json", "key4.db", "cert9.db"]
PROFILE_DIRS = ["Cache", "Code Cache", "cache2"]
# Profile subdirectories to ignore when scanning a Chromium-family root.
PROFILE_SKIP = {"guest profile", "system profile", "crashpad", "shadercache",
                "component crx cache", "graphiteDawnCache", "grshader cache"}


def dir_size(path, limit=20000):
    total = files = 0
    for root, dirs, names in os.walk(path, onerror=lambda e: None):
        for name in names:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
            files += 1
            if files >= limit:
                return total, True
    return total, False


def in_home(path):
    home = os.path.realpath(os.path.expanduser("~"))
    real = os.path.realpath(path)
    return real == home or real.startswith(home + os.sep)


def discover_profiles(root, family="chromium"):
    """Profile directories under `root` that hold browser data.

    firefox: entries named in profiles.ini, else any dir with places.sqlite or
             cookies.sqlite. chromium: `Default` and `Profile N`, plus any dir
             that already holds profile files. opera: subdirectories, and a
             legacy install that keeps its profile files directly in `root`."""
    found = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return found

    def names_of(path):
        try:
            return set(os.listdir(path))
        except OSError:
            return set()

    if family == "firefox":
        ini = os.path.join(root, "profiles.ini")
        try:
            import configparser
            cp = configparser.ConfigParser()
            cp.read(ini)
            for sec in cp.sections():
                if not sec.lower().startswith("profile"):
                    continue
                p = cp.get(sec, "Path", fallback=None)
                if not p:
                    continue
                cand = p if os.path.isabs(p) else os.path.join(root, p)
                if os.path.isdir(cand) and cand not in found:
                    found.append(cand)
        except (OSError, configparser.Error):
            pass
        if found:
            return found
        for e in entries:
            if e.is_dir(follow_symlinks=False) and (
                    names_of(e.path) & {"places.sqlite", "cookies.sqlite"}):
                found.append(e.path)
        return found

    for e in entries:
        if not e.is_dir(follow_symlinks=False):
            continue
        if e.name.lower() in PROFILE_SKIP:
            continue
        names = names_of(e.path)
        if (e.name == "Default" or e.name.startswith("Profile ")
                or names & set(PROFILE_FILES)
                or {"History", "Cookies", "Cache", "cache2"} & names):
            found.append(e.path)
    if family == "opera":
        names = names_of(root)                # legacy: profile files at root
        if (names & set(PROFILE_FILES)
                or {"History", "Cookies"} & names) and root not in found:
            found.insert(0, root)
    return found


def browser_inventory():
    print("== browser inventory (metadata only: existence and size) ==\n")
    any_found = False
    for b in BROWSERS:
        for label, rel in b["roots"]:
            root = os.path.expanduser(rel)
            if not os.path.isdir(root):
                continue
            if not in_home(root):
                print(f"{label}: {root} is outside your home - skipped")
                continue
            any_found = True
            total, truncated = dir_size(root)
            print(f"{label}: {root}")
            print(f"  total: {total / 1048576:.1f} MB"
                  f"{' (partial scan)' if truncated else ''}")
            for prof in discover_profiles(root, b["family"]):
                size, _ = dir_size(prof)
                print(f"  profile {os.path.basename(prof)}: "
                      f"{size / 1048576:.1f} MB")
                for name in PROFILE_FILES:
                    p = os.path.join(prof, name)
                    try:
                        st = os.lstat(p)
                        print(f"    {name:<16} {st.st_size:>10} bytes")
                    except OSError:
                        pass
                for name in PROFILE_DIRS:
                    p = os.path.join(prof, name)
                    if os.path.isdir(p):
                        size, _ = dir_size(p)
                        print(f"    {name + '/':<16} {size:>10} bytes")
            print()
    if not any_found:
        print("No browser profile directories found.")
    print("Nothing was opened, read, or deleted. No history, cookies, or "
          "credentials were accessed.")


def _marker_matches(name):
    """True if a process name matches a known browser marker exactly.

    Browser comms are short (all under the 15-char comm limit) and each marker
    is a full process name, so an exact match is both sufficient and safe. It
    avoids catching look-alike helpers such as `chrome_crashpad` (a crashpad
    handler, not a browser) or `brave-browser-s` (the launcher shell script)."""
    return (name or "").lower() in BROWSER_COMMS


def _is_browser_proc(pid, comm):
    """Detect a browser by comm, cmdline argv0, or flatpak cgroup app-id."""
    if _marker_matches(comm):
        return True
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
        first = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
        argv0 = os.path.basename(first).lower()
        if argv0.endswith(".exe"):
            argv0 = argv0[:-4]
        if _marker_matches(argv0):
            return True
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            cg = fh.read()
    except OSError:
        cg = ""
    for b in BROWSERS:
        for fid in b.get("flatpak_ids", ()):
            if f"app-{fid}" in cg or f"/{fid}" in cg:
                return True
    return False


def running_browsers():
    out = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        try:
            if os.stat(f"/proc/{pid}").st_uid != os.getuid():
                continue
            with open(f"/proc/{pid}/comm") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        if _is_browser_proc(pid, comm):
            out.append((int(pid), comm or "?"))
    return sorted(out)


def running_discord():
    """This user's Discord processes (native or flatpak)."""
    out = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        try:
            if os.stat(f"/proc/{pid}").st_uid != os.getuid():
                continue
            with open(f"/proc/{pid}/comm") as fh:
                comm = fh.read().strip().lower()
        except OSError:
            continue
        if comm.startswith("discord") or comm in ("betterdiscord",):
            out.append((int(pid), comm))
    return sorted(out)


def screen_locked():
    try:
        r = subprocess.run(["gdbus", "call", "--session",
                            "--dest", "org.gnome.ScreenSaver",
                            "--object-path", "/org/gnome/ScreenSaver",
                            "--method", "org.gnome.ScreenSaver.GetActive"],
                           capture_output=True, text=True, timeout=3)
        return "true" in r.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def privacy_status():
    print("== privacy status ==\n")
    br = running_browsers()
    counts = collections.Counter(c for _, c in br)
    print("browsers running :",
          ", ".join(f"{name} ({n} processes)" for name, n in sorted(counts.items()))
          or "none")
    locked = screen_locked()
    print("screen locked    :",
          {True: "yes", False: "no", None: "unavailable"}[locked])
    try:
        servers = vnc_servers()
        desc = ", ".join(f"{s['comm']} pid {s['pid']}" for s in servers)
    except RuntimeError as exc:
        desc = f"unavailable ({exc})"
    print("vnc servers      :", desc or "none")
    ports = listening_ports()
    if ports is None:
        print("remote listeners : unavailable")
    else:
        hit = sorted(p for p in ports if p in REMOTE_PORTS)
        print("remote listeners :", ", ".join(f":{p}" for p in hit) or "none")
    sr = socket_peers()
    if sr is None:
        print("active remote    : unavailable")
    else:
        print("active remote    :",
              ", ".join(f"{peer} -> :{p}" for p, peer, _ in sr) or "none")
    print("\nA root operator can hide all of the above. This is a best-effort view.")


LOCK_SOCKET = "/run/42-lock/control"
# Bounded poll for the authoritative `locked: true` state after a lock command.
# The supervisor's reply and its state-file write are not contractually
# ordered, so the reply is never trusted on its own.
LOCK_CONFIRM_TIMEOUT = _env_num("VNC_WATCH_LOCK_CONFIRM_TIMEOUT", 5.0, float)
LOCK_CONFIRM_POLL = 0.2


def _lock_via_supervisor():
    """Ask the 42 lock supervisor to lock. Returns True on a `LOCKED` reply.

    Some managed images (e.g. a 42 school seat) route the lock through a
    supervisor on this socket; GNOME's ScreenShield is absent there, so the
    D-Bus and loginctl paths silently do nothing. A `LOCKED` reply is the
    supervisor's acceptance — not proof the seat is locked (see
    `_confirm_lock`)."""
    if not os.path.exists(LOCK_SOCKET):
        return False
    try:
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(15)
            conn.connect(LOCK_SOCKET)
            conn.sendall(b"lock\n")
            return conn.recv(64) == b"LOCKED\n"
    except OSError:
        return False


def _confirm_lock(before_locked, timeout=None):
    """Verify a lock request against the authoritative seat-state file.

    Polls VNC_WATCH_LOCK_FILE for `locked: true` until it holds or `timeout`
    elapses. The socket reply and per-mechanism exit codes are not trusted, and
    GNOME ScreenShield / loginctl are never used as the verification source.

    `before_locked` is the `locked` value read before the command was sent, so
    an already-locked seat is not credited to this request. Returns
    (status, detail):

      "locked"      -- was not locked before; now authoritatively locked
      "already"     -- was already locked before the request (no transition)
      "unconfirmed" -- never reached `locked: true` (missing/malformed file,
                       permission error, stale state, or timeout)
    """
    timeout = LOCK_CONFIRM_TIMEOUT if timeout is None else timeout
    deadline = time.monotonic() + max(0.0, timeout)
    detail = "seat state unavailable"
    while True:
        state, detail = _locked_now()
        if state is True:
            if before_locked is True:
                return "already", "seat was already locked before the request"
            return "locked", "seat state reports locked"
        if time.monotonic() >= deadline:
            return "unconfirmed", detail
        time.sleep(LOCK_CONFIRM_POLL)


def lock_session():
    """Send a lock and verify it. Returns (ok, how).

    Tries, in order: the 42 lock supervisor (the real locker on a managed
    seat), GNOME's ScreenSaver D-Bus service, then loginctl. Each is only a
    *send*; the outcome is verified by `_confirm_lock` against the authoritative
    seat-state file, never by trusting exit codes — `loginctl lock-session`
    exits 0 on this seat without locking anything.
    """
    before, _ = _locked_now()
    if _lock_via_supervisor():
        status, why = _confirm_lock(before)
        if status == "locked":
            return True, "ft_lock (42 lock supervisor)"
        if status == "already":
            return True, "already locked (42 lock supervisor)"
        return False, f"lock supervisor replied LOCKED but {why}"
    try:
        subprocess.run(
            ["gdbus", "call", "--session",
             "--dest", "org.gnome.ScreenSaver",
             "--object-path", "/org/gnome/ScreenSaver",
             "--method", "org.gnome.ScreenSaver.Lock"],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass
    else:
        status, _why = _confirm_lock(before)
        if status == "locked":
            return True, "org.gnome.ScreenSaver.Lock"
    user = os.environ.get("USER") or str(os.getuid())
    try:
        sids = subprocess.run(["loginctl", "show-user", user, "-p", "Sessions",
                               "--value"], capture_output=True, text=True,
                              timeout=5).stdout.split()
    except (OSError, subprocess.SubprocessError):
        sids = []
    for sid in sids:
        try:
            subprocess.run(["loginctl", "lock-session", sid],
                           capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        status, _why = _confirm_lock(before)
        if status == "locked":
            return True, f"loginctl lock-session {sid}"
    return False, ("no working lock mechanism, or the seat state never "
                   "reported locked (lock supervisor, session bus and "
                   "loginctl failed)")


def ask(prompt):
    try:
        return input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return ""


def confirm(text):
    print(text)
    return ask("Proceed? [y/N] ") in ("y", "yes")


def menu_action(name, fn):
    try:
        fn()
        outcome = "ok"
    except Exception as exc:                 # report, never crash the menu
        print(f"failed: {exc}")
        outcome = f"error: {type(exc).__name__}"
    log_alert(f"menu action={name} outcome={outcome}")
    print()


def show_evidence(state):
    if not state:
        print("No state file yet - is `vnc-watch watch` running?\n")
        return
    print(f"state updated {state.get('updated')} (daemon pid {state.get('pid')})")
    print(f"unavailable: {state.get('unavailable')}\n")
    conns = state.get("connections") or []
    if conns:
        print(f"{'START':<21} {'PEER':<18} {'DUR':>7}  {'TIER':<22} CLOSED")
        print("-" * 84)
        for c in conns[-20:]:
            print(f"{c['start']:<21} {c['peer']:<18} "
                  f"{c['duration_s']:7.1f}s  {c['tier']:<22} "
                  f"{'yes' if c['closed'] else 'no'}")
    else:
        print("no connections recorded by the daemon")
    socks = state.get("sockets") or []
    print("\nsockets now:", ", ".join(
        f"{s['peer']}->:{s['port']} ({s['since_s']:.0f}s)" for s in socks) or "none")
    print("recent:")
    for line in (state.get("recent") or [])[-10:]:
        print(f"  {line}")
    print()


def show_log():
    try:
        with open(ALERT_LOG) as fh:
            lines = fh.readlines()[-25:]
    except OSError as exc:
        print(f"alert log unavailable: {exc}\n")
        return
    print("== last 25 alert-log lines ==")
    for line in lines:
        print("  " + line.rstrip())
    print()


def run_close_vnc(assume_yes=False, apply=True):
    """Shared path for `kick` and the menu entry. Returns an exit code."""
    preview = close_vnc(apply=False)
    if apply:
        preview["notes"] = [n for n in preview["notes"]
                            if not n.startswith("dry run")]
    print("\n== close VNC server ==\n")
    print(format_close_result(preview))

    actionable = [s for s in preview["found"] if s["base"] is not None]
    if actionable:
        if not apply:
            log_alert("action=close_vnc outcome=dry-run")
            print()
            return 0
        print("\nThis ends the whole VNC server, so every viewer is dropped.")
        print("X11 has no per-viewer disconnect. A root operator can restart it.")
        if not assume_yes and not confirm("Close it now?"):
            print("cancelled\n")
            log_alert("action=close_vnc outcome=cancelled")
            return 1
        res = close_vnc(apply=True)
        print("\n" + format_close_result(res))
        pids = ",".join(str(s["pid"]) for s in res["killed"]) or "-"
        outcome = "ok" if res["verified"] else "unverified"
        log_alert(f"action=close_vnc pids={pids} outcome={outcome}")
        remote_send_sync(*remote_message(
            "action", f"close_vnc pids={pids} {outcome} (manual)"))
        return 0 if res["verified"] else 2

    # No addressable VNC server. RDP runs as this user, so it can be stopped.
    active, port = rdp_status()
    if active is None:
        print("\n  note  : gnome-remote-desktop state unavailable")
        return 1
    if not active:
        print("\n  note  : nothing to close (no VNC server, no RDP service)")
        log_alert("action=close_vnc outcome=nothing-to-close")
        return 1
    print(f"\n  note  : gnome-remote-desktop is active "
          f"(listening on :3389: {'yes' if port else 'no'})")
    if not apply:
        log_alert("action=close_rdp outcome=dry-run")
        print()
        return 0
    print("Stopping it ends every RDP session it is serving.")
    if not assume_yes and not confirm("Stop gnome-remote-desktop now?"):
        print("cancelled\n")
        log_alert("action=close_rdp outcome=cancelled")
        return 1
    res = close_rdp(apply=True)
    print(f"  stopped: {res['stopped']}")
    for n in res["notes"]:
        print(f"  note  : {n}")
    log_alert(f"action=close_rdp outcome="
              f"{'ok' if res['stopped'] else 'failed'}")
    remote_send_sync(*remote_message(
        "action", f"close_rdp {'ok' if res['stopped'] else 'failed'} (manual)"))
    print()
    return 0 if res["stopped"] else 2


def menu_close_vnc():
    try:
        run_close_vnc()
    except Exception as exc:                 # report, never crash the menu
        print(f"failed: {exc}")
        log_alert(f"menu action=close_vnc outcome=error:{type(exc).__name__}")


def menu_clear():
    """Terminal-menu clear action. Same guarded path as the panel/tray wipe,
    confirmed in the terminal rather than a GTK dialog."""
    locked, why = active_lock_window()
    if locked:
        print(f"clear refused: {why} (exam/lock window active)\n")
        log_alert(f"menu action=clear outcome=refused:{why}")
        return
    targets, browsers, total = _clear_survey()
    if not _clear_has_work(targets, browsers):
        print("nothing to clear (no supported browser/Discord data and no "
              "supported browser running)\n")
        return
    if targets:
        lead = (f"Close browsers and delete their local data? {len(targets)} "
                 f"item(s), about {total / 1048576:.1f} MB — full profile "
                 f"reset: history, cookies, sessions, caches, autofill, saved "
                 f"logins, bookmarks and settings.")
    else:
        lead = (f"No local browser/Discord data found, but {len(browsers)} "
                f"supported browser process(es) are running.")
    prompt = (lead + " Running browsers are closed automatically (SIGTERM, "
              "then SIGKILL); open tabs and unsaved work are lost. Next "
              "launch starts from a fresh profile. Cannot be undone.")
    if not confirm(prompt):
        print("cancelled\n")
        log_alert("menu action=clear outcome=cancelled")
        return
    try:
        parts, _q, _res = _wipe_and_summary(True)
        print("; ".join(parts) + "\n")
    except Exception as exc:                 # report, never crash the menu
        print(f"clear failed: {exc}\n")
        log_alert(f"menu action=clear outcome=error:{type(exc).__name__}")


def menu():
    ensure_state_dir()
    while True:
        state = read_json(STATE_FILE)
        print("\n=== vnc-watch ===")
        if state:
            print(f"state: {state.get('updated')}   "
                  f"connections tracked: {len(state.get('connections') or [])}   "
                  f"live sockets: {len(state.get('sockets') or [])}")
        else:
            print("state: unavailable (daemon not running?)")
        print("1) view evidence")
        print("2) lock session")
        print("3) privacy status")
        print("4) browser inventory (metadata only)")
        print("5) ignore / acknowledge current state")
        print("6) close a running VNC server (all viewers)")
        print("7) preview the action window (no automatic action)")
        print("8) lockdown: close remote access and lock the screen")
        print("9) sweep capture tools (VNC/xwd/ffmpeg; root included)")
        print("10) clear browser + Discord data (guarded)")
        print("11) exit")
        choice = ask("select> ")
        if choice in ("11", "q", "quit", "exit"):
            print("bye")
            return 0
        if choice == "1":
            menu_action("view_evidence", lambda: (show_evidence(state),
                                                  show_log()))
        elif choice == "2":
            if confirm("This will lock your desktop session immediately."):
                ok, how = lock_session()
                print(f"{'locked via ' + how if ok else how}\n")
                log_alert(f"menu action=lock outcome={'ok:' + how if ok else how}")
            else:
                print("cancelled\n")
        elif choice == "3":
            menu_action("privacy_status", privacy_status)
        elif choice == "4":
            menu_action("browser_inventory", browser_inventory)
        elif choice == "5":
            state = state or {}
            peers = sorted({c["peer"] for c in (state.get("connections") or [])
                            if not c["closed"]})
            try:
                write_json_atomic(ACK_FILE, {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "peers": peers})
                print(f"acknowledged {len(peers)} peer(s). This is bookkeeping "
                      f"only; detection continues.\n")
                log_alert(f"menu action=ack peers={len(peers)}")
            except OSError as exc:
                print(f"could not write acknowledgement: {exc}\n")
        elif choice == "6":
            menu_close_vnc()
        elif choice == "8":
            if confirm("Close any remote session and lock the screen now?"):
                menu_action("lockdown", run_lockdown)
            else:
                print("cancelled\n")
        elif choice == "7":
            menu_action("popup_preview", lambda: run_popup_command(
                "Preview: VNC viewer attached",
                "127.0.0.1 -> local :5900 (no real detection)", 60,
                auto=False))
        elif choice == "9":
            menu_action("xwatch", lambda: xwatch_command(apply=True))
        elif choice == "10":
            menu_clear()
        else:
            print("unknown choice\n")


# ----------------------------------------------------------------- tray icon
VIEWER_TIERS = {"CONFIRMED RFB SESSION", "PROBABLE", "SUSPICIOUS"}
TRAY_ICON_IDLE = os.path.join(STATE_DIR, "tray-idle.png")
TRAY_ICON_ACTIVE = os.path.join(STATE_DIR, "tray-active.png")
TRAY_ICON_UNKNOWN = os.path.join(STATE_DIR, "tray-unknown.png")
# A state.json older than this means monitoring cannot be trusted (the daemon
# writes every ~5 s; 15 s of silence is a dead or wedged daemon).
TRAY_STATE_MAX_AGE = _env_num("VNC_WATCH_STATE_MAX_AGE", 15, int)


def tray_state(state):
    """(level, reason, n) from a state.json snapshot.

    level is one of:
      "active"  - concrete viewer evidence: a not-closed connection the daemon
                  tiered as a viewer, or an ESTABLISHED socket to a watched
                  port. Established only; a listener is NOT a viewer.
      "idle"    - daemon healthy, no viewer (it may still be listening)
      "unknown" - missing/unreadable state, stale timestamp, or dead daemon.
                  Monitoring cannot be trusted, so this is never shown as idle.

    Mirrors the daemon's protocol-only evidence; it never claims a human is
    watching.
    """
    if state is None:
        return "unknown", "no state (daemon not running?)", 0
    try:
        age = (datetime.now() - datetime.strptime(
            state["updated"], "%Y-%m-%d %H:%M:%S")).total_seconds()
    except (KeyError, TypeError, ValueError):
        return "unknown", "state unreadable", 0
    if age > TRAY_STATE_MAX_AGE:
        return "unknown", f"state stale ({age:.0f}s old — daemon down?)", 0
    pid = state.get("pid")
    if not pid or not os.path.isdir(f"/proc/{pid}"):
        return "unknown", "daemon not running", 0
    conns = [c for c in (state.get("connections") or [])
             if not c.get("closed") and c.get("tier") in VIEWER_TIERS]
    if conns:
        c = conns[-1]
        return "active", f"{c['tier'].lower()} viewer from {c['peer']}", len(conns)
    socks = state.get("sockets") or []
    if socks:
        s = socks[-1]
        return "active", f"live :{s['port']} session from {s['peer']}", len(socks)
    listeners = state.get("listeners") or []
    if listeners:
        return ("idle", "listening (" + ", ".join(f":{p}" for p in listeners)
                + "), no viewer", 0)
    return "idle", "monitoring, no remote viewer", 0


def watch_active(state):
    """Back-compat boolean view of tray_state()."""
    level, reason, n = tray_state(state)
    return level == "active", reason, n


def _tray_draw_icon(path, disc, ring):
    """Write a 64x64 ARGB PNG: a filled disc with a contrasting outer ring, so
    the dot reads on both light and dark top bars."""
    import cairo
    import math
    size = 64
    surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    cr = cairo.Context(surf)
    cr.set_operator(cairo.OPERATOR_CLEAR)
    cr.paint()
    cr.set_operator(cairo.OPERATOR_OVER)
    cx = cy = size / 2.0
    r = size * 0.33
    cr.arc(cx, cy, r + 3, 0, 2 * math.pi)
    cr.set_source_rgba(*ring)
    cr.fill()
    cr.arc(cx, cy, r, 0, 2 * math.pi)
    cr.set_source_rgba(*disc)
    cr.fill()
    surf.write_to_png(path)


def tray_icons():
    """{'idle','active','unknown'} -> icon path, generating PNGs if missing.

    White disc = idle, red disc = a viewer is attached, grey disc = no data
    (daemon down or state stale).
    """
    ensure_state_dir()
    specs = {
        "idle": (TRAY_ICON_IDLE, (1, 1, 1, 1), (0, 0, 0, 0.55)),
        "active": (TRAY_ICON_ACTIVE, (0.90, 0.16, 0.16, 1), (1, 1, 1, 0.9)),
        "unknown": (TRAY_ICON_UNKNOWN, (0.66, 0.66, 0.70, 1), (0, 0, 0, 0.55)),
    }
    for _k, (path, disc, ring) in specs.items():
        try:
            if not os.path.exists(path):
                _tray_draw_icon(path, disc, ring)
                os.chmod(path, 0o600)
        except OSError:
            pass
    return {k: v[0] for k, v in specs.items()}


def _kill_if_ours(pid, sig):
    """Send `sig` only if the pid is still this user's; never touch another UID."""
    try:
        if os.stat(f"/proc/{pid}").st_uid != os.getuid():
            return False
        os.kill(pid, sig)
        return True
    except OSError:
        return False


def _wait_gone(procs, timeout):
    """Return the subset of {pid: comm} still alive after up to `timeout` s."""
    left = dict(procs)
    deadline = time.monotonic() + max(0.0, timeout)
    while left and time.monotonic() < deadline:
        left = {pid: comm for pid, comm in left.items()
                if proc_state(pid) not in (None, "Z", "X")}
        if left:
            time.sleep(0.2)
    return left


# SIGTERM grace, then SIGKILL grace. A Clear was explicit, so the second stage
# needs no further confirmation. Overridable for slow machines / tests.
BROWSER_TERM_GRACE = _env_num("VW_BROWSER_TERM_GRACE", 8.0, float)
BROWSER_KILL_GRACE = _env_num("VW_BROWSER_KILL_GRACE", 4.0, float)


def quit_browsers(term_grace=None, kill_grace=None):
    """Terminate this user's browser processes: SIGTERM, then SIGKILL.

    Only processes owned by this UID are ever signalled (`_kill_if_ours`
    re-checks before every signal). SIGTERM is sent first; whatever survives
    the grace period is SIGKILLed without a second confirmation, because Clear
    was an explicit choice. Returns:

        {'asked': int, 'killed': [pid, ...], 'survivors': [(pid, comm), ...],
         'all_stopped': bool}

    Survivors are processes that could not be killed (e.g. an unkillable
    zombie owned by init, or an EPERM); they are reported and their data is
    then skipped, never claimed as cleared.
    """
    term_grace = BROWSER_TERM_GRACE if term_grace is None else term_grace
    kill_grace = BROWSER_KILL_GRACE if kill_grace is None else kill_grace
    procs = running_browsers()
    for pid, _comm in procs:
        _kill_if_ours(pid, signal.SIGTERM)
    left = _wait_gone(procs, term_grace)
    killed = []
    if left:
        for pid, _comm in left.items():
            if _kill_if_ours(pid, signal.SIGKILL):
                killed.append(pid)
        left = _wait_gone(left, kill_grace)
    survivors = sorted((pid, comm) for pid, comm in left.items())
    log_alert(f"clear: asked {len(procs)} browser proc(s) to quit, "
              f"SIGKILLed {len(killed)}, {len(survivors)} survived")
    return {"asked": len(procs), "killed": sorted(killed),
            "survivors": survivors, "all_stopped": not survivors}


def _ask_passphrase_gui(parent=None):
    """GTK password prompt for the panel. Returns the passphrase or None."""
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
    except Exception:
        return None
    dlg = Gtk.Dialog(title="Vault passphrase", transient_for=parent, modal=True)
    dlg.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                    "Encrypt", Gtk.ResponseType.OK)
    dlg.set_default_response(Gtk.ResponseType.OK)
    box = dlg.get_content_area()
    box.add(Gtk.Label(label="Passphrase for the encrypted archive "
                            "(not stored anywhere):"))
    entry = Gtk.Entry()
    entry.set_visibility(False)
    entry.set_activates_default(True)
    box.add(entry)
    dlg.show_all()
    resp = dlg.run()
    pw = entry.get_text() if resp == Gtk.ResponseType.OK else ""
    dlg.destroy()
    return pw or None


def _tray_confirm_wipe(parent=None):
    """Destructive confirm. Returns (decision, quit_first, encrypt, passphrase)
    where decision is True (proceed), False (cancel), or None (nothing to do)."""
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    targets, browsers, total = _clear_survey()
    if not _clear_has_work(targets, browsers):
        return None, False, False, None
    dlg = Gtk.MessageDialog(transient_for=parent, modal=True,
                            message_type=Gtk.MessageType.WARNING,
                            buttons=Gtk.ButtonsType.NONE)
    dlg.set_title("Clear browser + Discord data")
    dlg.set_markup("<b>Close browsers and clear local data?</b>")
    if targets:
        detail = (
            f"{len(targets)} item(s), about {total / 1048576:.1f} MB — full "
            f"profile reset across Firefox, Chrome, Chromium, Brave, Edge, "
            f"Vivaldi and Opera (native, Snap and Flatpak): history, "
            f"downloads, cookies, sessions, caches, autofill, saved logins, "
            f"bookmarks and settings, plus Discord storage. ")
    else:
        detail = (
            "No local browser/Discord data was found, but supported browser "
            "processes are running and will be closed. ")
    detail += (
        "Running browsers are closed automatically (SIGTERM, then SIGKILL); "
        "open tabs and unsaved work are lost. Next launch starts from a fresh "
        "profile: no history, no logged-in account, no restored windows. "
        "Deleting cannot be undone; the encrypted option keeps a restorable "
        "archive instead. This does not affect screen monitoring or VNC.")
    dlg.format_secondary_text(detail)
    dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
    dlg.add_button("Proceed", Gtk.ResponseType.OK)
    dlg.set_default_response(Gtk.ResponseType.CANCEL)
    chk_enc = Gtk.CheckButton.new_with_label(
        "Encrypt a recoverable archive instead of deleting")
    chk_enc.set_active(False)
    dlg.get_content_area().add(chk_enc)
    dlg.show_all()
    resp = dlg.run()
    encrypt = chk_enc.get_active()
    dlg.destroy()
    ok = resp == Gtk.ResponseType.OK
    pw = None
    if ok and encrypt:
        pw = (os.environ.get("VNC_WATCH_VAULT_PASSPHRASE")
              or _ask_passphrase_gui(parent))
        if not pw:
            return False, True, False, None   # passphrase cancelled
    return ok, True, encrypt, pw


def _confirm_parts(result):
    """Accept both (ok, quit) and (ok, quit, encrypt, passphrase) shapes."""
    if len(result) == 2:
        return result[0], result[1], False, None
    return result


def _wipe_and_summary(quit_first=True, encrypt=False, passphrase=None):
    """Close browsers, then wipe synchronously. Returns (parts, quit, result).

    Browsers are always terminated first (SIGTERM, then SIGKILL after the
    grace period): Clear is an explicit choice, so unsaved tabs are accepted as
    lost and no manual close is requested. `quit_first` is kept for existing
    callers but no longer gates the shutdown. Kept separate from _tray_do_wipe
    so a one-shot `clear` process can run it to completion instead of relying
    on a thread that dies with the process."""
    q = quit_browsers()
    res = wipe_private_data(apply=True, encrypt=encrypt, passphrase=passphrase)
    verb = "Archived" if encrypt else "Cleared"
    if res["items"]:
        parts = [f"{verb} {len(res['items'])} item(s), "
                 f"{res['total'] / 1048576:.1f} MB"]
    else:
        parts = ["no supported browser/Discord data found"]
    if res["vault"]:
        parts.append(f"vault {os.path.basename(res['vault'])} "
                     f"(restore with clear --restore)")
    if q["asked"]:
        closed = f"closed {q['asked']} browser proc(s)"
        if q["killed"]:
            closed += f", SIGKILLed {len(q['killed'])}"
        parts.append(closed)
    if q["survivors"]:
        who = ", ".join(f"{comm} (pid {pid})" for pid, comm in q["survivors"])
        parts.append(f"{len(q['survivors'])} could not be closed — "
                     f"{who} — their data was NOT cleared")
    if res["remaining"]:
        parts.append(f"{len(res['remaining'])} item(s) remain")
    if res["errors"]:
        parts.append(f"{len(res['errors'])} error(s)")
    return parts, q, res


def _tray_do_wipe(quit_first, encrypt=False, passphrase=None):
    def work():
        try:
            if encrypt or passphrase:
                parts, q, res = _wipe_and_summary(quit_first, encrypt,
                                                  passphrase)
            else:
                parts, q, res = _wipe_and_summary(quit_first)
            notify("vnc-watch", "; ".join(parts), "viewer",
                   urgent=bool(q["survivors"] or res["errors"]))
        except Exception as exc:
            notify("vnc-watch", f"clear failed: {exc}", "viewer")
    threading.Thread(target=work, daemon=True).start()


def _vault_list_command():
    archives = vault_archives()
    if not archives:
        print("no encrypted archives")
        return 0
    print("== encrypted vault ==\n")
    for path, size, mtime in archives:
        print(f"{datetime.fromtimestamp(mtime):%Y-%m-%d %H:%M:%S}  "
              f"{size / 1048576:8.1f} MB  {path}")
    print("\nrestore with: vnc-watch clear --restore [ARCHIVE]")
    return 0


def _confirm_wipe_cli(encrypt=False):
    """Fallback confirmation when GTK is unavailable (SSH / no display)."""
    targets, browsers, total = _clear_survey()
    if not _clear_has_work(targets, browsers):
        return None, False, False, None
    mode = "encrypt" if encrypt else "delete"
    if targets:
        print(f"{len(targets)} item(s), about {total / 1048576:.1f} MB — "
              "full browser profile reset (history, cookies, logins, sessions, "
              "bookmarks, settings) plus Discord storage")
    else:
        print("no local browser/Discord data found; "
              f"{len(browsers)} running browser process(es) will be closed")
    print("running browsers will be closed (SIGTERM, then SIGKILL); open "
          "tabs and unsaved work are lost")
    print(f"mode: {mode}"
          + (" (AES-256 archive, restorable with clear --restore)"
             if encrypt else " (cannot be undone)"))
    if not sys.stdin.isatty():
        print("refusing: no GUI and no terminal to confirm on")
        return False, False, False, None
    try:
        answer = input(f"Type '{mode}' to proceed: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False, False, False, None
    if answer != mode:
        return False, False, False, None
    pw = vault_passphrase(prompt=True) if encrypt else None
    if encrypt and not pw:
        return False, False, False, None
    return True, True, encrypt, pw


def clear_command(encrypt=False, restore=None, list_vault=False):
    """One-shot `clear`: guard, confirm (GTK), then wipe to completion.

    The panel/GNOME extension spawns this as its own process, so the work must
    finish before the process exits — no fire-and-forget thread here."""
    if list_vault:
        return _vault_list_command()
    if restore is not None:
        try:
            outcome = vault_restore(restore)
        except (OSError, RuntimeError) as exc:
            msg = f"restore failed: {exc}"
            print(msg, flush=True)
            notify("vnc-watch", msg, "viewer")
            return 2
        n = len(outcome["restored"])
        msg = f"restored {n} item(s) from {restore}"
        if outcome["conflicts"]:
            msg += f"; {len(outcome['conflicts'])} left in place (already present)"
            for rel, reason in outcome["conflicts"]:
                print(f"  kept existing {rel}: {reason}", flush=True)
        notify("vnc-watch", msg, "viewer", urgent=False)
        print(msg, flush=True)
        return 0
    locked, why = active_lock_window()
    if locked:
        msg = f"clear refused: {why} (exam/lock window active)"
        notify("vnc-watch", msg, "viewer")
        print(msg, flush=True)
        return 1
    try:
        ok, quit_first, gui_encrypt, passphrase = _confirm_parts(
            _tray_confirm_wipe())
        encrypt = encrypt or gui_encrypt
        if encrypt and not passphrase:
            passphrase = vault_passphrase()
    except Exception:
        # No display / GTK: confirm on the terminal instead of crashing.
        ok, quit_first, encrypt, passphrase = _confirm_wipe_cli(encrypt)
    if ok is None:
        msg = ("nothing to clear (no supported browser/Discord data and no "
               "supported browser running)")
        notify("vnc-watch", msg, "viewer", urgent=False)
        print(msg, flush=True)
        return 0
    if not ok:
        print("cancelled", flush=True)
        return 1
    try:
        if encrypt or passphrase:
            parts, q, res = _wipe_and_summary(quit_first, encrypt, passphrase)
        else:
            parts, q, res = _wipe_and_summary(quit_first)
    except Exception as exc:
        notify("vnc-watch", f"clear failed: {exc}", "viewer")
        print(f"clear failed: {exc}", flush=True)
        return 2
    msg = "; ".join(parts)
    notify("vnc-watch", msg, "viewer",
           urgent=bool(q["survivors"] or res["errors"]))
    print(msg, flush=True)
    return 2 if q["survivors"] else 0


def _tray_clear():
    locked, why = active_lock_window()
    if locked:
        notify("vnc-watch", f"clear refused: {why} (exam/lock window active)",
               "viewer")
        return
    ok, quit_first, encrypt, passphrase = _confirm_parts(
        _tray_confirm_wipe())
    if ok is None:
        notify("vnc-watch",
               "nothing to clear (no supported browser/Discord data and no "
               "supported browser running)", "viewer", urgent=False)
        return
    if ok:
        _tray_do_wipe(quit_first, encrypt, passphrase)


def _tray_ask(title, markup, detail):
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    d = Gtk.MessageDialog(message_type=Gtk.MessageType.QUESTION,
                          buttons=Gtk.ButtonsType.OK_CANCEL)
    d.set_title(title)
    d.set_markup(markup)
    d.format_secondary_text(detail)
    ok = d.run() == Gtk.ResponseType.OK
    d.destroy()
    return ok


def kick_command():
    """One-shot panel `kick`: confirm in a dialog, then close to completion.

    The CLI `kick` path prompts on stdin; from the panel there is no tty, so
    this variant confirms with the same GTK dialog the tray menu uses."""
    locked, why = active_lock_window()
    if locked:
        msg = f"kick refused: {why} (exam/lock window active)"
        notify("vnc-watch", msg, "viewer")
        print(msg, flush=True)
        return 1
    if not _tray_ask("Close VNC server", "<b>Close any running VNC server?</b>",
                     "This drops every viewer. X11 has no per-viewer "
                     "disconnect; a root operator can restart it."):
        print("cancelled", flush=True)
        return 1
    try:
        rc = run_close_vnc(assume_yes=True)
        notify("vnc-watch", f"close VNC finished (rc={rc})", "viewer",
               urgent=False)
        print(f"close VNC finished (rc={rc})", flush=True)
        return rc
    except Exception as exc:
        notify("vnc-watch", f"close VNC failed: {exc}", "viewer")
        print(f"close VNC failed: {exc}", flush=True)
        return 2


def _tray_kick():
    locked, why = active_lock_window()
    if locked:
        notify("vnc-watch", f"kick refused: {why} (exam/lock window active)",
               "viewer")
        return
    if not _tray_ask("Close VNC server", "<b>Close any running VNC server?</b>",
                     "This drops every viewer. X11 has no per-viewer "
                     "disconnect; a root operator can restart it."):
        return
    def work():
        try:
            rc = run_close_vnc(assume_yes=True)
            notify("vnc-watch", f"close VNC finished (rc={rc})", "viewer",
                   urgent=False)
        except Exception as exc:
            notify("vnc-watch", f"close VNC failed: {exc}", "viewer")
    threading.Thread(target=work, daemon=True).start()


def lock_command():
    """One-shot `lock`: lock the session and report the outcome."""
    try:
        ok, how = lock_session()
    except Exception as exc:
        ok, how = False, str(exc)
    msg = f"{'locked' if ok else 'lock failed'}: {how}"
    notify("vnc-watch", msg, "viewer", urgent=False)
    print(msg, flush=True)
    return 0 if ok else 1


def _tray_lock():
    lock_command()


def _tray_open_menu():
    argv = [sys.executable, os.path.abspath(__file__), "menu"]
    term = (shutil.which("gnome-terminal") or shutil.which("kgx")
            or shutil.which("x-terminal-emulator") or shutil.which("xterm"))
    if term and "gnome-terminal" in term:
        cmd = [term, "--", *argv]
    elif term and "kgx" in term:
        cmd = [term, "--", *argv]
    elif term:
        cmd = [term, "-e", *argv]
    else:
        cmd = argv
    try:
        subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except OSError as exc:
        notify("vnc-watch", f"cannot open menu: {exc}", "viewer")


def menu_window_command():
    """One-shot `menu-window`: open the interactive menu in a terminal."""
    _tray_open_menu()
    return 0


def _tray_quit():
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    Gtk.main_quit()


def _tray_menu():
    """The click menu shared by both tray backends. Returns (menu, status)."""
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    menu = Gtk.Menu()
    status = Gtk.MenuItem(label="vnc-watch: starting…")
    status.set_sensitive(False)
    menu.append(status)
    menu.append(Gtk.SeparatorMenuItem())

    def item(label, fn):
        it = Gtk.MenuItem(label=label)
        it.connect("activate", lambda _w: fn())
        menu.append(it)

    item("Open vnc-watch menu…", _tray_open_menu)
    item("Clear browser + Discord data…", _tray_clear)
    menu.append(Gtk.SeparatorMenuItem())
    item("Close VNC server (kick)", _tray_kick)
    item("Lock session", _tray_lock)
    menu.append(Gtk.SeparatorMenuItem())
    item("Quit tray", _tray_quit)
    menu.show_all()
    return menu, status


def _appindicator_ready():
    """True if the top-bar indicator will actually be shown.

    On GNOME it needs the `appindicatorsupport` shell extension ENABLED; if
    that extension is missing or off (e.g. locked by a dconf policy), an
    AppIndicator is created but never rendered, so we fall back to the floating
    chip. On non-GNOME desktops the indicator is assumed to work."""
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()
    if "gnome" not in desktop and "unity" not in desktop:
        return True
    for uuid in ("appindicatorsupport@rgcjonas.gmail.com",
                 "ubuntu-appindicators@ubuntu.com"):
        try:
            r = subprocess.run(["gnome-extensions", "info", uuid],
                               capture_output=True, text=True, timeout=4)
            if "State: ENABLED" in r.stdout:
                return True
        except (OSError, subprocess.SubprocessError):
            pass
    return False


def _tray_poll(status, on_change):
    """One poll cycle: read state, update the status label, and fire
    on_change(level, reason, n) only when the level flips.

    Levels: active | idle | unknown. `unknown` is used whenever the daemon's
    state is missing, unreadable, stale, or its pid is dead — never idle."""
    level, reason, n = tray_state(read_json(STATE_FILE))
    mark = {"active": "●", "idle": "○", "unknown": "?"}[level]
    status.set_label(f"{mark} {reason}")
    if level != _tray_poll.last:
        _tray_poll.last = level
        on_change(level, reason, n)
    return True


def _tray_indicator(icons):
    """Top-bar AppIndicator. Returns True if set up (not whether it renders)."""
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import GLib
    from gi.repository import AyatanaAppIndicator3 as AppIndicator

    ind = AppIndicator.Indicator.new(
        "vnc-watch", icons["unknown"],
        AppIndicator.IndicatorCategory.SYSTEM_SERVICES)
    ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)

    def set_icon(path):
        try:
            ind.set_icon_full(path, "vnc-watch")
        except Exception:
            ind.set_icon(path)

    set_icon(icons["unknown"])              # unknown until first poll
    menu, status = _tray_menu()
    ind.set_menu(menu)

    def on_change(level, *_):
        set_icon(icons[level])

    _tray_poll.last = None
    GLib.timeout_add(1500, lambda: _tray_poll(status, on_change))
    _tray_poll(status, on_change)
    return True


def _tray_floating(icons):
    """No-root fallback: a small always-on-top chip at the top edge, styled
    like a panel button. Left-click opens the same menu. Position via
    VNC_WATCH_TRAY_X / VNC_WATCH_TRAY_Y (defaults: top-right, under the panel)."""
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, GLib, Gdk

    menu, status = _tray_menu()

    win = Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
    win.set_decorated(False)
    win.set_resizable(False)
    win.set_skip_taskbar_hint(True)
    win.set_skip_pager_hint(True)
    win.set_keep_above(True)
    win.set_type_hint(Gdk.WindowTypeHint.UTILITY)
    win.set_title("vnc-watch")

    css = Gtk.CssProvider()
    css.load_from_data((
        ".vncwatch-chip { background: rgba(18,18,22,0.86);"
        " border-radius: 13px; }"
        " .vncwatch-chip label { color: #f4f4f5; }").encode())
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), css,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
    dot = Gtk.DrawingArea()
    dot.set_size_request(16, 16)
    lbl = Gtk.Label(label="vnc-watch")
    box.pack_start(dot, False, False, 0)
    box.pack_start(lbl, False, False, 0)
    eb = Gtk.EventBox()
    eb.get_style_context().add_class("vncwatch-chip")
    eb.set_margin_top(5)
    eb.set_margin_bottom(5)
    eb.set_margin_start(11)
    eb.set_margin_end(12)
    eb.add(box)
    win.add(eb)

    COLORS = {"idle": (1.0, 1.0, 1.0),
              "active": (0.92, 0.16, 0.16),
              "unknown": (0.66, 0.66, 0.70)}
    color = {"rgb": COLORS["unknown"]}      # grey until first poll

    def draw(_w, cr):
        r, g, b = color["rgb"]
        cr.set_source_rgba(1, 1, 1, 0.0)
        cr.paint()
        cr.set_source_rgb(r, g, b)
        cr.arc(8, 8, 6, 0, 6.283185307179586)
        cr.fill()
    dot.connect("draw", draw)

    def on_click(_w, event):
        menu.popup_at_pointer(event)
        return True
    eb.connect("button-press-event", on_click)

    def place():
        disp = Gdk.Display.get_default()
        mon = disp.get_primary_monitor() or disp.get_monitor(0)
        sw = mon.get_geometry().width
        w, _h = win.get_size()
        try:
            x = int(os.environ["VNC_WATCH_TRAY_X"])
        except (KeyError, ValueError):
            x = sw - w - 14
        try:
            y = int(os.environ["VNC_WATCH_TRAY_Y"])
        except (KeyError, ValueError):
            y = 32
        win.move(x, y)

    win.connect("show", lambda _w: place())

    def on_change(level, reason, _n):
        color["rgb"] = COLORS[level]
        dot.queue_draw()
        prefix = {"active": "WATCHING", "idle": "Idle",
                  "unknown": "UNKNOWN"}[level]
        win.set_tooltip_text(f"{prefix} — {reason}")

    _tray_poll.last = None
    win.show_all()
    GLib.idle_add(place)
    GLib.timeout_add(1500, lambda: _tray_poll(status, on_change))
    _tray_poll(status, on_change)
    # re-place if the panel/screen changes
    try:
        Gdk.Display.get_default().connect(
            "monitor-changed", lambda *_: (place(), False)[1])
    except Exception:
        pass
    return True


def tray_command(backend=None):
    """Tray icon: white = idle, red = viewer attached, grey = unknown.

    Reads the daemon's state.json and recolors. Clicking opens a menu: open
    the full menu, clear browser + Discord data (destructive, with a
    confirmation dialog), close a running VNC server, lock the session, quit.

    Uses the GNOME top-bar indicator when the AppIndicator shell extension is
    enabled; otherwise falls back to a docked always-on-top chip at the top
    edge (no root or shell extension required). Force with
    VNC_WATCH_TRAY_BACKEND=indicator|floating or `--tray-backend`.
    """
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

    ensure_state_dir()
    icons = tray_icons()
    backend = (backend or os.environ.get("VNC_WATCH_TRAY_BACKEND")
               or "").strip().lower()

    used = "floating"
    if backend == "indicator" or (backend != "floating"
                                  and _appindicator_ready()):
        try:
            _tray_indicator(icons)
            used = "indicator"
        except Exception as exc:            # missing typelib, no DBus, ...
            print(f"indicator unavailable ({exc}); using floating chip",
                  flush=True)
    if used == "floating":
        _tray_floating(icons)

    print(f"tray running ({used}) — white = idle, red = viewer, grey = unknown "
          f"(Ctrl-C to stop)", flush=True)
    try:
        Gtk.main()
    except KeyboardInterrupt:
        pass
    return 0


# --------------------------------------------------------------------- cli
def main():
    ap = argparse.ArgumentParser(
        prog="vnc-watch",
        description="Unprivileged, best-effort remote-viewing detection.")
    ap.add_argument("command", nargs="?",
                    choices=["watch", "audit", "ssh", "portal", "kick", "popup",
                             "channels", "lockdown", "shortcut", "xwatch",
                             "tray", "menu", "menu-window", "clear", "lock"],
                    help="watch (default), audit, ssh, portal, kick, popup, "
                         "channels, lockdown, shortcut, xwatch, tray, menu, "
                         "menu-window, clear, lock")
    ap.add_argument("--audit", action="store_true",
                    help="alias for `audit`")
    ap.add_argument("--portal", action="store_true",
                    help="alias for `portal`")
    ap.add_argument("--input-watch", action="store_true",
                    help="watch XTEST injection (supporting signal)")
    ap.add_argument("--x-watch", action="store_true",
                    help="watch X client count (noisy, off by default)")
    ap.add_argument("--yes", action="store_true",
                    help="with `kick`: skip the interactive confirmation")
    ap.add_argument("--panel", action="store_true",
                    help="with `kick`: confirm in a GTK dialog instead of on "
                         "stdin (used by the top-panel menu; no tty there)")
    ap.add_argument("--dry-run", action="store_true",
                    help="with `kick`: report the target, change nothing")
    ap.add_argument("--reason", default="Remote viewing detected",
                    help="with `popup`: headline text")
    ap.add_argument("--detail", default="",
                    help="with `popup`: peer / port detail line")
    ap.add_argument("--timeout", type=int, default=POPUP_TIMEOUT,
                    help="with `popup`: seconds before the automatic choice")
    ap.add_argument("--no-auto", action="store_true",
                    help="with `popup`: never act automatically on timeout")
    ap.add_argument("--set", action="append", metavar="KEY=VALUE",
                    help="with `channels`: store one channel setting")
    ap.add_argument("--clear", action="append", metavar="KEY",
                    help="with `channels`: remove one channel setting")
    ap.add_argument("--test", action="store_true",
                    help="with `channels`: send a test message")
    ap.add_argument("--no-lock", action="store_true",
                    help="with `lockdown`: close remote access but do not "
                         "lock the screen")
    ap.add_argument("--tray-backend", choices=["indicator", "floating"],
                    help="with `tray`: force the top-bar indicator or the "
                         "floating chip")
    ap.add_argument("--remove", action="store_true",
                    help="with `shortcut`: remove the hotkey")
    ap.add_argument("--binding", default="<Control><Alt><Shift>l",
                    help="with `shortcut`: key combination to bind")
    ap.add_argument("--encrypt", action="store_true",
                    help="with `clear`: store an encrypted, restorable archive "
                         "instead of deleting (passphrase from "
                         "VNC_WATCH_VAULT_PASSPHRASE or a prompt)")
    ap.add_argument("--restore", nargs="?", const="latest", metavar="ARCHIVE",
                    help="with `clear`: decrypt an archive back into place "
                         "(default: the newest one)")
    ap.add_argument("--vault-list", action="store_true",
                    help="with `clear`: list encrypted archives")
    args = ap.parse_args()

    cmd = args.command or "watch"
    if args.audit:
        cmd = "audit"
    if args.portal:
        cmd = "portal"

    if cmd == "audit":
        return audit()
    if cmd == "ssh":
        ensure_state_dir()
        return ssh_audit_section()
    if cmd == "portal":
        ensure_state_dir()
        return portal_status()
    if cmd == "kick":
        ensure_state_dir()
        if args.panel:
            return kick_command()
        return run_close_vnc(assume_yes=args.yes, apply=not args.dry_run)
    if cmd == "popup":
        ensure_state_dir()
        return run_popup_command(args.reason, args.detail, args.timeout,
                                 auto=not args.no_auto)
    if cmd == "channels":
        ensure_state_dir()
        return channels_command(args.set or (), args.clear or (), args.test)
    if cmd == "lockdown":
        ensure_state_dir()
        return run_lockdown(lock=not args.no_lock)
    if cmd == "shortcut":
        return shortcut_command(install=not args.remove, binding=args.binding)
    if cmd == "xwatch":
        ensure_state_dir()
        return xwatch_command(apply=not args.dry_run, assume_yes=args.yes)
    if cmd == "tray":
        return tray_command(backend=args.tray_backend)
    if cmd == "menu":
        return menu()
    if cmd == "menu-window":
        return menu_window_command()
    if cmd == "clear":
        ensure_state_dir()
        return clear_command(encrypt=args.encrypt, restore=args.restore,
                             list_vault=args.vault_list)
    if cmd == "lock":
        ensure_state_dir()
        return lock_command()
    return follow_live(args)


if __name__ == "__main__":
    sys.exit(main())