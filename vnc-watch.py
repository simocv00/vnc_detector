#!/usr/bin/env python3
"""vnc-watch - unprivileged, best-effort remote-viewing detection for this session.

    vnc-watch watch    live detection (default)
    vnc-watch audit    classify every connection in the current x11vnc log
    vnc-watch portal   one-shot screencast / RDP / VNC status
    vnc-watch kick     close a running VNC server (confirmation required)
    vnc-watch lockdown close remote access and lock the screen
    vnc-watch xwatch   evict screen-capture tools on :0 (root included)
    vnc-watch channels remote alerts (Discord / Telegram / ntfy / WhatsApp)
    vnc-watch menu     read the daemon's state and offer manual actions

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
import fcntl
import json
import os
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

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
XI_LOG_MAX = int(os.environ.get("VNC_WATCH_XI_MAX", 2 * 1024 * 1024))
# The alert log is rotated once when it exceeds this, keeping one `.1` backup,
# so an unattended daemon cannot slowly fill a small home volume.
ALERT_LOG_MAX = int(os.environ.get("VNC_WATCH_LOG_MAX", 5 * 1024 * 1024))

REPLACE_ID = {"viewer": 4201, "socket": 4202, "xclients": 4203,
              "cpu": 4204, "xtest": 4205, "autorepeat": 4206, "port": 4207}
COOLDOWN = {"viewer": 0, "socket": 5, "xclients": 1800, "cpu": 1800,
            "xtest": 30, "autorepeat": 900, "port": 600}
# Kinds whose suppressed repeats are rare enough to keep an audit trail.
LOG_SUPPRESSED = {"socket", "viewer", "port", "autorepeat", "cpu"}

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
    """Poll-based tailer that survives rotation and truncation."""

    def __init__(self, path, from_end=True):
        self.path = path
        self.fh = None
        self.key = None
        self.buf = b""
        self._open(from_end)

    def _open(self, from_end):
        self.fh = open(self.path, "rb")
        st = os.fstat(self.fh.fileno())
        self.key = (st.st_dev, st.st_ino)
        if from_end:
            self.fh.seek(0, os.SEEK_END)
        self.buf = b""

    def readlines(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return []                      # briefly missing mid-rotation
        if self.fh is None:
            self._open(True)
            return []
        if (st.st_dev, st.st_ino) != self.key:
            old = self._read()             # finish the old inode first
            self.fh.close()
            self._open(False)              # new file from the beginning
            return old + self._read()
        if st.st_size < self.fh.tell():    # truncated in place
            self.fh.seek(0)
            self.buf = b""
        return self._read()

    def _read(self):
        data = self.fh.read()
        if not data:
            return []
        self.buf += data
        *done, self.buf = self.buf.split(b"\n")   # keep the partial tail
        return [line.decode("utf-8", "replace") for line in done]

    def close(self):
        if self.fh:
            self.fh.close()
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
        with open(LOG, errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"cannot read {LOG}: {exc}")
        return 1

    conns, uncorrelated = [], []
    for line in lines:
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


def active_lock_window():
    """(True, reason) if a seat controller reports an active lock.

    Reads the file named by VNC_WATCH_LOCK_FILE (POLICY_FILE), if any. It is
    expected to be JSON describing the seat, not the account, so it applies to
    whoever is logged in at :0. With no path configured, an unreadable file or
    malformed content, the state is "unknown" and treated as not active.
    """
    if not POLICY_FILE:
        return False, "lock state unavailable"
    try:
        with open(POLICY_FILE) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
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
WIPE_ITEMS = [
    # Chromium-family
    "History", "History-journal", "History-wal", "History-shm",
    "Cookies", "Cookies-journal",
    "Network/Cookies", "Network/Cookies-journal",
    "Sessions", "Session Storage", "Local Storage", "IndexedDB",
    "Cache", "Code Cache", "GPUCache", "Service Worker",
    "Shared Dictionary", "WebStorage",
    # Firefox
    "places.sqlite", "places.sqlite-wal", "places.sqlite-shm",
    "cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm",
    "sessionstore-backups", "storage", "cache2", "startupCache",
    "shader-cache", "crashes",
]
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


def wipe_targets():
    """[(label, path)] of existing browser and Discord data to remove."""
    targets = []
    seen = set()
    for label, rel in BROWSER_ROOTS:
        root = os.path.expanduser(rel)
        if not os.path.isdir(root):
            continue
        for prof in discover_profiles(root):
            for item in WIPE_ITEMS:
                p = os.path.join(prof, item)
                if os.path.lexists(p) and p not in seen:
                    seen.add(p)
                    targets.append((f"{label}/{os.path.basename(prof)}", p))
    for rel in DISCORD_ROOTS:
        root = os.path.expanduser(rel)
        if not os.path.isdir(root):
            continue
        for item in DISCORD_ITEMS:
            p = os.path.join(root, item)
            if os.path.lexists(p) and p not in seen:
                seen.add(p)
                targets.append((f"discord/{os.path.basename(root)}", p))
    return targets


def wipe_private_data(apply=True):
    """Delete browser history/cookies/sessions/caches and Discord storage.

    Returns {'items': [(label, path, bytes)], 'total': int, 'errors': [...]}.
    """
    res = {"items": [], "total": 0, "errors": []}
    for label, path in wipe_targets():
        try:
            n = _remove_path(path, apply)
        except (OSError, RuntimeError) as exc:
            res["errors"].append(f"{path}: {exc}")
            continue
        res["items"].append((label, path, n))
        res["total"] += n
    if apply:
        log_alert(f"wipe: removed {len(res['items'])} item(s), "
                  f"{res['total'] / 1048576:.1f} MB, "
                  f"{len(res['errors'])} error(s)")
        for label, path, n in res["items"]:
            log_alert(f"wipe: {label} {path} ({n / 1048576:.1f} MB)")
    return res



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
POPUP_TIMEOUT = int(os.environ.get("VNC_WATCH_POPUP_TIMEOUT", "60"))
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
    ports0 = listening_ports()
    known_ports = ports0 if ports0 is not None else set()

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
    dirty = True

    def note(msg):
        recent.append(f"{datetime.now():%H:%M:%S} {msg}")

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
                    new = {p for p in ports - known_ports if p in REMOTE_PORTS}
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
                     "xi_log_bytes": os.path.getsize(XI_LOG)
                     if os.path.exists(XI_LOG) else 0,
                     "unavailable": {
                         "x11vnc": sx is None,
                         "autorepeat": autorepeat_state is None,
                         "xtest": not xtest,
                     },
                     "recent": list(recent)}))
                last_state_write = now
                dirty = False

            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\nstopped")
        return 0
    finally:
        if tail:
            tail.close()
        if xi_tail:
            xi_tail.close()
        if xinput_proc and xinput_proc.poll() is None:
            xinput_proc.terminate()


# -------------------------------------------------------------------- menu
BROWSER_ROOTS = [
    ("chrome (native)", "~/.config/google-chrome"),
    ("chromium (native)", "~/.config/chromium"),
    ("chrome (flatpak)", "~/.var/app/com.google.Chrome/config/google-chrome"),
    ("chromium (flatpak)", "~/.var/app/org.chromium.Chromium/config/chromium"),
    ("firefox (native)", "~/.mozilla/firefox"),
    ("firefox (flatpak)", "~/.var/app/org.mozilla.firefox/.mozilla/firefox"),
    ("brave (native)", "~/.config/BraveSoftware/Brave-Browser"),
    ("brave (flatpak)",
     "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"),
]
PROFILE_FILES = ["History", "Cookies", "Login Data", "Web Data", "Bookmarks",
                 "Preferences", "places.sqlite", "cookies.sqlite",
                 "logins.json", "key4.db", "cert9.db"]
PROFILE_DIRS = ["Cache", "Code Cache", "cache2"]
BROWSER_COMMS = {"chrome", "chromium", "chromium-browser", "firefox",
                 "msedge", "brave"}


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


def discover_profiles(root):
    """Profile subdirectories that actually contain browser data."""
    found = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return found
    for e in entries:
        if not e.is_dir(follow_symlinks=False):
            continue
        try:
            names = set(os.listdir(e.path))
        except OSError:
            continue
        if names & set(PROFILE_FILES) or "Cache" in names or "cache2" in names:
            found.append(e.path)
    return found


def browser_inventory():
    print("== browser inventory (metadata only: existence and size) ==\n")
    any_found = False
    for label, rel in BROWSER_ROOTS:
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
        for prof in discover_profiles(root):
            size, _ = dir_size(prof)
            print(f"  profile {os.path.basename(prof)}: {size / 1048576:.1f} MB")
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
        if comm.lower() in BROWSER_COMMS:
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


def lock_session():
    """Lock over the session bus first, then loginctl. Returns (ok, how)."""
    try:
        r = subprocess.run(["gdbus", "call", "--session",
                            "--dest", "org.gnome.ScreenSaver",
                            "--object-path", "/org/gnome/ScreenSaver",
                            "--method", "org.gnome.ScreenSaver.Lock"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return True, "org.gnome.ScreenSaver.Lock"
    except (OSError, subprocess.SubprocessError):
        pass
    user = os.environ.get("USER") or str(os.getuid())
    try:
        out = subprocess.run(["loginctl", "show-user", user, "-p", "Sessions",
                              "--value"], capture_output=True, text=True,
                             timeout=5).stdout.split()
    except (OSError, subprocess.SubprocessError):
        out = []
    for sid in out:
        try:
            r = subprocess.run(["loginctl", "lock-session", sid],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            return True, f"loginctl lock-session {sid}"
    return False, "no working lock mechanism (session bus and loginctl failed)"


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
        print("10) exit")
        choice = ask("select> ")
        if choice in ("10", "q", "quit", "exit"):
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
        else:
            print("unknown choice\n")


# --------------------------------------------------------------------- cli
def main():
    ap = argparse.ArgumentParser(
        prog="vnc-watch",
        description="Unprivileged, best-effort remote-viewing detection.")
    ap.add_argument("command", nargs="?",
                    choices=["watch", "audit", "portal", "kick", "popup",
                             "channels", "lockdown", "shortcut", "xwatch",
                             "menu"],
                    help="watch (default), audit, portal, kick, popup, "
                         "channels, lockdown, shortcut, xwatch, menu")
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
    ap.add_argument("--remove", action="store_true",
                    help="with `shortcut`: remove the hotkey")
    ap.add_argument("--binding", default="<Control><Alt><Shift>l",
                    help="with `shortcut`: key combination to bind")
    args = ap.parse_args()

    cmd = args.command or "watch"
    if args.audit:
        cmd = "audit"
    if args.portal:
        cmd = "portal"

    if cmd == "audit":
        return audit()
    if cmd == "portal":
        ensure_state_dir()
        return portal_status()
    if cmd == "kick":
        ensure_state_dir()
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
    if cmd == "menu":
        return menu()
    return follow_live(args)


if __name__ == "__main__":
    sys.exit(main())