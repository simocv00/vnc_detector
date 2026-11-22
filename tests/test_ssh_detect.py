#!/usr/bin/env python3
"""Isolation tests for the SSH subsystem.

Everything runs against throwaway fixtures: a fake PROC_ROOT, fake utmp/wtmp
files, and monkeypatched loginctl/ss/webhook. No live campus SSH session, real
/proc entry, or real channel is inspected, modified, or contacted.

    python3 tests/test_ssh_detect.py
"""
import importlib.util
import os
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, os.pardir, "vnc-watch.py")
SANDBOX = tempfile.mkdtemp(prefix="vw-ssh-test-")
PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


os.environ["HOME"] = os.path.join(SANDBOX, "home")
os.makedirs(os.environ["HOME"], exist_ok=True)
spec = importlib.util.spec_from_file_location("vw", SRC)
M = importlib.util.module_from_spec(spec)
sys.argv = ["vnc-watch"]
spec.loader.exec_module(M)

# ---------------------------------------------------------------- proc fixture
PROC = os.path.join(SANDBOX, "proc")
os.makedirs(PROC, exist_ok=True)


def make_proc(pid, ppid, session_sid, start, scope, exe="sh", cmdline=None):
    d = os.path.join(PROC, str(pid))
    os.makedirs(d, exist_ok=True)
    # fields 4..22 after the (comm) field: ppid pgrp session tty tpgid flags
    # minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
    # num_threads itrealvalue starttime
    rest = [ppid, ppid, session_sid] + [0] * 15 + [start]
    stat = f"{pid} ({exe}) S " + " ".join(str(x) for x in rest) + "\n"
    open(os.path.join(d, "stat"), "w").write(stat)
    cg = (f"0::/user.slice/user-1000.slice/session-{scope}.scope\n"
          if scope else "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n")
    open(os.path.join(d, "cgroup"), "w").write(cg)
    open(os.path.join(d, "comm"), "w").write(f"{exe}\n")
    if cmdline is not None:
        open(os.path.join(d, "cmdline"), "wb").write(
            b"\0".join(x.encode() for x in cmdline) + b"\0")
    return d


make_proc(1000, 900, 1000, 111, "183", exe="sshd")        # session process
make_proc(1001, 1000, 1000, 222, "183", exe="sudo")       # child
make_proc(2000, 1, 2000, 333, None, exe="systemd")        # user manager (outside)
make_proc(3000, 1, 3000, 444, "999", exe="bash")          # other session

M.PROC_ROOT = PROC
M.WTMP_FILE = os.path.join(SANDBOX, "wtmp")
M.UTMP_FILE = os.path.join(SANDBOX, "utmp")

print("\n== session-id distinction & cgroup correlation ==")
procs = M.ssh_processes("183")
ids = {p["pid"] for p in procs}
check("only session-183 cgroup processes", ids == {1000, 1001}, str(ids))
check("user manager excluded", 2000 not in ids)
check("other session excluded", 3000 not in ids)
p0 = next(p for p in procs if p["pid"] == 1000)
check("process_sid recorded separately from loginctl id",
      p0["process_sid"] == 1000 and p0["loginctl_sid"] == "183", str(p0))
check("identity is sid:pid:start",
      p0["identity"] == "183:1000:111", p0["identity"])
check("repeat scan stable identity",
      {p["identity"] for p in M.ssh_processes("183")} ==
      {"183:1000:111", "183:1001:222"})

print("\n== loginctl_sid vs POSIX process_sid ==")
sess = [{"key": "sid:183", "sid": "183", "uid": "1000", "user": "bocal",
         "seat": "-"}]
M.loginctl_sessions = lambda: sess
M.loginctl_detail = lambda sid: {"User": "1000", "Remote": "yes",
                                 "RemoteHost": "10.23.1.3", "Service": "sshd",
                                 "Leader": "1000", "TTY": ""}
M.utmp_sessions = lambda: [{"key": ("utmp", "pts/1", "bocal", "10.23.1.3", 1),
                            "user": "bocal", "line": "pts/1",
                            "host": "10.23.1.3", "start": 1}]
s = M.ssh_sessions()
check("remote session detected", len(s) == 1, str(s))
check("loginctl_sid kept as 183", s[0]["loginctl_sid"] == "183")
check("leader_pid kept separately", s[0]["leader_pid"] == 1000)
check("line falls back to utmp by host", s[0]["line"] == "pts/1", s[0]["line"])

print("\n== classification ==")
check("session kind", s[0]["kind"] == "ssh-session")
check("connection is not a session kind",
      M._ssh_should_webhook({"kind": "ssh-connection", "account": None}))
check("non-bocal session not webhooked",
      not M._ssh_should_webhook({"kind": "ssh-session", "account": "alice"}))
check("bocal session webhooked",
      M._ssh_should_webhook({"kind": "ssh-session", "account": "bocal"}))
check("history never webhooked",
      not M._ssh_should_webhook({"kind": "ssh-history", "account": "bocal"}))

print("\n== redaction ==")
argv = ["cmd", "--password", "hunter2", "--token=abc123",
        "--user", "bob", "Authorization: Bearer zzz.zzz",
        "AWS_SECRET_ACCESS_KEY=AKIAxxxx", "ghp_deadbeefdeadbeef",
        "/bin/sh", "-c", "curl -H 'X: 1'"]
red = M._redact_argv(argv)
joined = " ".join(red)
check("--password next token masked", "hunter2" not in joined, joined)
check("--token=value masked", "abc123" not in joined, joined)
check("Bearer credential masked", "zzz.zzz" not in joined, joined)
check("KEY=value masked", "AKIAxxxx" not in joined, joined)
check("github token masked", "ghp_deadbeefdeadbeef" not in joined, joined)
check("script body masked", "curl" not in joined, joined)
check("safe args kept", "bob" in joined)

print("\n== command capture off by default ==")
check("SSH_CMDLINE default off", M.SSH_CMDLINE is False)
M.SSH_CMDLINE = False
check("no cmd_redacted when off",
      next(p for p in M.ssh_processes("183") if p["pid"] == 1001)["cmd_redacted"]
      is None)
M.SSH_CMDLINE = True
make_proc(1001, 1000, 1000, 222, "183", exe="sudo",
          cmdline=["sudo", "-S", "-n", "--password", "s3cret", "-u", "root"])
p = next(p for p in M.ssh_processes("183") if p["pid"] == 1001)
check("cmd summary redacted when enabled",
      p["cmd_redacted"] is not None and "s3cret" not in " ".join(p["cmd_redacted"]),
      str(p["cmd_redacted"]))
M.SSH_CMDLINE = False

# ------------------------------------------------------------------ wtmp tests
print("\n== wtmp offset / rotation / truncation ==")


def rec(ut_type, line, user, host, start):
    b = bytearray(384)
    struct.pack_into("<h", b, 0, ut_type)
    b[8:8 + len(line)] = line.encode()
    b[44:44 + len(user)] = user.encode()
    b[76:76 + len(host)] = host.encode()
    struct.pack_into("<i", b, 340, start)
    return bytes(b)


USER_PROCESS = 7
with open(M.WTMP_FILE, "wb") as fh:
    fh.write(rec(USER_PROCESS, "tty7", "melayyad", ":0", 1))     # local, ignored
    fh.write(rec(USER_PROCESS, "pts/0", "bocal", "10.23.1.3", 2))  # remote
    fh.write(rec(2, "pts/0", "bocal", "10.23.1.3", 3))           # not USER_PROCESS
new, state, note = M.wtmp_new_records({})
check("only USER_PROCESS remote record kept", len(new) == 1, str(new))
check("local :0 ignored", all(r["host"] != ":0" for r in new))
check("offset advanced to size", state["offset"] == os.path.getsize(M.WTMP_FILE))
again, state2, _ = M.wtmp_new_records(state)
check("no replay of old records", again == [], str(again))

with open(M.WTMP_FILE, "ab") as fh:
    fh.write(rec(USER_PROCESS, "pts/2", "bocal", "10.23.1.4", 4))
delta, state3, _ = M.wtmp_new_records(state2)
check("new record read once", len(delta) == 1 and delta[0]["host"] == "10.23.1.4")

# rotation: replace with a fresh file (new inode)
tmp = M.WTMP_FILE + ".new"
with open(tmp, "wb") as fh:
    fh.write(rec(USER_PROCESS, "pts/3", "bocal", "10.23.1.5", 5))
os.replace(tmp, M.WTMP_FILE)
rot, state4, note = M.wtmp_new_records(state3)
check("rotation detected", note == "rotated", note)
check("rotated file read from start", len(rot) == 1, str(rot))

# truncation: same inode shrunk below the stored offset. Grow the file first so
# the stored offset is genuinely beyond the shrunken size, then truncate in place
# (same inode) and confirm the reader rewinds to 0 instead of skipping bytes.
with open(M.WTMP_FILE, "ab") as fh:
    fh.write(rec(USER_PROCESS, "pts/5", "bocal", "10.23.1.7", 7))
    fh.write(rec(USER_PROCESS, "pts/6", "bocal", "10.23.1.8", 8))
grown, state_grown, _ = M.wtmp_new_records(state4)
with open(M.WTMP_FILE, "wb") as fh:            # truncates in place, same inode
    fh.write(rec(USER_PROCESS, "pts/4", "bocal", "10.23.1.6", 6))
big = state_grown["offset"]
tr, state5, note = M.wtmp_new_records(state_grown)
check("offset was past shrunken size", big > os.path.getsize(M.WTMP_FILE),
      f"{big} vs {os.path.getsize(M.WTMP_FILE)}")
check("truncation detected", note == "truncated", note)
check("truncated file re-read from 0", len(tr) == 1, str(tr))

# unsupported layout
with open(M.WTMP_FILE, "ab") as fh:
    fh.write(b"\0" * 7)
un, state6, note = M.wtmp_new_records(state5)
check("unsupported size reported", note and note.startswith("unsupported"), note)
check("unsupported returns no records", un is None, str(un))

print("\n== payloads: metadata only, no argv/secrets ==")
M.remote_alert = lambda t, x: True
for ev, must in [
    ({"kind": "ssh-session", "account": "bocal", "uid": "1000",
      "remote_host": "10.23.1.3", "loginctl_sid": "183", "line": "pts/1",
      "service": "sshd", "evidence": "OBSERVED"},
     ["ssh-session", "bocal", "10.23.1.3", "loginctl 183", "OBSERVED"]),
    ({"kind": "ssh-connection", "account": None, "peer": "10.23.1.9",
      "peer_port": "5555", "local_port": 22, "evidence": "OBSERVED"},
     ["ssh-connection", "10.23.1.9", "none correlated", "OBSERVED"]),
    ({"kind": "ssh-command", "account": "bocal", "remote_host": "10.23.1.3",
      "loginctl_sid": "183", "exe": "sudo", "pid": 1, "ppid": 0,
      "start_ticks": 9, "automation": "automated", "evidence": "OBSERVED",
      "cmd_redacted": ["sudo", "***REDACTED***"]},
     ["ssh-command", "executable: sudo", "automation: automated"]),
    ({"kind": "ssh-x11vnc", "service": "x11vnc.service", "from": "active",
      "to": "inactive", "evidence": "OBSERVED"},
     ["x11vnc.service", "active -> inactive", "cause: unknown"]),
]:
    title, text = M.ssh_remote_message(ev)
    blob = title + "\n" + text
    ok = all(x in blob for x in must)
    check(f"payload has fields: {ev['kind']}", ok, blob)
    check(f"payload has no argv/secret: {ev['kind']}",
          "cmd_redacted" not in blob and "s3cret" not in blob, blob)

print("\n== webhook dedup + rate limit ==")
sent = []
M.remote_alert = lambda t, x: (sent.append((t, x)) or True)
M.log_alert = lambda msg: None
M.notify = lambda *a, **k: None
M.SSH_WEBHOOK_COOLDOWN = 0.0
M.SSH_WEBHOOK_MAX = 3
M._ssh_wh_times.clear()
M._ssh_wh_last.clear()
for i in range(5):
    M.ssh_emit({"kind": "ssh-connection", "account": None,
                "peer": f"10.0.0.{i}", "peer_port": "1", "local_port": 22,
                "evidence": "OBSERVED"})
check("global cap respected", len(sent) == 3, len(sent))
# per-key cooldown
sent.clear()
M._ssh_wh_times.clear()
M._ssh_wh_last.clear()
M.SSH_WEBHOOK_COOLDOWN = 100.0
for _ in range(3):
    M.ssh_emit({"kind": "ssh-session", "account": "bocal",
                "remote_host": "1.2.3.4", "loginctl_sid": "9",
                "evidence": "OBSERVED"})
check("per-key cooldown dedups", len(sent) == 1, len(sent))

print("\n== severity ==")
check("session info", M.ssh_severity({"kind": "ssh-session"}) == "info")
check("connection warning", M.ssh_severity({"kind": "ssh-connection"}) == "warning")
check("automated command info",
      M.ssh_severity({"kind": "ssh-command", "automation": "automated"}) == "info")
check("manual command warning",
      M.ssh_severity({"kind": "ssh-command", "automation": "unknown"}) == "warning")
check("different account not auto-urgent",
      M.ssh_severity({"kind": "ssh-session", "account": "alice"}) == "info")

print("\n== source report ==")
src = M.ssh_source_report()
check("source report has keys", set(src) >= {"ss", "proc", "utmp", "wtmp"})
M.WTMP_FILE = os.path.join(SANDBOX, "missing-wtmp")
check("missing wtmp reported", M.ssh_source_report()["wtmp"] is False)

print("\n== separation from VNC/RDP ==")
check("port 22 not in REMOTE_PORTS", 22 not in M.REMOTE_PORTS)
check("no ssh kind in VIEWER_TIERS",
      not any("ssh" in t.lower() for t in M.VIEWER_TIERS))
check("SSH kinds have distinct names",
      M.ssh_sessions()[0]["kind"] == "ssh-session")

print("\n== outbound (client-side) detection ==")


class _FakeSS:
    def __init__(self, out):
        self.stdout = out
        self.returncode = 0


_ESTAB = "\n".join([
    "0 0 10.11.1.5:22 10.23.1.3:48676",       # server socket -> skip
    "0 0 10.11.1.5:54321 1.2.3.4:22",         # outbound ssh
    "0 0 10.11.1.5:54322 1.2.3.4:5900",       # outbound vnc
    "0 0 10.11.1.5:54323 1.2.3.4:3389",       # outbound rdp
    "0 0 10.11.1.5:34567 1.2.3.4:443",        # unrelated -> ignore
]) + "\n"
_LISTEN = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
_orig_run = M.subprocess.run
M.SSH_OUTBOUND = True


def _fake_run(cmd, *a, **k):
    # established query vs listener query get different fixtures
    return _FakeSS(_LISTEN if "-tln" in cmd else _ESTAB)


M.subprocess.run = _fake_run
outs = M.outbound_peers()
ports = sorted(o["rport"] for o in outs)
check("outbound finds 22/5900/3389", ports == [22, 3389, 5900], str(ports))
check("server socket (local :22, listener present) not counted",
      all(o["lport"] != 22 for o in outs), str(outs))
check("unrelated :443 not counted", all(o["rport"] != 443 for o in outs))
check("outbound carries both endpoints",
      outs and {"lhost", "lport", "rhost", "rport"} <= set(outs[0]))
check("outbound is not webhooked",
      not M._ssh_should_webhook({"kind": "outbound", "account": None}))

# Improvement: a local service port is reported when NO listener is bound to it.
M.subprocess.run = lambda cmd, *a, **k: _FakeSS(
    "0 0 10.11.1.5:5900 1.2.3.4:22\n" if "established" in cmd else _LISTEN)
o2 = M.outbound_peers()
check("client-bound service port reported when not listening",
      len(o2) == 1 and o2[0]["lport"] == 5900 and o2[0]["rport"] == 22, str(o2))

# Conservative: with listener info unavailable, a local service port is skipped
def _no_listen(cmd, *a, **k):
    if "-tln" in cmd:
        raise OSError("ss listener denied")
    return _FakeSS(_ESTAB)
M.subprocess.run = _no_listen
o3 = M.outbound_peers()
check("listener-unavailable -> local service port skipped",
      o3 is not None and all(o["lport"] != 22 for o in o3), str(o3))

# detection failure -> None (degraded, not "none")
def _boom(*a, **k):
    raise OSError("ss missing")
M.subprocess.run = _boom
check("outbound failure returns None", M.outbound_peers() is None)
# disabled via flag -> [] (no scan at all)
M.SSH_OUTBOUND = False
M.subprocess.run = _orig_run
check("outbound disabled returns empty", M.outbound_peers() == [])
M.SSH_OUTBOUND = True

# ------------------------------------------------------------------- restore
print("\n== sandbox guard ==")
check("sandbox under /tmp", SANDBOX.startswith("/tmp"))
check("state dir under sandbox",
      os.path.realpath(M.STATE_DIR).startswith(os.path.realpath(SANDBOX)))

print(f"\nRESULT pass={PASS} fail={FAIL}")
shutil.rmtree(SANDBOX, ignore_errors=True)
sys.exit(1 if FAIL else 0)