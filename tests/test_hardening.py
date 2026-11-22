#!/usr/bin/env python3
"""Regression tests for the robustness/hardening pass.

Covers: env-var parsing that must not crash the tool, the tailer's rotation /
truncation / disappearance handling and bounded partial buffer, streaming
audit, atomic state writes, and the single-instance watcher lock.

    python3 tests/test_hardening.py
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, os.pardir, "vnc-watch.py")
SANDBOX = tempfile.mkdtemp(prefix="vw-hard-test-")
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


def quiet_stderr(fn, *a):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        return fn(*a), buf.getvalue()


print("== env parsing ==")
v, _ = quiet_stderr(M._env_num, "VW_T_MISSING", 7, int)
check("missing env uses default", v == 7)
os.environ["VW_T_INT"] = "12"
check("valid int parsed", M._env_num("VW_T_INT", 7, int) == 12)
os.environ["VW_T_INT"] = "5M"
v, err = quiet_stderr(M._env_num, "VW_T_INT", 7, int)
check("malformed int falls back", v == 7 and "invalid" in err, (v, err))
os.environ["VW_T_INT"] = "-3"
v, err = quiet_stderr(M._env_num, "VW_T_INT", 7, int)
check("negative int falls back", v == 7 and "negative" in err, (v, err))
os.environ["VW_T_FLT"] = "2.5"
check("valid float parsed", M._env_num("VW_T_FLT", 1.0, float) == 2.5)
os.environ["VW_T_FLT"] = "nope"
v, _ = quiet_stderr(M._env_num, "VW_T_FLT", 1.0, float)
check("malformed float falls back", v == 1.0)
for k in ("VW_T_INT", "VW_T_FLT"):
    os.environ.pop(k, None)

print("\n== tailer ==")
p = os.path.join(SANDBOX, "tail.log")
with open(p, "wb") as fh:
    fh.write(b"a\nb\n")
t = M.Tail(p, from_end=False)
check("reads existing lines", t.readlines() == ["a", "b"])
with open(p, "ab") as fh:
    fh.write(b"c\npart")
check("partial line held back", t.readlines() == ["c"])
with open(p, "ab") as fh:
    fh.write(b"ial\n")
check("partial line completed", t.readlines() == ["partial"])

os.rename(p, p + ".1")
with open(p, "wb") as fh:
    fh.write(b"new1\n")
got = t.readlines()
check("rotation follows the new inode", got == ["new1"], got)

with open(p, "ab") as fh:
    fh.write(b"tail\n")
t.readlines()
with open(p, "wb") as fh:            # truncate in place (same inode)
    fh.write(b"z\n")
check("in-place truncation rereads", t.readlines() == ["z"])

os.unlink(p)
check("missing file returns empty (no raise)", t.readlines() == [])
with open(p, "wb") as fh:
    fh.write(b"back\n")
check("file reappearing is picked up", t.readlines() == ["back"])

q = os.path.join(SANDBOX, "big.log")
open(q, "wb").close()
t2 = M.Tail(q, from_end=False)
with open(q, "ab") as fh:
    fh.write(b"A" * (M.Tail.MAX_PARTIAL + 100))
t2.readlines()
check("partial buffer is bounded", len(t2.buf) <= M.Tail.MAX_PARTIAL,
      str(len(t2.buf)))

print("\n== atomic state write ==")
ap = os.path.join(SANDBOX, "state.json")
M.write_json_atomic(ap, {"k": 1, "list": [1, 2]})
with open(ap) as fh:
    doc = json.load(fh)
check("json round-trips", doc == {"k": 1, "list": [1, 2]}, doc)
check("state file is 0600",
      stat.S_IMODE(os.stat(ap).st_mode) == 0o600,
      oct(stat.S_IMODE(os.stat(ap).st_mode)))

print("\n== single-instance lock ==")
os.makedirs(M.STATE_DIR, exist_ok=True)
fd1, err1 = M.acquire_watch_lock()
check("first lock acquired", fd1 is not None and err1 is None, err1)
fd2, err2 = M.acquire_watch_lock()
check("second instance refused", fd2 is None and "already running" in err2, err2)
if fd1 is not None:
    os.close(fd1)
fd3, err3 = M.acquire_watch_lock()
check("lock reacquirable after release", fd3 is not None and err3 is None, err3)
if fd3 is not None:
    os.close(fd3)

print("\n== vault (authenticated, encrypt instead of delete) ==")
available = [b for b in ("gpg", "openssl") if shutil.which(b)]
check("at least one crypto backend is available", bool(available), available)


def _seed(prof):
    os.makedirs(os.path.join(prof, "Sessions"), exist_ok=True)
    for rel, body in (("Cookies", b"cookie-bytes"),
                      ("History", b"history-bytes"),
                      ("Sessions/session", b"tab-bytes"),
                      ("Bookmarks", b'{"roots":{}}')):
        with open(os.path.join(prof, rel), "wb") as fh:
            fh.write(body)


def _expect_raise(fn, needle=""):
    try:
        fn()
    except (RuntimeError, OSError) as exc:
        return needle in str(exc), str(exc)
    return False, "no exception raised"


def _plain_with(tar_path, members):
    """tar members: (name, kind, payload) with kind file/dir/sym/lnk.

    Writes a manifest matching the file/dir members, exactly as the real
    writer would, so the archive reaches the member checks rather than failing
    on a missing manifest.
    """
    entries = []
    for name, kind, payload in members:
        if kind == "file":
            entries.append({"rel": name, "type": "file", "size": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "mode": 0o600})
        elif kind == "dir":
            entries.append({"rel": name, "type": "dir", "size": 0,
                            "sha256": None, "mode": 0o755})
    with tarfile.open(tar_path, "w") as tar:
        data = json.dumps({"version": 1, "entries": entries},
                          sort_keys=True).encode()
        info = tarfile.TarInfo(M.VAULT_MANIFEST)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        for name, kind, payload in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(payload)
                ti.mode = 0o600
                tar.addfile(ti, io.BytesIO(payload))
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tar.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tar.addfile(ti)
            elif kind == "lnk":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tar.addfile(ti)


def _seal_evil(backend, members, name):
    work = os.path.join(SANDBOX, "evil-" + name)
    os.makedirs(work, exist_ok=True)
    plain = os.path.join(work, "plain.tar")
    _plain_with(plain, members)
    out = os.path.join(SANDBOX, name + ".tar.gpg")
    M._vault_seal(backend, "pw-test-123", plain, out)
    return out


for backend in available:
    print(f"\n-- backend: {backend} --")
    prof = os.path.join(os.environ["HOME"], ".config", "chromium", "Default")
    if os.path.isdir(prof):
        shutil.rmtree(prof)
    _seed(prof)

    arc = M.vault_store([os.path.join(prof, "Cookies")], "pw-test-123",
                        backend=backend)
    check(f"[{backend}] archive created", os.path.isfile(arc), arc)
    check(f"[{backend}] archive is 0600",
          stat.S_IMODE(os.stat(arc).st_mode) == 0o600,
          oct(stat.S_IMODE(os.stat(arc).st_mode)))
    with open(arc, "rb") as fh:
        blob = fh.read()
    check(f"[{backend}] envelope has magic + a 48-byte header",
          blob[:8] == M.VAULT_MAGIC and len(blob) > M.VAULT_HEADER_LEN)
    check(f"[{backend}] list returns the member",
          any(n.endswith("Cookies")
              for n in M._vault_list_names(arc, "pw-test-123", backend)))

    # Q8: wrong passphrase fails at the MAC, before any decryption.
    ok, detail = _expect_raise(
        lambda: M._vault_list_names(arc, "wrong-pass", backend),
        "authentication failed")
    check(f"[{backend}] wrong passphrase fails at the MAC", ok, detail)

    # Q3/Q8: corrupted ciphertext.
    corrupt = os.path.join(SANDBOX, f"corrupt-{backend}")
    with open(corrupt, "wb") as fh:
        fh.write(blob[:M.VAULT_HEADER_LEN] + b"X"
                 + blob[M.VAULT_HEADER_LEN + 1:])
    ok, detail = _expect_raise(
        lambda: M.vault_verify(corrupt, "pw-test-123", backend=backend),
        "authentication failed")
    check(f"[{backend}] corrupted ciphertext fails the MAC", ok, detail)

    # Q3/Q8: truncated archive.
    trunc = os.path.join(SANDBOX, f"trunc-{backend}")
    with open(trunc, "wb") as fh:
        fh.write(blob[:-50])
    ok, detail = _expect_raise(
        lambda: M.vault_verify(trunc, "pw-test-123", backend=backend),
        "authentication failed")
    check(f"[{backend}] truncated archive fails the MAC", ok, detail)

    # Q3/Q8: modified archive (a wiped MAC byte).
    modified = os.path.join(SANDBOX, f"mod-{backend}")
    with open(modified, "wb") as fh:
        fh.write(blob[:8] + b"\x00" * 16 + b"\x01" + blob[25:])
    ok, detail = _expect_raise(
        lambda: M.vault_verify(modified, "pw-test-123", backend=backend),
        "authentication failed")
    check(f"[{backend}] modified archive fails the MAC", ok, detail)

    # Q2/Q5/Q8: manifest hash mismatch is caught (simulates a source change
    # between the collect-time hash and the archived bytes).
    orig_hash = M._hash_file
    M._hash_file = lambda p: ("00" * 32, os.path.getsize(p))
    before = set(os.listdir(M.VAULT_DIR))
    try:
        ok, detail = _expect_raise(
            lambda: M.vault_store([os.path.join(prof, "History")],
                                  "pw-test-123", backend=backend),
            "hash mismatch")
    finally:
        M._hash_file = orig_hash
    check(f"[{backend}] manifest hash mismatch is caught", ok, detail)
    check(f"[{backend}] a failed store leaves no new archive",
          set(os.listdir(M.VAULT_DIR)) == before,
          os.listdir(M.VAULT_DIR))

    # Q4: restore round-trip.
    os.unlink(os.path.join(prof, "Cookies"))
    outcome = M.vault_restore(arc, "pw-test-123", backend=backend)
    check(f"[{backend}] restore returns a restored list",
          any(r.endswith("Cookies") for r in outcome["restored"]), outcome)
    check(f"[{backend}] restored bytes match",
          open(os.path.join(prof, "Cookies"), "rb").read() == b"cookie-bytes")

    # Q4: never overwrite an existing file silently.
    with open(os.path.join(prof, "Cookies"), "wb") as fh:
        fh.write(b"newer-local-bytes")
    outcome2 = M.vault_restore(arc, "pw-test-123", backend=backend)
    check(f"[{backend}] existing file left untouched on restore",
          open(os.path.join(prof, "Cookies"), "rb").read() == b"newer-local-bytes"
          and any(c[0].endswith("Cookies") for c in outcome2["conflicts"]),
          outcome2)

    # Q4: symlink member, hardlink member, duplicate paths, symlinked parent.
    evil = _seal_evil(backend, [("evil", "sym", "/etc/passwd")], f"sym-{backend}")
    ok, detail = _expect_raise(
        lambda: M.vault_restore(evil, "pw-test-123", backend=backend), "link")
    check(f"[{backend}] symlink member refused", ok, detail)

    evil = _seal_evil(backend, [("hl", "lnk", "target")], f"lnk-{backend}")
    ok, detail = _expect_raise(
        lambda: M.vault_restore(evil, "pw-test-123", backend=backend), "link")
    check(f"[{backend}] hardlink member refused", ok, detail)

    evil = _seal_evil(backend, [("dup", "file", b"d"),
                                ("dup", "file", b"d")], f"dup-{backend}")
    ok, detail = _expect_raise(
        lambda: M.vault_restore(evil, "pw-test-123", backend=backend),
        "duplicate")
    check(f"[{backend}] duplicate member refused", ok, detail)

    home = os.environ["HOME"]
    outside = os.path.join(SANDBOX, f"outside-{backend}")
    os.makedirs(outside, exist_ok=True)
    link = os.path.join(home, "linked")
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink(outside, link)
    evil = _seal_evil(backend, [("linked", "dir", None),
                                ("linked/b", "dir", None),
                                ("linked/b/file", "file", b"boom")],
                      f"parent-{backend}")
    outcome3 = M.vault_restore(evil, "pw-test-123", backend=backend)
    check(f"[{backend}] symlinked destination parent refused",
          any("symlink" in reason for _r, reason in outcome3["conflicts"]),
          outcome3["conflicts"])
    check(f"[{backend}] nothing written through the symlinked parent",
          not os.path.exists(os.path.join(outside, "b", "file")))
    os.unlink(link)

print("\n== vault end-to-end + partial-deletion reporting ==")
if available:
    backend = available[0]
    root = os.path.join(os.environ["HOME"], ".config", "chromium")
    prof = os.path.join(root, "Default")
    if os.path.isdir(root):
        shutil.rmtree(root)
    _seed(prof)
    with open(os.path.join(root, "Local State"), "wb") as fh:
        fh.write(b'{"profile":{}}')          # root-level account/session cache

    res = M.wipe_private_data(apply=True, allow_running=True, encrypt=True,
                              passphrase="pw-test-123")
    check("encrypt mode leaves a vault archive", bool(res["vault"]), res)
    check("encrypt mode removed the originals",
          not os.path.exists(os.path.join(prof, "History"))
          and not os.path.exists(os.path.join(prof, "Sessions")),
          (res["errors"], res["items"]))
    check("encrypt mode removed the whole profile root",
          not os.path.exists(root))
    check("encrypt mode archived the whole profile root (incl. bookmarks)",
          any(p == root for p in res["removed"]), res["removed"])

    # Q6: removed/remaining name exactly what stayed — fail closed, no passphrase.
    os.makedirs(prof, exist_ok=True)
    with open(os.path.join(prof, "History"), "wb") as fh:
        fh.write(b"keep-me")
    res2 = M.wipe_private_data(apply=True, allow_running=True, encrypt=True,
                               passphrase=None)
    check("missing passphrase keeps the data (fail closed)",
          os.path.isfile(os.path.join(prof, "History"))
          and any("vault" in e for e in res2["errors"]), res2["errors"])
    check("missing passphrase reports the survivor",
          any(p.startswith(root) for p in res2["remaining"]),
          res2["remaining"])
    check("nothing was reported removed on fail-closed",
          res2["removed"] == [], res2["removed"])

print("\n== clear: automatic browser termination ==")


def _spawn_fake(ignore_term=False):
    """A stand-in for a browser process, owned by this UID."""
    if ignore_term:
        code = ("import signal, time;"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                "time.sleep(300)")
    else:
        code = "import time; time.sleep(300)"
    return subprocess.Popen([sys.executable, "-c", code])


def _clear_profile():
    root = os.path.join(os.environ["HOME"], ".config", "chromium")
    prof = os.path.join(root, "Default")
    os.makedirs(os.path.join(prof, "Sessions"), exist_ok=True)
    for rel in ("Cookies", "History", "Sessions/session", "Preferences"):
        with open(os.path.join(prof, rel), "wb") as fh:
            fh.write(b"x" * 64)
    with open(os.path.join(prof, "Bookmarks"), "wb") as fh:
        fh.write(b'{"roots":{}}')
    with open(os.path.join(root, "Local State"), "wb") as fh:
        fh.write(b'{"profile":{}}')
    return prof


_orig_rb = M.running_browsers
_orig_rd = M.running_discord

# A cooperative process: SIGTERM is enough.
p = _spawn_fake()
M.running_browsers = lambda: [(p.pid, "firefox")]
M.running_discord = lambda: []
try:
    q = M.quit_browsers(term_grace=3.0, kill_grace=2.0)
finally:
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
check("SIGTERM stops a cooperative browser", q["all_stopped"], q)
check("cooperative process did not need SIGKILL", q["killed"] == [], q)
check("cooperative process is actually gone", p.poll() is not None)
if p.poll() is None:
    p.kill()
    p.wait()

# A process that ignores SIGTERM: must be SIGKILLed without a second prompt.
p = _spawn_fake(ignore_term=True)
time.sleep(0.6)                     # let the child install its SIGTERM handler
M.running_browsers = lambda: [(p.pid, "chromium")]
M.running_discord = lambda: []
try:
    q = M.quit_browsers(term_grace=1.0, kill_grace=4.0)
finally:
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
check("SIGTERM-ignoring browser is SIGKILLed", p.pid in q["killed"], q)
check("SIGTERM-ignoring browser does not survive", q["all_stopped"]
      and p.poll() is not None, q)
if p.poll() is None:
    p.kill()
    p.wait()

# A process that cannot be killed: reported, never claimed cleared.
p = _spawn_fake()
M.running_browsers = lambda: [(p.pid, "vivaldi")]
M.running_discord = lambda: []
_orig_kill = M._kill_if_ours
M._kill_if_ours = lambda pid, sig: False
try:
    q = M.quit_browsers(term_grace=0.4, kill_grace=0.4)
finally:
    M._kill_if_ours = _orig_kill
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
    p.kill()
    p.wait()
check("an unkillable process is reported as a survivor",
      q["survivors"] == [(p.pid, "vivaldi")] and not q["all_stopped"], q)

# UID safety: another user's process is never signalled, and unrelated
# same-UID processes are not browsers.
if os.getuid() != 0:
    check("another UID's process is never signalled",
          M._kill_if_ours(1, signal.SIGKILL) is False)
check("marker matching rejects non-browsers",
      not M._marker_matches("sleep") and not M._marker_matches("python3"))
fakebin = os.path.join(SANDBOX, "banana")
shutil.copy(shutil.which("sleep") or "/bin/sleep", fakebin)
os.chmod(fakebin, 0o755)
p = subprocess.Popen([fakebin, "120"])
time.sleep(0.3)
scan = [pid for pid, _c in M.running_browsers()]
check("unrelated same-UID process is not a browser target",
      p.pid not in scan, [p.pid, scan])
p.kill()
p.wait()

# A browser-named process (the comm a native or Snap install presents) is
# detected — the same marker matching covers every install type.
fakebin = os.path.join(SANDBOX, "firefox")
shutil.copy(shutil.which("sleep") or "/bin/sleep", fakebin)
os.chmod(fakebin, 0o755)
p = subprocess.Popen([fakebin, "120"])
time.sleep(0.3)
scan = [pid for pid, _c in M.running_browsers()]
check("a browser-named process is detected as a target",
      p.pid in scan, [p.pid, scan])
p.kill()
p.wait()

# End-to-end: ordinary Clear closes the browser, then removes its data.
prof = _clear_profile()
p = _spawn_fake()
M.running_discord = lambda: []


def _fake_rb():
    return [(p.pid, "firefox")] if p.poll() is None else []


M.running_browsers = _fake_rb
try:
    parts, q, res = M._wipe_and_summary(encrypt=False)
finally:
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
check("clear closed the browser before wiping", q["all_stopped"]
      and p.poll() is not None, q)
check("clear removed History/Cookies after closing",
      not os.path.exists(os.path.join(prof, "History"))
      and not os.path.exists(os.path.join(prof, "Cookies")), res["remaining"])
check("clear removed the whole profile root (fresh next launch)",
      not os.path.exists(os.path.join(os.environ["HOME"], ".config",
                                      "chromium")), res["remaining"])
check("clear reports no remaining browser data",
      not any("History" in r or "Cookies" in r for r in res["remaining"]),
      res["remaining"])
check("clear summary mentions the closed browser",
      any("closed" in p for p in parts), parts)

# End-to-end: Encrypt mode also closes the browser before archiving.
prof = _clear_profile()
p = _spawn_fake()
M.running_discord = lambda: []
M.running_browsers = lambda: [(p.pid, "firefox")] if p.poll() is None else []
try:
    parts, q, res = M._wipe_and_summary(encrypt=True, passphrase="pw-clear-1")
finally:
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
check("encrypt mode closed the browser first", q["all_stopped"]
      and p.poll() is not None, q)
check("encrypt mode archived the browser data",
      bool(res["vault"]) and not os.path.exists(os.path.join(prof, "Cookies")),
      (res["vault"], res["errors"]))

# A survivor must leave the data in place and say so.
prof = _clear_profile()
p = _spawn_fake()
M.running_discord = lambda: []
M.running_browsers = lambda: [(p.pid, "firefox")]
_orig_kill = M._kill_if_ours
M._kill_if_ours = lambda pid, sig: False
try:
    parts, q, res = M._wipe_and_summary(encrypt=False)
finally:
    M._kill_if_ours = _orig_kill
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
    p.kill()
    p.wait()
check("a survivor keeps its browser data in place",
      os.path.exists(os.path.join(prof, "Cookies")) and q["survivors"], q)
check("a survivor is not reported as cleared",
      any("could not be closed" in x for x in parts)
      and any(p.startswith(os.path.join(os.environ["HOME"], ".config",
                                        "chromium")) for p in res["remaining"]),
      (parts, res["remaining"]))

print("\n== clear: shutdown decoupled from wipe targets ==")


def _rm_roots():
    for stray in (".config/chromium", ".config/BraveSoftware",
                  ".config/google-chrome", ".mozilla", ".config/microsoft-edge",
                  ".config/vivaldi", ".config/opera"):
        shutil.rmtree(os.path.join(os.environ["HOME"], stray),
                      ignore_errors=True)


# The predicate that gates the panel/tray/CLI confirm dialogs.
check("_clear_has_work: targets only -> True",
      M._clear_has_work([("chromium (native)", "/p", "remove")], []) is True)
check("_clear_has_work: browsers only -> True",
      M._clear_has_work([], [(1, "firefox")]) is True)
check("_clear_has_work: neither -> False",
      M._clear_has_work([], []) is False)

# 1. No wipe targets, but a supported browser runs: it must still be closed,
#    and the report must say no data targets were found (not "nothing to do").
_rm_roots()
p = _spawn_fake()
M.running_discord = lambda: []
M.running_browsers = lambda: [(p.pid, "firefox")] if p.poll() is None else []
try:
    parts, q, res = M._wipe_and_summary(encrypt=False)
finally:
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
    if p.poll() is None:
        p.kill()
        p.wait()
check("no-targets: running browser is still closed",
      q["all_stopped"] and p.poll() is not None, q)
check("no-targets: report says no data targets found",
      res["items"] == [] and any("no supported browser" in x for x in parts),
      parts)

# 2. Wipe targets exist, no browser running: data is wiped anyway.
_rm_roots()
prof = _clear_profile()
M.running_discord = lambda: []
M.running_browsers = lambda: []
try:
    parts, q, res = M._wipe_and_summary(encrypt=False)
finally:
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
check("targets + no browser: data is wiped",
      bool(res["items"]) and not os.path.exists(
          os.path.join(os.environ["HOME"], ".config", "chromium")), res)
check("targets + no browser: nothing left in place",
      res["remaining"] == [], res["remaining"])

# 3. Neither targets nor a running browser: clean no-op.
_rm_roots()
M.running_discord = lambda: []
M.running_browsers = lambda: []
try:
    targets, browsers, total = M._clear_survey()
finally:
    M.running_browsers = _orig_rb
    M.running_discord = _orig_rd
check("neither: survey is empty", targets == [] and browsers == []
      and total == 0, (targets, browsers, total))
check("neither: no work, no dialog",
      M._clear_has_work(targets, browsers) is False)

# 4. Clear and Encrypt both shut down before touching data (record order).
def _shutdown_order(encrypt):
    _rm_roots()
    _clear_profile()
    p = _spawn_fake()
    seq = []
    _oq, _ow = M.quit_browsers, M.wipe_private_data
    M.running_discord = lambda: []
    M.running_browsers = lambda: [(p.pid, "firefox")] if p.poll() is None else []

    def rec_quit(*a, **k):
        seq.append("quit")
        return _oq(*a, **k)

    def rec_wipe(*a, **k):
        seq.append("wipe")
        return _ow(*a, **k)

    M.quit_browsers = rec_quit
    M.wipe_private_data = rec_wipe
    try:
        M._wipe_and_summary(encrypt=encrypt,
                            passphrase=("pw-order" if encrypt else None))
    finally:
        M.quit_browsers = _oq
        M.wipe_private_data = _ow
        M.running_browsers = _orig_rb
        M.running_discord = _orig_rd
        if p.poll() is None:
            p.kill()
            p.wait()
    return seq


check("clear shuts down before wiping", _shutdown_order(False) == ["quit", "wipe"])
check("encrypt shuts down before archiving",
      _shutdown_order(True) == ["quit", "wipe"])

print("\n== lock session ==")


def _fake_supervisor(path, reply, after=None):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with conn:
            try:
                conn.recv(64)
                if after:
                    after()
                conn.sendall(reply)
            except OSError:
                pass
    threading.Thread(target=serve, daemon=True).start()
    return srv


def _write_state(path, locked, intervals=None):
    with open(path, "w") as fh:
        json.dump({"session": "c82", "username": "melayyad",
                   "locked": locked, "intervals": intervals or []}, fh)


class _R:
    def __init__(self, rc, out=b""):
        self.returncode = rc
        self.stdout = out if isinstance(out, str) else out.decode()
        self.stderr = ""


sockdir = tempfile.mkdtemp(prefix="vw-lock-", dir=SANDBOX)
_orig_sock = M.LOCK_SOCKET
_orig_policy = M.POLICY_FILE
_orig_run = M.subprocess.run
_orig_confirm = M.LOCK_CONFIRM_TIMEOUT
M.LOCK_CONFIRM_TIMEOUT = 0.4          # keep the suite fast


def _no_run(*_a, **_k):
    return _R(1)


state = os.path.join(sockdir, "seat.json")

# 1. successful lock and state transition.
_write_state(state, False)
sock = os.path.join(sockdir, "ok.sock")
srv = _fake_supervisor(sock, b"LOCKED\n",
                       after=lambda: _write_state(state, True))
M.LOCK_SOCKET = sock
M.POLICY_FILE = state
M.subprocess.run = _no_run
try:
    ok, how = M.lock_session()
finally:
    M.subprocess.run = _orig_run
    srv.close()
check("lock success requires a locked state transition",
      ok is True and "supervisor" in how, (ok, how))

# 2. already locked before the request is handled explicitly.
_write_state(state, True)
st, detail = M._confirm_lock(True)
check("_confirm_lock reports already-locked, not a transition",
      st == "already" and "already" in detail, (st, detail))
sock = os.path.join(sockdir, "ok2.sock")
srv = _fake_supervisor(sock, b"LOCKED\n")
M.LOCK_SOCKET = sock
M.subprocess.run = _no_run
try:
    ok, how = M.lock_session()
finally:
    M.subprocess.run = _orig_run
    srv.close()
check("an already-locked seat is not credited to this request",
      ok is True and "already" in how, (ok, how))

# 3. socket reports success but the state file stays unlocked.
_write_state(state, False)
sock = os.path.join(sockdir, "lie.sock")
srv = _fake_supervisor(sock, b"LOCKED\n")
M.LOCK_SOCKET = sock
M.subprocess.run = _no_run
try:
    ok, how = M.lock_session()
finally:
    M.subprocess.run = _orig_run
    srv.close()
check("LOCKED reply with an unlocked state file is not success",
      ok is False and "replied LOCKED" in how, (ok, how))

# 4. missing or malformed state file must not confirm.
M.LOCK_SOCKET = os.path.join(sockdir, "none.sock")
M.POLICY_FILE = os.path.join(sockdir, "missing.json")
st, detail = M._confirm_lock(False)
check("missing state file: unconfirmed with a reason",
      st == "unconfirmed" and "unreadable" in detail, (st, detail))
with open(os.path.join(sockdir, "broken.json"), "w") as fh:
    fh.write("{not json")
M.POLICY_FILE = os.path.join(sockdir, "broken.json")
st, detail = M._confirm_lock(False)
check("malformed state file: unconfirmed",
      st == "unconfirmed" and "malformed" in detail, (st, detail))

# 5. timeout is bounded.
_write_state(state, False)
M.POLICY_FILE = state
t0 = time.monotonic()
st, detail = M._confirm_lock(False, timeout=0.5)
dt = time.monotonic() - t0
check("timeout is bounded and unconfirmed",
      st == "unconfirmed" and 0.4 <= dt <= 2.5, (st, dt, detail))

# 6. the state file updates after a delay; polling catches it.
_write_state(state, False)
threading.Thread(target=lambda: (time.sleep(0.5),
                                 _write_state(state, True)),
                 daemon=True).start()
st, detail = M._confirm_lock(False, timeout=3.0)
check("a delayed state transition is caught by polling",
      st == "locked", (st, detail))

# 7. an active interval is a guard signal, not the locked field.
now = time.time()
_write_state(state, False, [[now - 10, now + 10]])
M.POLICY_FILE = state
active, why = M.active_lock_window()
locked_now, _d = M._locked_now()
check("an active interval is detected by the guard",
      active is True and "interval" in why, (active, why))
check("an active interval is not the locked field",
      locked_now is False, locked_now)
st, _d = M._confirm_lock(False)
check("an interval-only window does not confirm a lock action",
      st == "unconfirmed", st)

# The relocation control: an unlocked seat never confirms.
_write_state(state, False)
st, _d = M._confirm_lock(False)
check("an unlocked seat never confirms", st == "unconfirmed", st)

M.LOCK_CONFIRM_TIMEOUT = _orig_confirm
M.POLICY_FILE = _orig_policy
M.LOCK_SOCKET = _orig_sock
shutil.rmtree(sockdir, ignore_errors=True)

print("\n== streaming audit ==")
log = os.path.join(SANDBOX, "x11vnc.log")
with open(log, "w") as fh:
    fh.write("01/01/2026 10:00:00 Got connection from client 1.2.3.4\n")
    fh.write("01/01/2026 10:00:05 Pixel format for client 1.2.3.4\n")
    fh.write("01/01/2026 10:00:06 Client 1.2.3.4 gone\n")
    fh.write("not a timestamped line\n")
old_log = M.LOG
M.LOG = log
out = io.StringIO()
with contextlib.redirect_stdout(out):
    rc = M.audit()
M.LOG = old_log
text = out.getvalue()
check("audit classifies streamed log",
      rc == 0 and "1 connection(s)" in text
      and "CONFIRMED RFB SESSION" in text, text[-300:])

print(f"\nRESULT pass={PASS} fail={FAIL}")
sys.exit(1 if FAIL else 0)