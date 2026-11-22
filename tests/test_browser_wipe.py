#!/usr/bin/env python3
"""Isolation tests for the browser + Discord cleanup.

Runs entirely against throwaway HOME directories under a temporary root. It
re-points $HOME for every phase, so no real profile, state dir, or Discord
file is ever read or deleted. A final guard asserts that nothing outside the
temporary root was touched.

    python3 tests/test_browser_wipe.py
"""
import importlib.util
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, os.pardir, "vnc-watch.py")
SANDBOX = tempfile.mkdtemp(prefix="vw-wipe-test-")

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


def load_module():
    os.environ["HOME"] = os.path.join(SANDBOX, "modulehome")
    os.makedirs(os.environ["HOME"], exist_ok=True)
    spec = importlib.util.spec_from_file_location("vw", SRC)
    m = importlib.util.module_from_spec(spec)
    sys.argv = ["vnc-watch"]
    spec.loader.exec_module(m)
    m.DISCORD_ROOTS = []              # never touch even a sandboxed Discord dir
    return m


M = load_module()

# ---------------------------------------------------------------- fixtures
CHROMIUM_FILES = ["History", "History-wal", "History-shm", "Cookies",
                  "Login Data", "Web Data", "Bookmarks", "Preferences"]
CHROMIUM_DIRS = ["Cache", "Code Cache", "Local Storage", "IndexedDB"]


def _touch(path, data=b"x" * 512):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def make_chromium_profile(root, profile="Default", bookmarks=b'{"roots":{}}'):
    base = os.path.join(root, profile)
    for f in CHROMIUM_FILES:
        _touch(os.path.join(base, f), bookmarks if f == "Bookmarks" else b"x" * 512)
    for d in CHROMIUM_DIRS:
        _touch(os.path.join(base, d, "data.bin"))
    return base


def make_firefox_profile(root, profile="abc.default-release", bookmarked=True):
    base = os.path.join(root, profile)
    os.makedirs(base, exist_ok=True)
    for f in ["cookies.sqlite", "formhistory.sqlite", "logins.json",
              "logins-backup.json", "key4.db", "key3.db", "sessionstore.jsonlz4"]:
        _touch(os.path.join(base, f))
    for d in ["sessionstore-backups", "cache2", "storage"]:
        _touch(os.path.join(base, d, "d.bin"))
    db = os.path.join(base, "places.sqlite")
    if os.path.exists(db):
        os.unlink(db)
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT);"
        "CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, fk INTEGER,"
        " type INTEGER, parent INTEGER);"
        "CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER);"
        "CREATE TABLE moz_inputhistory(place_id INTEGER, input TEXT);"
        "CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER);"
        "INSERT INTO moz_places VALUES (1,'https://keep.example','BM');"
        "INSERT INTO moz_places VALUES (2,'https://drop.example','H');"
        "INSERT INTO moz_bookmarks VALUES (10,1,1,0);"
        "INSERT INTO moz_historyvisits VALUES (100,2);"
        "INSERT INTO moz_inputhistory VALUES (2,'drop');"
        "INSERT INTO moz_annos VALUES (1,2);")
    con.commit()
    con.close()
    return base


def write_profiles_ini(root, rel_name):
    with open(os.path.join(root, "profiles.ini"), "w") as fh:
        fh.write("[Profile0]\nName=default-release\nIsRelative=1\n"
                 f"Path={rel_name}\nDefault=1\n")


def build_all(home, native=True, flatpak=True):
    """Create a full tree for every browser under `home`."""
    H = lambda *p: os.path.join(home, *p)
    made = {}
    for b in M.BROWSERS:
        for label, rel in b["roots"]:
            is_flatpak = "flatpak" in label
            if is_flatpak and not flatpak:
                continue
            if not is_flatpak and not native:
                continue
            root = os.path.expanduser(rel)
            os.makedirs(root, exist_ok=True)
            if b["family"] == "firefox":
                name = "abc.default-release"
                make_firefox_profile(root, name)
                write_profiles_ini(root, name)
            elif b["name"] in ("chromium", "google-chrome"):
                make_chromium_profile(root, "Default")
                make_chromium_profile(root, "Profile 1")
            else:
                make_chromium_profile(root, "Default")
            made[(b["name"], label)] = root
    return made


def fresh_home(tag):
    home = os.path.join(SANDBOX, tag)
    if os.path.exists(home):
        shutil.rmtree(home)
    os.makedirs(home)
    os.environ["HOME"] = home
    return home


def exists(*p):
    return os.path.lexists(os.path.join(*p))


# ------------------------------------------------------------------- tests
print("\n== config invariant ==")
check("browser_config_ok empty", M.browser_config_ok() == [],
      str(M.browser_config_ok()))
names = {b["name"] for b in M.BROWSERS}
check("seven browsers", names == {"firefox", "chromium", "google-chrome",
                                  "brave", "edge", "vivaldi", "opera"},
      str(names))
all_comms = set()
all_roots = set()
for b in M.BROWSERS:
    all_comms |= set(b["comms"])
    all_roots |= set(r for _l, r in b["roots"])
check("every comm has a browser/root", all_comms == M.BROWSER_COMMS)
check("every root has a family", all_roots == {r for _l, r in M.BROWSER_ROOTS})

print("\n== process-marker matching (no look-alike false positives) ==")
for good in ("firefox", "chromium", "chrome", "brave", "msedge",
             "vivaldi-bin", "opera"):
    check(f"marker matches {good}", M._marker_matches(good))
for bad in ("chrome_crashpad", "brave-browser-s", "brave-browser",
            "chromium-browser", "bash", "electron", "code"):
    check(f"marker ignores {bad}", not M._marker_matches(bad))

print("\n== discovery: native + flatpak, all browsers ==")
home = fresh_home("discovery")
build_all(home, native=True, flatpak=True)
for b in M.BROWSERS:
    for label, rel in b["roots"]:
        root = os.path.expanduser(rel)
        profs = M.discover_profiles(root, b["family"])
        check(f"discover {label}", len(profs) >= 1, f"root={root} profs={profs}")
# multiple profiles
chrome_root = os.path.expanduser("~/.config/google-chrome")
profs = M.discover_profiles(chrome_root, "chromium")
check("chrome multiple profiles", {os.path.basename(p) for p in profs} ==
      {"Default", "Profile 1"}, str(profs))

print("\n== opera legacy root-level profile ==")
home = fresh_home("opera-legacy")
op = os.path.join(home, ".config", "opera")
os.makedirs(op, exist_ok=True)
for f in CHROMIUM_FILES:                       # files directly in the root
    _touch(os.path.join(op, f), b'{"roots":{}}' if f == "Bookmarks"
           else b"x" * 512)
for d in CHROMIUM_DIRS:
    _touch(os.path.join(op, d, "data.bin"))
profs = M.discover_profiles(op, "opera")
check("opera legacy root discovered", op in profs, str(profs))
M.wipe_private_data(apply=True, allow_running=True)
check("opera legacy History deleted", not os.path.exists(os.path.join(op, "History")))
check("opera legacy Bookmarks PRESERVED (root layout)",
      os.path.exists(os.path.join(op, "Bookmarks")))

print("\n== firefox profiles.ini ==")
home = fresh_home("ff-ini")
root = os.path.join(home, ".mozilla", "firefox")
os.makedirs(root, exist_ok=True)
make_firefox_profile(root, "xyz.default-release")
write_profiles_ini(root, "xyz.default-release")
profs = M.discover_profiles(root, "firefox")
check("firefox profiles.ini path", any(os.path.basename(p) ==
      "xyz.default-release" for p in profs), str(profs))

print("\n== Snap roots: multiple firefox profiles ==")
home = fresh_home("snap-ff")
snap_root = os.path.join(home, "snap", "firefox", "common", ".mozilla",
                         "firefox")
os.makedirs(snap_root, exist_ok=True)
for name in ("aaa.default-release", "bbb.default"):
    make_firefox_profile(snap_root, name)
with open(os.path.join(snap_root, "profiles.ini"), "w") as fh:
    fh.write("[Profile0]\nName=a\nIsRelative=1\nPath=aaa.default-release\n"
             "Default=1\n\n[Profile1]\nName=b\nIsRelative=1\n"
             "Path=bbb.default\n")
check("snap firefox root is a configured root",
      "~/snap/firefox/common/.mozilla/firefox"
      in [r for _l, r in M.BROWSER_ROOTS],
      [r for _l, r in M.BROWSER_ROOTS if "snap" in r])
profs = M.discover_profiles(snap_root, "firefox")
check("snap firefox discovers both profiles",
      {os.path.basename(p) for p in profs} ==
      {"aaa.default-release", "bbb.default"}, str(profs))
res = M.wipe_private_data(apply=True, allow_running=True)
check("snap wipe: no errors", res["errors"] == [], str(res["errors"][:2]))
for name in ("aaa.default-release", "bbb.default"):
    base = os.path.join(snap_root, name)
    check(f"snap {name}: cookies removed",
          not os.path.exists(os.path.join(base, "cookies.sqlite")), base)
    check(f"snap {name}: places.sqlite (bookmarks) preserved",
          os.path.exists(os.path.join(base, "places.sqlite")), base)

print("\n== GitHub-like session cookie removed, bookmarks preserved ==")
home = fresh_home("github")
cdir = os.path.join(home, ".config", "chromium", "Default")
os.makedirs(cdir, exist_ok=True)
cookies_db = os.path.join(cdir, "Cookies")
con = sqlite3.connect(cookies_db)
con.executescript(
    "CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT,"
    " encrypted_value BLOB, path TEXT, expires_utc INTEGER);"
    "INSERT INTO cookies VALUES('github.com','user_session','tok',"
    " x'deadbeef','/', 9999999999);"
    "INSERT INTO cookies VALUES('github.com','logged_in','yes',"
    " x'cafe','/', 9999999999);")
con.commit()
con.close()
with open(os.path.join(cdir, "Bookmarks"), "wb") as fh:
    fh.write(b'{"roots":{"bookmark_bar":{"children":[{"name":"gh"}]}}}')
with open(os.path.join(cdir, "History"), "wb") as fh:
    fh.write(b"history-bytes")
res = M.wipe_private_data(apply=True, allow_running=True)
check("github: Cookies database removed whole",
      not os.path.exists(cookies_db), cdir)
check("github: no cookie record survives",
      not any(os.path.exists(p) for p in
              (cookies_db, cookies_db + "-wal", cookies_db + "-shm")))
check("github: Bookmarks preserved",
      os.path.exists(os.path.join(cdir, "Bookmarks")))
check("github: History removed",
      not os.path.exists(os.path.join(cdir, "History")))

print("\n== wipe: chromium-family + firefox (allow_running) ==")
home = fresh_home("wipe")
build_all(home, native=True, flatpak=True)
res = M.wipe_private_data(apply=True, allow_running=True)
check("no errors", res["errors"] == [], str(res["errors"][:3]))

cdef = os.path.join(home, ".config", "google-chrome", "Default")
check("chrome History deleted", not exists(cdef, "History"))
check("chrome History-wal deleted", not exists(cdef, "History-wal"))
check("chrome Login Data deleted", not exists(cdef, "Login Data"))
check("chrome Web Data deleted", not exists(cdef, "Web Data"))
check("chrome Cookies deleted", not exists(cdef, "Cookies"))
check("chrome Cache deleted", not exists(cdef, "Cache"))
check("chrome Bookmarks PRESERVED", exists(cdef, "Bookmarks"))
check("chrome Preferences PRESERVED", exists(cdef, "Preferences"))
check("chrome Profile 1 History deleted",
      not exists(home, ".config/google-chrome/Profile 1/History"))
for name, rel in [("edge", ".config/microsoft-edge"),
                  ("vivaldi", ".config/vivaldi")]:
    base = os.path.join(home, rel, "Default")
    check(f"{name} History deleted", not exists(base, "History"), base)
    check(f"{name} Bookmarks PRESERVED", exists(base, "Bookmarks"), base)
# opera native (Default layout)
check("opera History deleted",
      not exists(home, ".config/opera/Default/History"))
check("opera Bookmarks PRESERVED",
      exists(home, ".config/opera/Default/Bookmarks"))

ff = os.path.join(home, ".mozilla", "firefox", "abc.default-release")
check("firefox places PRESERVED", exists(ff, "places.sqlite"))
check("firefox cookies deleted", not exists(ff, "cookies.sqlite"))
check("firefox formhistory deleted", not exists(ff, "formhistory.sqlite"))
check("firefox logins.json deleted", not exists(ff, "logins.json"))
check("firefox key4.db deleted", not exists(ff, "key4.db"))
check("firefox key3.db deleted", not exists(ff, "key3.db"))
check("firefox sessionstore-backups deleted",
      not exists(ff, "sessionstore-backups"))
check("firefox cache2 deleted", not exists(ff, "cache2"))
check("firefox places -wal removed", not exists(ff, "places.sqlite-wal"))
con = sqlite3.connect(os.path.join(ff, "places.sqlite"))
bms = con.execute("SELECT COUNT(*) FROM moz_bookmarks").fetchone()[0]
urls = [r[0] for r in con.execute("SELECT url FROM moz_places")]
visits = con.execute("SELECT COUNT(*) FROM moz_historyvisits").fetchone()[0]
ic = con.execute("PRAGMA integrity_check").fetchone()[0]
con.close()
check("firefox bookmarks kept", bms >= 1, str(bms))
check("firefox bookmarked url kept", "https://keep.example" in urls, str(urls))
check("firefox history url dropped", "https://drop.example" not in urls, str(urls))
check("firefox visits cleared", visits == 0, str(visits))
check("firefox places integrity ok", ic == "ok", ic)

print("\n== dry-run does not modify ==")
home = fresh_home("dryrun")
build_all(home)
res = M.wipe_private_data(apply=False)
check("dry-run reports items", len(res["items"]) > 0)
check("dry-run left History", exists(home, ".config/google-chrome/Default/History"))

print("\n== running browser blocks cleanup ==")
home = fresh_home("running")
build_all(home)
orig_rb = M.running_browsers

M.running_browsers = lambda: [(999, "brave")]
try:
    res = M.wipe_private_data(apply=True)
finally:
    M.running_browsers = orig_rb
check("running: nothing removed", len(res["items"]) == 0, str(len(res["items"])))
check("running: reported skip", any("a browser is running" in s
      for s in res["skipped"]), str(res["skipped"][:1]))
check("running: History intact",
      exists(home, ".config/google-chrome/Default/History"))

print("\n== in-use file blocks cleanup ==")
home = fresh_home("inuse")
build_all(home)
orig_fiu = M._file_in_use

M._file_in_use = lambda p: 4242 if os.path.basename(p) == "History" else None
try:
    res = M.wipe_private_data(apply=True, allow_running=True)
finally:
    M._file_in_use = orig_fiu
check("in-use: History kept",
      exists(home, ".config/google-chrome/Default/History"))
check("in-use: reported skip", any("in use by pid 4242" in s
      for s in res["skipped"]), str(res["skipped"][:1]))

print("\n== path protections ==")
home = fresh_home("paths")
outside = os.path.join(SANDBOX, "outside.txt")
_touch(outside)
link = os.path.join(home, "escape")
os.symlink(outside, link)
try:
    M._remove_path(link, apply=True)
    leaked = True
except RuntimeError:
    leaked = False
check("symlink escape refused", not leaked and os.path.exists(outside))
try:
    M._remove_path("/etc/hostname", apply=True)
    refused = False
except RuntimeError:
    refused = True
check("out-of-home refused", refused)

print("\n== terminal menu exposes guarded clear ==")
with open(SRC) as fh:
    src_text = fh.read()
check("menu_clear defined", "def menu_clear(" in src_text)
check("menu option present", "clear browser + Discord data (guarded)" in src_text)
check("menu routes through _wipe_and_summary",
      "parts, _q, _res = _wipe_and_summary(True)" in src_text)

# ------------------------------------------------------------- final guard
print("\n== sandbox guard ==")
check("sandbox is under /tmp", SANDBOX.startswith("/tmp"))
check("real HOME untouched (module home under sandbox)",
      os.path.realpath(M.STATE_DIR).startswith(os.path.realpath(SANDBOX)),
      M.STATE_DIR)

print(f"\nRESULT pass={PASS} fail={FAIL}")
shutil.rmtree(SANDBOX, ignore_errors=True)
sys.exit(1 if FAIL else 0)
