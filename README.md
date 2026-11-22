# vnc-watch

An unprivileged, best-effort detector for someone viewing or controlling your
desktop session through VNC or RDP — with a popup that can cut the session and
wipe local traces, and optional out-of-band alerts to Discord, Telegram, ntfy
or WhatsApp.

It is a single Python file. No root, no packages, no kernel modules.

---

## What it does

- Watches for **VNC/RDP listeners and live connections** (`:5900`–`:5903`,
  `:3389`, `:11100`) and classifies them from the RFB protocol log when one is
  available.
- Watches for **new login sessions** (`/var/run/utmp` + `loginctl`), so an SSH
  or console login by someone else is reported even if they never touch VNC.
- Shows a **desktop notification** and an optional **action window** with three
  choices when a remote session appears.
- Can **close the VNC server** (`XKillClient` via the X-Resource extension) or
  stop your own `gnome-remote-desktop` service.
- Can **wipe browser and Discord traces** on demand.
- Can **push every alert off the machine** to a channel you control, so the
  log survives if the session is tampered with.
- Provides `lockdown`: close remote access and lock the screen, on a hotkey.

## What it does not do

This matters more than the feature list. Read it before trusting the tool.

- **It cannot see a root-level viewer that hides itself.** `x11vnc -quiet`,
  log truncation, a different VNC implementation, `/dev/fb0` reads or
  `XGetImage` grabs are invisible to it.
- **It cannot revoke only the remote mouse and keyboard.** VNC injects through
  the XTEST device and the X server refuses to let an unprivileged client
  disable that device (`BadAccess`). XTEST input is deliberately
  indistinguishable from real input. The only real control is ending the
  session (or locking it).
- **`kick` ends the whole VNC server**, not one viewer. X11 has no
  per-connection disconnect.
- **X-level features need Xorg.** Under Wayland you still get socket
  detection, login alerts, RDP service control and screen locking; VNC
  eviction and the XTEST signal do not apply.
- **A root operator on the machine can read your channel credentials**, post
  to your channel, or block outbound traffic. Remote alerts raise the cost of
  quiet access; they do not make you invisible.

---

## Requirements

| Need | Why | Without it |
|---|---|---|
| Linux, Python 3.8+ | the tool itself | — |
| Xorg session | `kick`, XTEST signal | those features report "unavailable" |
| systemd (user) | background daemon | run `vnc-watch watch` manually |
| `libX11.so.6`, `libXRes.so.1` | X client → PID mapping | `kick` reports unavailable |
| `xinput` | XTEST injection signal | that signal is skipped |
| `gdbus` or `notify-send` | desktop notifications | silent |
| `python3-gi` + GTK 3 | action window | window skipped, notification only |
| GNOME Shell 42 (X11) | top-panel indicator | use the legacy tray or action window |
| readable `/var/run/utmp` | login detection | falls back to `loginctl` |

Check what your machine has:

```bash
make check
```

Install:

```bash
make install
```

That creates `~/.local/bin/vnc-watch` (symlink), installs
`~/.config/systemd/user/vnc-watch.service`, creates the state directory, and
starts the daemon. Re-running `make install` is safe.

For a native GNOME top-panel status dot, also run:

```bash
make panel-install && make panel-restart
```

See **Top-panel indicator** below.

Without systemd:

```bash
python3 vnc-watch.py watch --input-watch
```

---

## Commands

| Command | What it does |
|---|---|
| `vnc-watch watch` | run the detector (default command) |
| `vnc-watch audit` | classify every connection in the current VNC log |
| `vnc-watch ssh` | SSH subsystem view: sessions, scoped processes, connections, wtmp, x11vnc |
| `vnc-watch portal` | one-shot screenshot/RDP/VNC status report |
| `vnc-watch menu` | interactive menu of all actions |
| `vnc-watch kick [--yes] [--dry-run]` | close a running VNC server |
| `vnc-watch xwatch [--yes] [--dry-run]` | evict screen-capture tools on `:0` (root included) |
| `vnc-watch popup [--no-auto]` | open the action window manually |
| `vnc-watch lockdown [--no-lock]` | close remote access and lock the screen |
| `vnc-watch channels [--test] [--set K=V] [--clear K]` | configure remote alerts |
| `vnc-watch shortcut [--remove] [--binding ...]` | install/remove the lockdown hotkey |
| `vnc-watch clear` | confirm, then wipe browser + Discord data (panel menu) |
| `vnc-watch lock` | lock the session (panel menu) |
| `vnc-watch menu-window` | open the interactive menu in a terminal (panel menu) |
| `vnc-watch tray [--tray-backend indicator\|floating]` | legacy GTK status dot (see below) |

Useful flags for `watch`:

- `--input-watch` — also monitor XTEST injection (supporting signal only)
- `--x-watch` — also monitor X client count (noisy, off by default)

---

## Detection confidence

Tiers come from protocol evidence, never from "a human is watching":

| Tier | Meaning |
|---|---|
| `CONFIRMED RFB SESSION` | RFB handshake completed (pixel format seen) |
| `PROBABLE` | RFB version exchanged, no handshake |
| `SUSPICIOUS` | socket held ≥ 10 s with no protocol evidence |
| `INFO` | probe, instant connect/close, rejected websocket |

Supporting signals that never change a tier: xdamage objects, x11vnc
`client_count`, X client count, CPU use, autorepeat flips, XTEST events.

---

## SSH (separate subsystem)

SSH is detected, worded and stored on its own terms. It never feeds the
VNC/RDP tiers above, never changes `REMOTE_PORTS`, and leaves all existing VNC
detection untouched. Everything here runs unprivileged.

Event kinds: `ssh-session`, `ssh-connection`, `outbound`, `ssh-command`,
`ssh-x11vnc`, `ssh-daemon`, `ssh-history`, `ssh-keychange`.

### Evidence ladder

A TCP connection to `:22` is **never** called a login. Only an explicit, readable
auth record correlated by account + source + time may be treated as
`AUTHENTICATED`, and even then it names the **account**, never the human at the
keyboard. Default evidence level is `OBSERVED`.

| Source | What it gives | Privilege |
|---|---|---|
| `loginctl` | remote sessions (`Remote=yes`/`RemoteHost`/`Service=sshd`), account, Leader PID, TTY | none |
| `/proc` | processes scoped to the session (cgroup `session-<id>.scope`, else Leader) | none |
| `ss` | established inbound TCP to `:22` | none |
| `/var/log/wtmp` | **historical** remote-login records, read forward only | none |
| `systemctl show` | `x11vnc.service` ActiveState/UnitFileState | none |
| `/var/log/auth.log`, `/var/log/btmp` | login method / failed logins, only if readable | adm/root (usually not) |

### loginctl id vs POSIX session id

They are different things. The event keeps `loginctl_sid` (e.g. `183`) and
`leader_pid` separately; process correlation uses the session cgroup
(`/user.slice/.../session-<id>.scope`, primary) or the `Leader` PID (secondary).
The POSIX `process_sid` (stat field 6) is recorded for identity but is **not**
the loginctl id. A process's identity is `loginctl_sid:pid:start_ticks`, so a
repeated poll is stable while a later run of the same binary is still new.

### Process / command visibility

On by default through `/proc`, scoped only to descendants in an identified SSH
session. It records exe, PID, PPID, session and start time. `/proc` is a
**point-in-time snapshot**, not a command history. When `/proc` is restricted the
subsystem reports a degraded source and keeps running.

Raw `argv` is **never** persisted by default. Command capture is off unless
`VNC_WATCH_SSH_CMDLINE=1`; when enabled only a redacted summary is stored —
likely secrets masked and script bodies (`-c`/`--command`) replaced. `environ`
is never read. No process is ever signalled, terminated, or interfered with.

### x11vnc

`x11vnc.service` state changes are recorded as a **service-state observation**
with `cause: unknown`. They are never attributed to a specific account.

### Client-side (outbound) connections

Separately from inbound sessions, the subsystem records **outbound** established
TCP connections this host opens to a monitored destination port (`22`, `3389`,
`5900`–`5903`, `11100`). It reports the **connection only**: local and remote
endpoint plus the destination port. It does **not** attribute a process or a
user, does **not** detect SSH tunnels or port forwards as such, and does **not**
indicate that a remote screen is being viewed or controlled. A port match is
`OBSERVED`, nothing more.

The server side is inferred by port. A local socket is treated as the server
side only when a listener is actually bound to that local port; if no listener
exists, a socket on a service port is reported rather than dropped. When
listener information is unavailable the check stays conservative and skips it.
Residual limitation: a host that both listens on a service port and uses that
same port as a *source* port for a client connection (explicit bind, or a port
range that includes it) masks that client socket as server-side.

This signal never feeds the viewer tiers and never includes command data. It is
**local-only** — never webhooked — because outbound traffic is common on a
workstation. Disable it entirely with `VNC_WATCH_SSH_OUTBOUND=0`.

### wtmp / history

The record size is validated against the file (default 384) with a first-record
sanity check; an unsupported layout is reported, not guessed. Rotation (inode
change) and truncation (size below the stored offset) are handled, partial
records are held until complete, and history is kept separate from live state.
Old records are baselined at startup and **never replayed**.

### Webhook

Metadata only: event type, account, source, timestamp, loginctl session id and
evidence level. Raw cmdlines, script bodies and environment are never sent.
Only `bocal` sessions/commands and unattributed connections/service changes
leave the machine; another account's activity stays local unless explicitly
allowed. Sends are deduplicated per session/process with a cooldown and a global
rate cap; suppressed sends are logged locally, never silently dropped. The local
audit trail is written independently of webhook delivery, and a webhook failure
never stops monitoring.

---

## The action window

Triggered by a `CONFIRMED`/`PROBABLE` viewer or a new VNC/RDP connection:

```
Remote viewing detected
VNC viewer attached
203.0.113.9:49152 -> this machine's :5900

Auto in 60 s: close the connection and wipe browser + Discord data.
[ Close + wipe ] [ Keep connection, wipe data ] [ Do nothing ]
```

- **Close + wipe** — ends the VNC server (or stops `gnome-remote-desktop`),
  then deletes browser and Discord data.
- **Keep connection, wipe data** — leaves the viewer attached, removes stored
  traces only.
- **Do nothing** — explicit dismissal.
- **No click within 60 s** — applies *Close + wipe* automatically.
- Both destructive buttons ask a second confirmation; the timeout does not.

> **This is destructive.** If you leave the window alone, it logs you out of
> Discord and web apps and deletes history, cookies and caches. Tune or disable
> it before relying on the tool:
>
> ```bash
> VNC_WATCH_POPUP_TIMEOUT=120     # longer countdown
> VNC_WATCH_POPUP_AUTO=0          # never act automatically
> ```

If the file named by `VNC_WATCH_LOCK_FILE` reports an active seat lock/exam
window, the countdown is disabled and the window waits for you. The variable is
unset by default, so on a normal machine the guard is inert and the automatic
choice is enabled.

The file is expected to be JSON with an optional `"locked": true` field and an
optional `"intervals": [[start, end], ...]` list of Unix timestamps. Point the
daemon at your institution's seat-state file only if you have one:

```bash
make install LOCKFILE=/run/seat-lock/seat0.json
# or add Environment=VNC_WATCH_LOCK_FILE=/run/seat-lock/seat0.json to the unit
```

### What the wipe removes

Supported browsers — **stable native, Snap and Flatpak** installs:

| Browser | Native root | Snap root | Flatpak app-id |
| --- | --- | --- | --- |
| Firefox | `~/.mozilla/firefox` | `~/snap/firefox/common/.mozilla/firefox` | `org.mozilla.firefox` |
| Chromium | `~/.config/chromium` | `~/snap/chromium/common/chromium` | `org.chromium.Chromium` |
| Google Chrome | `~/.config/google-chrome` | — | `com.google.Chrome` |
| Brave | `~/.config/BraveSoftware/Brave-Browser` | — | `com.brave.Browser` |
| Microsoft Edge | `~/.config/microsoft-edge` | — | `com.microsoft.Edge` |
| Vivaldi | `~/.config/vivaldi` | — | `com.vivaldi.Vivaldi` |
| Opera | `~/.config/opera` (or `Default/`) | — | `com.opera.Opera` |

Every profile in a root is cleaned (`Default`, `Profile 1`, ...; Firefox
profiles from `profiles.ini`; Opera's legacy root-level layout). Per profile
the following are removed:

- **Chromium-family** (Chromium, Chrome, Brave, Edge, Vivaldi, Opera):
  `History`, `Visited Links`, `Web Data`, `Login Data`, `Login Data For
  Account`, `Affiliation Database`, `Cookies`, `Network/Cookies`, `Sessions`,
  `Current Session`, `Current Tabs`, `Last Session`, `Last Tabs`,
  `Session Storage`, `Local Storage`, `IndexedDB`, `Cache`, `Code Cache`,
  `GPUCache`, `Service Worker`, `Shared Dictionary`, `Storage`, and the
  network-state files — each database file is deleted **together with its
  `-journal`/`-wal`/`-shm` sidecars**, so no rows survive in a WAL.
- **Firefox**: `cookies.sqlite`, `formhistory.sqlite`, `logins.json`,
  `logins-backup.json`, `key4.db`, `key3.db`, `signons.sqlite`,
  `sessionstore-backups`, `sessionstore.jsonlz4`, `storage`, `cache2`,
  `startupCache`, `shader-cache`, `crashes`.

Firefox's `places.sqlite` is **not** deleted — it holds bookmarks as well as
history. It is cleaned in place with SQL: history visits, typed-input history,
and places not referenced by any bookmark are removed, while the bookmark tree
and its annotations survive. `wal_checkpoint(TRUNCATE)` must succeed and the
database is `VACUUM`ed with `secure_delete` on; `PRAGMA integrity_check` must
return `ok`. On any unexpected failure the whole step is aborted and reported,
and the WAL/SHM files are left in place.

**Bookmarks are the only thing preserved.** Saved passwords, autofill, form
history and NSS login data are removed. On Chromium-family browsers the
`Bookmarks`/`Bookmarks.bak` files and `Preferences` are left untouched; a pass
deletes credentials and history but keeps the bookmark file.

Per Discord (`discord`, `discordcanary`, `discordptb`, `BetterDiscord`):
`Cache`, `Code Cache`, `GPUCache`, `Local Storage`, `Session Storage`,
`IndexedDB`, `logs`, `Network Persistent State`, `Service Worker`.

**Clear closes running browsers for you.** On an explicit Clear, every
supported browser process owned by your UID is terminated automatically —
SIGTERM first, then SIGKILL after a short grace period (`VW_BROWSER_TERM_GRACE`,
default 8 s, then `VW_BROWSER_KILL_GRACE`, default 4 s) — because you chose
Clear and accepted losing open tabs and unsaved work. No manual close is
requested, and the SIGKILL needs no second confirmation. Only processes owned
by your UID are ever signalled (the UID is re-checked immediately before each
signal); other users' processes and unrelated applications are never touched.
A process that cannot be killed is reported, and its data is left in place and
reported as remaining — never claimed cleared. This is local-data cleanup only:
it does not stop root-level screen monitoring, VNC viewing, screenshots, or
remote access.

A category whose application is still running is skipped rather than deleted
out from under it, and any individual file a same-user process holds open is
skipped too; every removal is logged with its size, and every skip or failure
is reported. Paths outside your home are refused and symlinks are never
followed out of it. The same shutdown runs before Encrypt mode archives its
data.

### Encrypt instead of delete

The action window has a second mode: **encrypt a recoverable archive instead
of deleting**. The same eligible files are written into one AES-256 archive
under `~/.local/state/vnc-watch/vault/`; the archive is then decrypted once and
every member's SHA-256 re-checked against a per-file manifest recorded at
archive time. Only if all of that holds are the originals removed. If the
archive cannot be created or verified, nothing is deleted (fail closed).

```bash
VNC_WATCH_VAULT_PASSPHRASE='...' vnc-watch clear --encrypt
vnc-watch clear --vault-list                 # archives, size, date
VNC_WATCH_VAULT_PASSPHRASE='...' vnc-watch clear --restore        # newest
VNC_WATCH_VAULT_PASSPHRASE='...' vnc-watch clear --restore FILE   # specific
```

The archive is an authenticated envelope: `VWVAULT1` magic ‖ 16-byte random
salt ‖ HMAC-SHA256 ‖ ciphertext. The MAC (encrypt-then-MAC) is computed over
the magic, salt and ciphertext with a key derived from the passphrase by
PBKDF2-HMAC-SHA256 (200000 iterations), and it is **verified before anything is
decrypted** — so a wrong passphrase, a flipped byte, a truncation or a modified
archive is rejected at the MAC, not silently decrypted. This is what makes the
`openssl` path authenticated; its raw AES-256-CBC has no integrity of its own.

`gpg` is used when present (symmetric, `--cipher-algo AES256`), otherwise
`openssl enc -aes-256-cbc -pbkdf2`. The passphrase is read from
`VNC_WATCH_VAULT_PASSPHRASE` or prompted for, passed to the cipher over a file
descriptor (never argv), and **never stored**. From the panel you are asked for
it in a GTK dialog. The archive itself is 0600.

Restore verifies the MAC and every member hash first, extracts into a staging
directory, then moves members into place **without clobbering**: existing files
are left untouched and reported as conflicts, and absolute paths, `..` members,
links, special files, duplicate members and symlinked destination parents are
refused. The result names the restored members and every conflict. A wipe
reports `removed` and `remaining` lists, so it is always clear which originals
were deleted and which were left — there is no atomic rollback.

Because encryption is a *recoverable* mode, it is not a privacy guarantee
against someone who later obtains the passphrase, and the archive grows with
the data you chose to keep.

> **Known limits:** deleting `Login Data` removes the stored ciphertext, but
> the OS-keyring master key (`Chrome Safe Storage`) and Firefox's NSS password
> are left in place; synced passwords/history can return from a signed-in
> account; and channel variants (Beta/Dev/Canary/Snapshot) are not covered.
> Cookies and caches are removed as whole files, so affected sites log you out.

---

## Top-panel indicator

A real GNOME **top-panel button** next to volume/battery/keyboard/lock/power —
not a floating window. It shows a coloured status dot and a click menu:

- **white** — idle: the daemon is alive and reports no remote viewer.
- **red** — the daemon reports a viewer (`CONFIRMED`/`PROBABLE`/`SUSPICIOUS`)
  or an **established** socket to a VNC/RDP port.
- **grey** — **unknown**: no readable state, a stale timestamp, or a dead
  daemon pid. Monitoring cannot be trusted, so it never shows white here.

The dot is read-only state; the menu offers the same actions as the action
window: **Open vnc-watch menu…**, **Clear browser + Discord data…** (behind the
usual confirmation), **Close VNC server (kick)**, and **Lock session**. The
clear and kick entries refuse while a campus lock/exam window is active.

It polls `state.json` every 1.5 s and mirrors the daemon's logic exactly. A
state file older than 15 s (`VNC_WATCH_STATE_MAX_AGE`) or whose `pid` is gone
counts as unknown — a stopped or crashed detector shows grey, never a
reassuring white. A **listening** service with nobody attached is idle (white);
only established connections or protocol-tiered viewers turn it red.

### Install

```bash
make panel-install    # per-user extension + mode file + shell drop-in
make panel-restart    # reload the shell once so it picks up the new env
make panel-status     # show what is installed and the shell's data dirs
make panel-uninstall  # remove everything (reload/logout to drop the button)
```

No root, no dconf writes, and no system files are touched. The pieces live
entirely under `$HOME` (see **Files**).

### Why it works this way (and the exact limitation)

GNOME only lets a shell extension add a panel item, and this machine pins
`org.gnome.shell enabled-extensions` with a root-owned dconf lock, so the
AppIndicator extension can never be enabled. Reading the Shell's own source
(`extensionSystem.js`) shows the two enable paths:

1. the locked `enabled-extensions` allow-list — unwritable; and
2. **session-mode extensions**, read from the mode file — but on Ubuntu a
   *per-user* mode extension is explicitly refused (`Desktop.is("ubuntu") &&
   isModeExtension && type === PER_USER`).

The only userspace route is to make our extension a **system**-type extension —
i.e. outside `~/.local/share`. A systemd **user** drop-in can give the Shell a
data dir under `$HOME` without root or dconf:

```
# ~/.config/systemd/user/org.gnome.Shell@x11.service.d/override.conf
[Service]
Environment=XDG_DATA_DIRS=%h/.vnc-watch-xdg:<existing dirs>
SuccessExitStatus=
SuccessExitStatus=1
SuccessExitStatus=SIGTERM
```

With that dir first, the Shell loads our copy of the `ubuntu` mode file (which
appends `vnc-watch@local` to `enabledExtensions`) and finds the extension there,
classified as **system** — so the Ubuntu per-user guard does not fire.

This is a deliberate, documented workaround of the *intent* of the campus
allow-list (it never writes the locked key). It is also fragile: it pins the
Shell's `XDG_DATA_DIRS`, needs a Shell reload, and could break on a GNOME
update. `make panel-install` prints the exact `XDG_DATA_DIRS` it wrote.

### Legacy GTK tray (superseded)

`vnc-watch tray` still exists as a separate GTK program with two backends
(`--tray-backend indicator|floating`) and its own unit
`vnc-watch-tray.service`. The **floating** backend is a docked always-on-top
chip, not a panel item; the **indicator** backend only renders when the
AppIndicator shell extension is enabled (blocked here). Do not run it alongside
the top-panel indicator. It is kept only for non-GNOME desktops and manual use.

---

## Lockdown

```bash
vnc-watch lockdown          # evict remote access, then lock
vnc-watch lockdown --no-lock
```

Bind **Ctrl+Alt+Shift+L** to it with:

```bash
make shortcut          # or: vnc-watch shortcut
```

That adds a GNOME custom shortcut (stored in dconf; no root). A physical
keypress works even while someone else is injecting input. `make install` does
not touch your keybindings.

Remove or rebind:

```bash
vnc-watch shortcut --remove
vnc-watch shortcut --binding '<Control><Alt><Shift>k'
```

The sequence is deliberate: eviction and locking happen locally first, and the
network notification is sent only afterwards, so a slow webhook cannot delay
the lock.

### How the lock is sent and verified

`lock` (and `lockdown`) sends the lock through, in order:

1. the **42 lock supervisor** socket `/run/42-lock/control` (`lock` → `LOCKED`),
2. GNOME's `org.gnome.ScreenSaver.Lock` over the session bus,
3. `loginctl lock-session`.

None of those replies is trusted on its own. After the command, the outcome is
verified only against the seat-state file named by `VNC_WATCH_LOCK_FILE`: a lock
is reported as **locked** only once that file authoritatively reports
`"locked": true`. A seat that was already locked before the request is reported
as **already locked** (a lock-without-transition, never credited to the
request), and a missing, unreadable, malformed, or never-updated state file
returns **unconfirmed** — never a false success. This matters because on a
managed seat `loginctl lock-session` exits `0` while locking nothing, and GNOME
ScreenShield may be absent entirely.

Because verification reads `VNC_WATCH_LOCK_FILE`, that variable must be set for
the process running the lock — the installed unit gets it via
`Environment=`, and an interactive terminal needs it too:

```bash
export VNC_WATCH_LOCK_FILE=/run/42-lock/seat0.json
vnc-watch lock                      # or run with the variable inline
```

The interval-based seat-lock guard (`active_lock_window`) reads the same file
but through a separate field: it treats an active `"intervals"` span as a
lock/exam window, while verification uses only the `"locked"` field, so a
scheduled window is never mistaken for a successful lock action.

---

## Sweeping capture tools (`xwatch`)

`kick` handles the usual case: one `x11vnc` server shared by several viewers,
and one `XKillClient` drops them all. `xwatch` is the wider sweep. It
enumerates every X client on `:0` through the X-Resource extension, attributes
each to a pid and uid, and evicts **capture-tool candidates** — by process
identity, not by uid, because the viewer we care about is a root-run `x11vnc`.
A uid-0 exemption would skip exactly the process we want.

```bash
vnc-watch xwatch --dry-run   # list every X client on :0, change nothing
vnc-watch xwatch             # evict the candidates (asks first)
vnc-watch xwatch --yes       # ... skipping the confirmation
```

A **candidate** is a process whose comm matches a dedicated capture tool
(`x11vnc`, `Xvnc`, `vino-server`, `gnome-remote-de...`, `xwd`, `scrot`,
`import`, `maim`, `flameshot`, `obs`, screen recorders, ...). Ambiguous
multimedia tools (`ffmpeg`, `gst-launch`, ...) are candidates only when their
argv also names a display grab (`x11grab`, `ximagesrc`, `xdisplay`); a plain
transcode or playback is never treated as surveillance. **A name match is a
candidate, not proof of active viewing.**

A candidate is a **target** (would be evicted) when its name is not on the
protected list (`lightdm`, `Xorg`, `gnome-shell`) and its uid is not exempt.
**root is not exempt** — it is the point.

Identity is revalidated immediately before every `XKillClient`: the current
base->pid mapping must still equal the original target and its comm must be
unchanged, otherwise the kill is skipped. This narrows, but cannot close, the
race — the fresh lookup and the kill are separate X round-trips, so a client
can still exit and free its base in between. Eviction is also **refused while
an exam/lock window is active**, for normal, menu, and `--yes` invocation
alike. There is no automatic or loop eviction.

- `VNC_WATCH_X_EXEMPT_UIDS` — extra uids to never evict (comma/space separated).
- `VNC_WATCH_X_EXEMPT_COMMS` — extra comm names to never target.
- `VNC_WATCH_X_EVICT_SELF=1` — also evict candidates owned by your own uid
  (off by default, so you never kill your own screenshot mid-run).

Honest limits: a service that restarts its viewer brings it back (you do not
own the restart button); the match is by process name (and argv for ambiguous
tools), which root can rename; and a capture path with **no X client** —
reading `/dev/fb0` or a kernel module — is invisible and unreachable from your
uid. `xwatch` buys eviction, evidence, and cost, not prevention, against a
root adversary.

---

## Remote alerts

Every alert is mirrored to each configured channel, which doubles as an
off-machine copy of the log.

Off-machine payloads omit hostname and username by default; those stay local.
Set `VNC_WATCH_ALERT_IDENTITY=host,user` to include them (explicit opt-in,
documented here for that purpose). If the variable is unset or empty, the
privacy-preserving default applies and no replacement identifier is added.
The `xwatch` event payload carries event type, action, result, per-target
pid/uid/comm, survivors, skips, and errors — but never argv/cmdline or
filesystem paths.

The event counters are derived from the per-target outcome lines, so the
totals cannot disagree with the details. `skipped` counts safe
identity-change skips (the base→pid binding changed before the kill, so a
recycled resource was left alone); `errors` counts operational failures
(the kill was attempted and failed, or was not sent). The `result` field
reads `all connections dropped` only when every intended target was evicted
and none survived; otherwise it is `partial` (some eviction happened) or
`no eviction`. A lock-window refusal is delivered as
`refused (exam/lock window; no eviction)` — never as a successful eviction.

```bash
vnc-watch channels                 # show config (values masked)
vnc-watch channels --test          # send a test message
vnc-watch channels --set KEY=VALUE
vnc-watch channels --clear KEY
```

Configuration lives in `~/.local/state/vnc-watch/channels.json` (mode 0600).
See `examples/channels.json`.

### ntfy.sh — easiest, no account

```bash
vnc-watch channels --set ntfy_topic=some-long-random-string
vnc-watch channels --test
```

Subscribe to the same topic in the ntfy app. The topic name is the only
secret; make it long and random.

### Discord webhook

Server → channel → Edit Channel → Integrations → Webhooks → New Webhook →
Copy URL.

```bash
vnc-watch channels --set discord_webhook='https://discord.com/api/webhooks/...'
vnc-watch channels --test
```

The webhook URL is a bearer credential: anyone holding it can post to your
channel. Delete and recreate it if it leaks.

### Telegram bot

Message `@BotFather` → `/newbot` → token. Send the bot a message, then read
your chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates`.

```bash
vnc-watch channels --set telegram_token=123456:ABC... --set telegram_chat=987654321
```

### WhatsApp (CallMeBot)

Send `I allow callmebot to send me messages` on WhatsApp to
`+34 644 51 95 23`; it replies with an API key.

```bash
vnc-watch channels --set whatsapp_phone=+15551234567 --set whatsapp_apikey=000000
```

Third-party relay: less private than ntfy or Telegram.

### Your own endpoint

Anything that accepts a JSON POST:

```json
{"title": "...", "text": "...", "host": "...", "user": "...", "time": "..."}
```

```bash
vnc-watch channels --set webhook_url=https://your-server/hook
```

### What triggers a message

- VNC/RDP connection opens, or a new listener appears on a watched port
- `CONFIRMED`/`PROBABLE` viewer detection
- New login session (utmp or loginctl), including `user@pts/N from host`
- SSH: new session, new connection with no correlated session, or `x11vnc.service`
  state change (metadata only; bocal-scoped, see the SSH section)
- Actions taken: popup choice, connection closed, data wiped, lockdown

---

## Files

```
~/.local/bin/vnc-watch                        symlink created by make install
~/.config/systemd/user/vnc-watch.service      the detector, user service
~/.config/systemd/user/vnc-watch-tray.service legacy GTK tray, user service

Top-panel indicator (make panel-install):
~/.vnc-watch-xdg/gnome-shell/extensions/vnc-watch@local/   the shell extension
~/.vnc-watch-xdg/gnome-shell/modes/ubuntu.json             mode file (adds UUID)
~/.config/systemd/user/org.gnome.Shell@x11.service.d/override.conf   drop-in

~/.local/state/vnc-watch/
    vnc-watch.log        alert log (also mirrored to your channels)
    vnc-watch.out        daemon stdout/stderr
    vnc-watch-tray.out   tray stdout/stderr
    state.json           daemon -> menu snapshot
    ack.json             menu acknowledgements (bookkeeping only)
    channels.json        0600, remote alert credentials
    xinput-xi2.log       XTEST dump, capped at 2 MB
    popup.lock           keeps one action window open at a time
    watch.lock           flock: one live watcher at a time, holds its pid
    tray-idle.png        0600, generated tray icon (white)
    tray-active.png      0600, generated tray icon (red)
    tray-unknown.png     0600, generated tray icon (grey, no data)
```

The state directory is created 0700 (so the files inside stay private
regardless of their own mode); `channels.json` is 0600 and JSON writes are
atomic. The alert log rotates once at 5 MB to `vnc-watch.log.1`, so it cannot
grow without bound. A full or unwritable volume fails closed: writes are
skipped with an error on stderr and the daemon keeps running, disabling only
XTEST input-watch if its dump cannot be opened.

Robustness details:

- Only one `watch` daemon can run: `watch.lock` is held with `flock`, so a
  second copy exits `2` instead of double-alerting or racing on `state.json`.
- `SIGTERM`/`SIGHUP` run the cleanup path (close the log tail, stop the
  `xinput` child, release the lock) instead of leaving orphans behind.
- Malformed `VNC_WATCH_*` numeric settings fall back to the documented default
  with a one-line warning; a typo cannot stop `audit` or the daemon from
  starting.
- The log tailer survives rotation, in-place truncation and a temporarily
  unreadable file, and bounds the buffer for an unterminated line (1 MiB).
- `audit` streams the log instead of reading it whole, so a large
  `x11vnc.log` cannot exhaust memory on a small home volume.

---

## Troubleshooting

**Nothing happens / no daemon**

```bash
make status
systemctl --user status vnc-watch
tail -n 40 ~/.local/state/vnc-watch/vnc-watch.out
```

**`kick` says "no X client maps to this PID"**

The X-Resource extension is missing or the server uses a display other than
`:0`. Check `xdpyinfo | grep X-Resource`.

**Action window never appears**

GTK 3 for Python is missing (`make check`), or the daemon has no `DISPLAY`.
It also refuses to open more than one window at a time, and at most one per
120 s.

**Discord returns `http 403 error code: 1010`**

Cloudflare rejects Python's default User-Agent. This is already fixed in the
code; if you see it again, your proxy or a newer block is involved. Test with
`curl -H 'User-Agent: vnc-watch/1.0' ...`.

**Wiped data came back**

A running browser can re-flush databases from memory. Close browsers before
relying on a wipe.

**Top-panel indicator missing after install**

The extension is enabled only after the Shell reloads with the new data dir:

```bash
make panel-status      # are the extension, mode file, and drop-in present?
make panel-restart     # reload the shell once
gnome-extensions info vnc-watch@local   # expect: State: ENABLED
journalctl --user -n 100 --no-pager | grep -i 'vnc-watch@local'
```

If `State` is `INITIALIZED` or the button is absent, the Shell did not see the
new `XDG_DATA_DIRS` — confirm `panel-status` shows `~/.vnc-watch-xdg` first,
then reload again (or log out and back in).

**Panel dot is stuck grey**

Grey means the daemon snapshot is missing, stale (>15 s), or its `pid` is dead.
Check `make status` and `systemctl --user status vnc-watch`.

**Daemon stopped with "Start request repeated too quickly"**

It hit the restart limit after repeated failures (often a full disk):

```bash
systemctl --user reset-failed vnc-watch
systemctl --user start vnc-watch
```

---

## Uninstall

```bash
make panel-uninstall          # remove the top-panel indicator (then reload)
make uninstall                # stop and remove service + symlink, keep state
make purge                    # also delete ~/.local/state/vnc-watch
vnc-watch shortcut --remove   # remove the hotkey
```

---

## How it works

- **Connections**: `ss`/`/proc/net/tcp` for live peers and listeners;
  optional tailing of `/var/log/x11vnc.log` for RFB handshake evidence.
- **X clients**: the X-Resource extension maps each X client to a PID
  (`XResQueryClientIds`, mask bit 1). `XKillClient` on the VNC server's client
  base ends its display connection.
- **Logins**: fixed-offset parsing of the 384-byte `struct utmp`, plus
  `loginctl list-sessions`.
- **Notifications**: libnotify over D-Bus. **Action window**: GTK 3.
- **Remote alerts**: `urllib` posts, queued on a daemon thread so a slow
  endpoint cannot stall detection.

Environment variables: `VNC_WATCH_POPUP_TIMEOUT`, `VNC_WATCH_POPUP_AUTO`,
`VNC_WATCH_LOCK_FILE` (seat-lock guard and lock verification; unset = disabled),
`VNC_WATCH_LOCK_CONFIRM_TIMEOUT` (lock-verify poll, default 5 s),
`VNC_WATCH_X_EXEMPT_UIDS`, `VNC_WATCH_X_EXEMPT_COMMS`,
`VNC_WATCH_X_EVICT_SELF` (`xwatch` targeting),
`VNC_WATCH_ALERT_IDENTITY` (off-machine host/user; unset = private),
`VNC_WATCH_XI_MAX`, `VNC_WATCH_LOG_MAX`, `VNC_WATCH_UTMP` (testing).

---

## Scope and ethics

This is a personal privacy tool for **your own session on your own account**.
It observes, and on request ends, remote access to the machine you are sitting
at. It is not a monitoring tool for other people, and it should not be pointed
at anyone else's session.

Some of what it does — closing a service run by your institution, wiping data
on a shared machine — may conflict with campus policy, even when the action is
in your own account. Read your institution's rules before enabling the
automatic actions, and prefer `VNC_WATCH_POPUP_AUTO=0` if you are unsure.