# Review request: unprivileged VNC/remote-viewing detection on a monitored workstation

I need a second opinion on a detection tool. Below is the environment, what I found,
what I built, what I tested, and where I know it is weak. I want concrete improvements
or better techniques, not a restatement of the design. The script is `vnc-watch.py`
(paste it alongside this brief; pure Python 3 stdlib only).

Identifiers below are genericized: host names, addresses, account names and vendor
service names are placeholders. Everything else is real behavior observed on an X11
GNOME workstation running a centrally managed campus image.

---

## 1. Environment

| Item | Value |
|---|---|
| OS | Ubuntu 22.04.5, kernel 6.8.0 |
| Display | X11 (`:0`), GNOME 42, lightdm — **not** Wayland |
| Host | shared lab workstation, LAN `192.0.2.10`, institution-managed image |
| Account | a normal user, uid 1000, **no sudo, not in `input` group** |
| Home | network-mounted (iSCSI/iSCSI-like) volume, small (a few GB), nearly full |
| Auth | central directory (SSSD/LDAP + Kerberos) |
| Logging | local rsyslog forwards `*.*` to a central syslog server |
| Firewall | ufw **disabled** |

The workstation runs an institution-managed monitoring stack as root. The role of each
component matters more than its name:

## 2. What I found (monitoring stack)

| Component | Role | Sees screen? |
|---|---|---|
| remote-viewing service (root) | `x11vnc`-style server, `-display :0`, listens `0.0.0.0:5900`, `-shared -forever -xdamage` | **Yes — live, shared, full control** (no `-viewonly`) |
| remote worker (root) | task worker for a proctoring/management backend, talks to a message broker, runs continuously, can capture on command | **Yes — on command** (`XGetImage`/`fb0` style, no network trace) |
| timing/telemetry daemon | periodic process/lock check, reports state to a remote API with a service token, can force logout/reboot/restart display manager | No |
| display guard | reads xrandr/xset/gamma, terminates the session on suspected screen blackout | No |
| idle / physical-input watchers (root) | read `/dev/input/event*`, **timestamps only**, explicitly discard keycodes/coords | No |
| lock supervisor, home-ownership hook, PAM session hooks | lock enforcement, network-home ownership, session hooks | No |

Relevant fact: `/var/log/x11vnc.log` is mode `644`, so an unprivileged user **can** read
VNC connection records. That is the basis of everything I built.

Prior traffic in that log, unexplained: five connections 21:02–21:04 from `127.0.0.1`,
each `0.0 s`, each rejected as `Got 'ws' WebSockets handshake` / `Hixie no longer supported`,
retrying with exponential backoff (1 s → 5 s → 30 s → 60 s) then stopping. No RFB
handshake has ever completed on this machine.

## 3. What I built

`vnc-watch.py`, two modes:

- `--audit` — parse the whole log, classify every past connection.
- default — live watch, alerts on detection.

Signals used concurrently:

1. **Tail `/var/log/x11vnc.log`**, event-parse: `Got connection from client <peer>`,
   `Client <peer> gone`, handshake proof (`Client Protocol Version`, `Pixel format`,
   case-insensitive because x11vnc mixes casing), `Normal socket connection`,
   `WebSockets handshake`.
2. **Socket poll** every 0.4 s: `ss -H -tn state established '( dport = :5900 or sport = :5900 )'`.
3. **X client count**: connected AF_UNIX sockets to `X11-unix/X0` in `/proc/net/unix`
   (state `03`), baseline snapshot, alert on `+2`.
4. **x11vnc CPU delta** from `/proc/<pid>/stat` utime+stime over 2 s (log only, not alerting).

Classification rule: `VIEWER` if a handshake line was seen **or** the connection
lasted ≥ 3 s; otherwise `probe`. Deliberately biased to false positives.

Alerting: `notify-send -u critical -t 0`, terminal bell, append to
`~/.local/state/vnc-watch.log`.

Run detached: `setsid nohup python3 -u vnc-watch.py > out 2>&1 &`.

### Bugs I hit and fixed while testing (in case they recur)

- `NEGOTIATED` tuple matched `"Normal Socket connection"` but the log emits
  `"Normal socket connection"` — case-sensitive `in` silently never matched.
- The live `negotiated` branch keyed on `payload in pending`, but `payload` was the
  log line text while `pending` was keyed by peer — handshake never attached to a connection.
  Audit mode worked, live mode did not. Fixed by attaching to the newest pending entry.
- Redirecting stdout to a file made output invisible until exit → must run `python3 -u`.
- `pkill -f 'vnc-watch.py'` matches its own command line and SIGTERMs the invoking shell.
  Needs `pkill -f '[v]nc-watch.py'`.
- A process-argument pattern that also appears in the invoking command line can match the
  shell itself; prefer bracket patterns and avoid the same literal elsewhere in the command.

## 4. Test results

| Test | Simulated | Live output | Audit verdict |
|---|---|---|---|
| A | connect + immediate close | `probe closed after 0.00s` | `probe (instant connect/close)` |
| B | socket held 5 s, no RFB | `!!! VNC VIEWER ... 5.0s` | `REAL VNC SESSION (no handshake seen)` |
| C | RFB 003.008 version exchange | `handshake: Client Protocol Version 3.8` then `!!! VNC VIEWER ... 2.9s` | `REAL VNC SESSION` |

All tests from `127.0.0.1` (cannot spoof a remote source without root). Desktop
notifications fired and persisted. Side effect noticed in the log: x11vnc logs
`Disabled X server key autorepeat` on connect and `Restored ... to: 1` on disconnect —
a possible physical tell (hold a key; if it stops repeating, someone is attached).

## 5. Known weaknesses — where I want ideas

1. **Root can silence it.** `-quiet`, truncating/rotating the log, or bypassing VNC
   entirely (`XGetImage` with root X auth, `/dev/fb0`) leaves zero network and zero log trace.
   Detection is best-effort against a non-root adversary only.
2. **Log rotation/truncation is not handled.** The tail keeps a byte offset; if the file is
   rotated (inode change) or truncated, detection silently stops or seeks wrong. No inode check.
3. **Multi-client collisions.** `-shared` permits multiple viewers; `pending` is keyed by peer
   string, so two clients from the same IP overwrite each other.
4. **Attribution is nil.** Peer IP only — no reverse DNS, no process, no ASN/geo. `ss -p`
   cannot name root-owned processes.
5. **X client count heuristic is crude.** Baseline ~27, threshold `+2`, 2 s poll. A short-lived
   screenshot grab (milliseconds) is invisible; a browser opening tabs could false-positive.
6. **No view-only vs control distinction.** Assumed impossible client-side. Is it? Idea:
   correlate physical input (unavailable — the institution's input-idle file is root-only) with
   X input activity to infer XTEST injection. Any unprivileged path to that?
7. **CPU heuristic unused for alerting** (logged only). Threshold `>0.5 s CPU / 2 s` is a guess,
   no calibration, no suppression of known-busy periods.
8. **No supervision.** If the process dies nothing restarts it. A `systemd --user` unit is
   possible but the graphical session bus must exist for `notify-send`.
9. **Alert log is plaintext, unanchored**, and lives on the same volume an admin controls.
10. **xdg-desktop-portal screencast is not covered at all.** A remote-desktop implementation
    installed by default could serve a PipeWire screencast via the portal that would not touch
    port 5900 or x11vnc's log.

## 6. What I want from you

Concrete, implementable answers — not a general audit methodology:

1. **Rotation/truncation-safe tailing** in pure Python: track `(st_dev, st_ino, size)` and
   reopen on change, or is inotify worth the dependency? Show the correct state machine,
   including partial lines split across reads.
2. **Can an unprivileged user detect `XGetImage` / `/dev/fb0` grabs at all?** Evaluate the
   X-Resource extension as an enumerator of client connections (would need a pure-Python X
   protocol implementation since `python-xlib`/`xrestop` are absent — is that realistic?).
   Compare with AF_UNIX connected-socket deltas from `/proc/net/unix`. Which is actually
   reliable, and what are the miss windows?
3. **Attribution without root.** Anything in `/proc` or `/proc/net` that maps an established
   `:5900` peer to a process/uid for *other* users? If no, say so plainly.
4. **Better `VIEWER` rule.** Should I require handshake + `created xdamage object` + a
   minimum `client_count: 1` dwell, instead of the 3 s timeout? Propose a rule with
   explicit false-positive/false-negative trade-offs.
5. **Input-injection inference without `/dev/input`.** Is there a sound way to distinguish
   XTEST-injected events from physical ones as an unprivileged X client (XRECORD on own
   session, XI2 raw events, pointer motion vs. `loginctl` IdleHint)? If it requires root, say so.
6. **Portal/PipeWire coverage.** What unprivileged artifacts reveal a screencast started via
   `xdg-desktop-portal` — D-Bus name ownership, `~/.local/share/xdg-desktop-portal` logs,
   `pw-dump` node names? Give the specific check.
7. **Supervision.** `systemd --user` unit vs. a `tmux` pane vs. cron `@reboot` for a process
   that must survive terminal close and has no root. Recommend one and write the unit.
8. **Anything I have missed** on an X11 GNOME box for remote viewing: MIT-SHM segments in
   `/dev/shm`, GLX/DRI, `X11-unix` socket acceptance, RDP/VNC paths,
   `x11vnc -R` control socket, TCP wrappers.

## 7. Constraints to respect

- No root, ever. No installing packages. No modifying the institution's monitoring services
  (tampering is exactly what the guard daemons exist to catch).
- Python 3.10 stdlib preferred; a single file is fine.
- Assume the adversary is root and can hide; the goal is honest best-effort detection plus
  a clear statement of what it cannot see.
