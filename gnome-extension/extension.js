// vnc-watch top-panel indicator for GNOME Shell 42 (legacy extension).
//
// A real panel button in the system status area: a coloured dot plus a menu.
//   white = idle   red = viewer attached   grey = monitoring unavailable
//
// It reads the daemon's snapshot and mirrors tray_state() from vnc-watch.py
// exactly, so the panel can never show a reassuring white when monitoring is
// dead, stale, or unreadable. Menu actions shell out to the vnc-watch CLI.
//
// No root, no dconf, no system files: this extension is installed into a
// per-user dir that is exposed to the shell as a *system* data dir.

'use strict';

const { Clutter, GLib, GObject, St } = imports.gi;
const Cairo = imports.gi.cairo;

const Main = imports.ui.main;
const PanelMenu = imports.ui.panelMenu;
const PopupMenu = imports.ui.popupMenu;

const UUID = 'vnc-watch@local';

// Must match BASE_STATE / STATE_FILE in vnc-watch.py.
const STATE_FILE = GLib.build_filenamev(
    [GLib.get_home_dir(), '.local', 'state', 'vnc-watch', 'state.json']);

const POLL_MS = 1500;                 // TRAY_STATE_MAX_AGE is 15s in the daemon
const MAX_AGE = 15;
const VIEWER_TIERS = new Set(
    ['CONFIRMED RFB SESSION', 'PROBABLE', 'SUSPICIOUS']);

const COLORS = {
    idle: [1.00, 1.00, 1.00],         // white
    active: [0.92, 0.16, 0.16],       // red
    unknown: [0.66, 0.66, 0.70],      // grey
};

function read_state() {
    try {
        let [ok, bytes] = GLib.file_get_contents(STATE_FILE);
        if (!ok || !bytes)
            return null;
        return JSON.parse(new TextDecoder().decode(bytes));
    } catch (e) {
        return null;
    }
}

// "YYYY-MM-DD HH:MM:SS" in local time, matching datetime.strptime(...) in
// tray_state().
function parse_ts(s) {
    if (typeof s !== 'string')
        return null;
    let m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(s);
    if (!m)
        return null;
    let t = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime();
    return isNaN(t) ? null : t;
}

function pid_alive(pid) {
    if (!pid)
        return false;
    let dir = `/proc/${pid}`;
    return GLib.file_test(dir, GLib.FileTest.IS_DIR);
}

// Returns [level, reason, n] — a faithful mirror of tray_state().
function classify(st) {
    if (!st || typeof st !== 'object')
        return ['unknown', 'no state (daemon not running?)', 0];

    let ts = parse_ts(st.updated);
    if (ts === null)
        return ['unknown', 'state unreadable', 0];

    let age = (Date.now() - ts) / 1000;
    if (age > MAX_AGE)
        return ['unknown',
                `state stale (${Math.round(age)}s old — daemon down?)`, 0];

    if (!pid_alive(st.pid))
        return ['unknown', 'daemon not running', 0];

    let conns = (st.connections || []).filter(
        c => c && !c.closed && VIEWER_TIERS.has(c.tier));
    if (conns.length) {
        let c = conns[conns.length - 1];
        return ['active', `${c.tier.toLowerCase()} viewer from ${c.peer}`,
                conns.length];
    }

    let socks = st.sockets || [];
    if (socks.length) {
        let s = socks[socks.length - 1];
        return ['active', `live :${s.port} session from ${s.peer}`, socks.length];
    }

    let listeners = st.listeners || [];
    if (listeners.length) {
        let ports = listeners.map(p => `:${p}`).join(', ');
        return ['idle', `listening (${ports}), no viewer`, 0];
    }

    return ['idle', 'monitoring, no remote viewer', 0];
}

const VncWatchIndicator = GObject.registerClass(
class VncWatchIndicator extends PanelMenu.Button {
    _init() {
        super._init(0.0, 'vnc-watch', false);

        this._rgb = COLORS.unknown;
        this._timeoutId = 0;

        this._dot = new St.DrawingArea({
            x_align: Clutter.ActorAlign.CENTER,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._dot.set_size(14, 14);
        this._dot.connect('repaint', () => this._repaint());
        this.add_child(this._dot);

        // Status line (read-only), then the actions — same set the tray menu
        // offered, minus "quit" (there is no tray process to quit here).
        this._statusItem = new PopupMenu.PopupMenuItem('vnc-watch: starting…');
        this._statusItem.setSensitive(false);
        this.menu.addMenuItem(this._statusItem);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this.menu.addAction('Open vnc-watch menu…',
            () => this._spawn(['menu-window']));
        this.menu.addAction('Clear browser + Discord data…',
            () => this._spawn(['clear']));
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addAction('Close VNC server (kick)',
            () => this._spawn(['kick', '--panel']));
        this.menu.addAction('Lock session',
            () => this._spawn(['lock']));

        this._timeoutId = GLib.timeout_add(
            GLib.PRIORITY_DEFAULT, POLL_MS, () => this._poll());
        this._poll();
    }

    _repaint() {
        let cr = this._dot.get_context();
        cr.setOperator(Cairo.Operator.CLEAR);
        cr.paint();
        cr.setOperator(Cairo.Operator.OVER);
        let [r, g, b] = this._rgb;
        cr.setSourceRGBA(r, g, b, 1.0);
        cr.arc(7, 7, 5, 0, 2 * Math.PI);
        cr.fill();
    }

    _poll() {
        let [level, reason] = classify(read_state());
        this._rgb = COLORS[level] || COLORS.unknown;
        this._dot.queue_repaint();
        this._statusItem.label.text = `vnc-watch: ${reason}`;
        return GLib.SOURCE_CONTINUE;
    }

    _spawn(args) {
        // Prefer the installed CLI symlink; fall back to PATH.
        let bin = GLib.build_filenamev(
            [GLib.get_home_dir(), '.local', 'bin', 'vnc-watch']);
        if (!GLib.file_test(bin, GLib.FileTest.IS_EXECUTABLE))
            bin = 'vnc-watch';
        try {
            GLib.spawn_async(null, [bin, ...args], null,
                GLib.SpawnFlags.SEARCH_PATH, null);
        } catch (e) {
            logError(e, 'vnc-watch: failed to spawn CLI');
        }
    }

    destroy() {
        if (this._timeoutId) {
            GLib.source_remove(this._timeoutId);
            this._timeoutId = 0;
        }
        super.destroy();
    }
});

let _indicator = null;

function init() {
    _indicator = null;
}

function enable() {
    _indicator = new VncWatchIndicator();
    Main.panel.addToStatusArea(UUID, _indicator);
}

function disable() {
    if (_indicator) {
        _indicator.destroy();
        _indicator = null;
    }
}
