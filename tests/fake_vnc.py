#!/usr/bin/env python3
# language: Python 3.8+, stdlib only, target: Linux
# fake_vnc.py - a mock RFB/VNC endpoint for exercising vnc-watch.
#
# It speaks enough of the RFB 003.008 handshake to look like a real VNC
# server to protocol-aware tooling, and holds the TCP session open so the
# socket layer of vnc-watch sees an established connection on a watched port.
#
#   server: python3 fake_vnc.py --port 5900 --hold 10
#   client: python3 fake_vnc.py --client --port 5900 --hold 8
#
# Run both (client in another shell) to produce a full, held RFB session.
#
# Scope: for testing vnc-watch on your own machine. It is not a VNC server:
# it ignores FramebufferUpdateRequest and never paints pixels.

import argparse
import socket
import struct
import sys
import time

VER_38 = b"RFB 003.008\n"
SEC_NONE = 1
NAMELEN = len(b"vnc-watch-test")


def recv_exact(sock, n):
    """Read exactly n bytes or raise (guards against short reads)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def log(tag, msg):
    print(f"{tag:<6} {msg}", file=sys.stderr, flush=True)


def serve(conn, addr, protocol):
    """Server-half of the RFB handshake, then hold."""
    log("SRV", f"accepted {addr[0]}:{addr[1]}")
    conn.sendall(protocol)
    log("SRV", f"-> server version {protocol.decode().strip()}")
    cver = recv_exact(conn, 12)
    log("SRV", f"<- client version {cver.decode(errors='replace').strip()}")

    # Security handshake: offer exactly one type (None = 1).
    conn.sendall(bytes([1, SEC_NONE]))
    log("SRV", "-> security types: [1 None]")
    chosen = recv_exact(conn, 1)
    log("SRV", f"<- client chose security type {chosen[0]}")

    if cver >= VER_38:
        conn.sendall(struct.pack(">I", 0))
        log("SRV", "-> SecurityResult OK")

    shared = recv_exact(conn, 1)
    log("SRV", f"<- ClientInit shared={shared[0]}")

    # ServerInit: size, 32bpp true-colour pixel format, desktop name.
    pf = struct.pack(">BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    name = b"vnc-watch-test"
    init = (struct.pack(">HH", 1280, 800) + pf
            + struct.pack(">I", NAMELEN) + name)
    conn.sendall(init)
    log("SRV", "-> ServerInit 1280x800x32 'vnc-watch-test'")
    log("SRV", "handshake complete (rfbbuffer full)")


def client(host, port, hold, protocol):
    """Client-half: connect, handshake, hold so the peer sees the session."""
    s = socket.create_connection((host, port), timeout=5)
    log("CLI", f"connected to {host}:{port}")
    sver = recv_exact(s, 12)
    log("CLI", f"<- server version {sver.decode(errors='replace').strip()}")
    s.sendall(protocol)
    log("CLI", f"-> client version {protocol.decode().strip()}")
    ntypes = recv_exact(s, 1)[0]
    types = recv_exact(s, ntypes) if ntypes else b""
    log("CLI", f"<- security types {list(types)}")
    if SEC_NONE not in types:
        log("CLI", "no None security offered; aborting")
        return
    s.sendall(bytes([SEC_NONE]))
    if sver >= VER_38:
        res = struct.unpack(">I", recv_exact(s, 4))[0]
        log("CLI", f"<- SecurityResult {res} ({'OK' if res == 0 else 'FAIL'})")
    s.sendall(b"\x01")                     # ClientInit: shared
    hdr = recv_exact(s, 24)
    w, h = struct.unpack(">HH", hdr[:4])
    nl = struct.unpack(">I", hdr[20:24])[0]
    dname = recv_exact(s, nl) if nl else b""
    log("CLI", f"<- ServerInit {w}x{h} name={dname.decode(errors='replace')}")
    log("CLI", f"handshake complete; holding {hold}s")
    deadline = time.monotonic() + hold
    s.settimeout(1.0)
    while time.monotonic() < deadline:
        try:
            if s.recv(4096) == b"":
                break
        except socket.timeout:
            pass
    s.close()
    log("CLI", "closed")


def main():
    ap = argparse.ArgumentParser(prog="fake_vnc")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5900)
    ap.add_argument("--hold", type=float, default=10.0,
                    help="seconds to keep the accepted session open")
    ap.add_argument("--protocol", default="RFB 003.008\n",
                    help="version banner to offer")
    ap.add_argument("--client", action="store_true",
                    help="act as the viewer instead of the server")
    ap.add_argument("--on-accept", default="",
                    help="shell command to run when a peer attaches")
    args = ap.parse_args()
    protocol = args.protocol.encode()

    if args.client:
        client(args.host, args.port, args.hold, protocol)
        return 0

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(8)
    log("SRV", f"listening on {args.host}:{args.port}")
    try:
        conn, addr = srv.accept()
    except KeyboardInterrupt:
        return 0
    if args.on_accept:
        import subprocess
        subprocess.Popen(args.on_accept, shell=True)
    conn.settimeout(1.0)
    deadline = time.monotonic() + args.hold
    try:
        serve(conn, addr, protocol)
        while time.monotonic() < deadline:
            try:
                if conn.recv(4096) == b"":
                    break
            except socket.timeout:
                pass
    except (ConnectionError, OSError) as exc:
        log("SRV", f"peer gone: {exc}")
    finally:
        conn.close()
        srv.close()
        log("SRV", "closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
