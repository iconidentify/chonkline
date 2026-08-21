#!/usr/bin/env python3
"""Negative controls: confirm the checks we are avoiding really do refuse."""
import socket, time, sys

def attempt(label, capab_extra, proto="1205", server_fmt=None):
    try:
        s = socket.create_connection(("127.0.0.1", 7001), timeout=8)
    except Exception as e:
        return label, f"connect failed: {e}"
    s.settimeout(5)
    def send(l): s.sendall((l + "\r\n").encode())
    send(f"CAPAB START {proto}")
    send("CAPAB CAPABILITIES :NICKMAX=30 CHANMAX=50 MAXMODES=20 MAXLINE=512")
    for extra in capab_extra:
        send(extra)
    send("CAPAB END")
    if server_fmt is None:
        server_fmt = f"SERVER chonk.test linkpass 0 2CH :Chonkline Test" if proto == "1205" \
                     else f"SERVER chonk.test linkpass 2CH :Chonkline Test"
    send(server_fmt)
    send(f":2CH BURST {int(time.time())}")
    send(":2CH ENDBURST")
    buf, lines = b"", []
    end = time.time() + 5
    while time.time() < end:
        try: c = s.recv(8192)
        except socket.timeout: break
        if not c: break
        buf += c
        while b"\n" in buf:
            ln, _, buf = buf.partition(b"\n")
            ln = ln.decode("utf-8","replace").rstrip("\r")
            if ln: lines.append(ln)
        if any(l.startswith("ERROR") for l in lines): break
        if any("ENDBURST" in l for l in lines): break
    s.close()
    err = next((l for l in lines if l.startswith("ERROR")), None)
    if err: return label, "REFUSED -> " + err[:120]
    if any("ENDBURST" in l for l in lines): return label, "LINKED"
    return label, "INCOMPLETE"

tests = [
    ("baseline: omit all mode capabs", []),
    ("send WRONG chanmodes",
        ["CAPAB CHANMODES :simple:inviteonly=i simple:moderated=m"]),
    ("send WRONG usermodes",
        ["CAPAB USERMODES :simple:invisible=i"]),
    ("send mismatched CASEMAPPING",
        ["CAPAB CAPABILITIES :CASEMAPPING=rfc1459"]),
    ("wrong link password",
        [], "1205", "SERVER chonk.test WRONGPASS 0 2CH :Chonkline Test"),
    ("protocol 1206 (v4 native)", [], "1206"),
    ("protocol 1204 (too old)", [], "1204"),
]
print("=" * 72)
for t in tests:
    label, res = attempt(*t)
    mark = "OK  " if ("LINKED" in res) else "STOP"
    print(f"  {mark} {label:34s} {res}")
    time.sleep(1.2)
print("=" * 72)
