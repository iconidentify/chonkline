#!/usr/bin/env python3
"""Drive an InspIRCd S2S handshake by hand, as chonkline would.

Deliberately sends the MINIMAL CAPAB: no CHANMODES, no USERMODES, no EXTBANS,
no CASEMAPPING key. If the source reading is right, InspIRCd skips every mode
comparison and accepts a peer that advertises no modes at all.
"""
import socket, sys, time

HOST, PORT = "127.0.0.1", 7001
SID, NAME, PASS = "2CH", "chonk.test", "linkpass"
PROTO = sys.argv[1] if len(sys.argv) > 1 else "1205"

sent, recv = [], []

def send(sock, line):
    sent.append(line)
    sock.sendall((line + "\r\n").encode())

s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(6)

send(s, f"CAPAB START {PROTO}")
send(s, "CAPAB CAPABILITIES :NICKMAX=30 CHANMAX=50 MAXMODES=20 IDENTMAX=10 "
        "MAXQUIT=255 MAXTOPIC=307 MAXKICK=255 MAXREAL=128 MAXAWAY=200 MAXHOST=64 MAXLINE=512")
send(s, "CAPAB END")
if PROTO == "1205":
    send(s, f"SERVER {NAME} {PASS} 0 {SID} :Chonkline Test")   # 1205 has the unused field
else:
    send(s, f"SERVER {NAME} {PASS} {SID} :Chonkline Test")     # 1206 dropped it

ts = int(time.time())
send(s, f":{SID} BURST {ts}")
send(s, f":{SID} SINFO version :chonkline-beta {NAME} :")
send(s, f":{SID} UID {SID}AAAAAA {ts} chonkuser 127.0.0.1 127.0.0.1 chonk 127.0.0.1 {ts} + :Chonkline User")
send(s, f":{SID} ENDBURST")

buf = b""
deadline = time.time() + 8
while time.time() < deadline:
    try:
        chunk = s.recv(8192)
    except socket.timeout:
        break
    if not chunk:
        break
    buf += chunk
    while b"\n" in buf:
        line, _, buf = buf.partition(b"\n")
        line = line.decode("utf-8", "replace").rstrip("\r")
        if line:
            recv.append(line)
    # Their ENDBURST means the link is fully established.
    if any(" ENDBURST" in r for r in recv):
        # keep reading briefly for anything after
        deadline = min(deadline, time.time() + 1.0)

s.close()

print("=" * 62)
print("SENT")
print("=" * 62)
for l in sent:
    print("  >", l[:150])
print()
print("=" * 62)
print(f"RECEIVED ({len(recv)} lines)")
print("=" * 62)
for l in recv:
    print("  <", l[:160])

print()
print("=" * 62)
err  = [r for r in recv if r.startswith("ERROR") or " ERROR " in r]
capb = [r for r in recv if r.startswith("CAPAB")]
srv  = [r for r in recv if " SERVER " in r or r.startswith("SERVER")]
burst= [r for r in recv if " BURST" in r]
endb = [r for r in recv if "ENDBURST" in r]
print(f"protocol offered   : {PROTO}")
print(f"CAPAB lines back   : {len(capb)}")
print(f"SERVER back        : {'YES' if srv else 'no'}")
print(f"BURST began        : {'YES' if burst else 'no'}")
print(f"ENDBURST (linked)  : {'YES' if endb else 'no'}")
print(f"ERROR              : {err[0][:120] if err else 'none'}")
print()
print("VERDICT:", "LINK ESTABLISHED" if (endb and not err) else ("REFUSED" if err else "INCOMPLETE"))
