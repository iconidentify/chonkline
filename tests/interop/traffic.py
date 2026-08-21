#!/usr/bin/env python3
"""End-to-end: link as a server, then prove traffic flows both ways with a real
client connected to InspIRCd."""
import socket, time, threading, sys

SID, NAME, PASS = "2CH", "chonk.test", "linkpass"
UID = SID + "AAAAAA"
results = {}

def rd(sock, store, stop):
    buf = b""
    while not stop.is_set():
        try:
            c = sock.recv(8192)
        except Exception:
            break
        if not c: break
        buf += c
        while b"\n" in buf:
            line, _, buf = buf.partition(b"\n")
            line = line.decode("utf-8", "replace").rstrip("\r")
            if line: store.append(line)

# ---- 1. establish the server link ----
srv = socket.create_connection(("127.0.0.1", 7001), timeout=10)
slines, stop = [], threading.Event()
threading.Thread(target=rd, args=(srv, slines, stop), daemon=True).start()
def ssend(l): srv.sendall((l + "\r\n").encode())

ts = int(time.time())
ssend("CAPAB START 1205")
ssend("CAPAB CAPABILITIES :NICKMAX=30 CHANMAX=50 MAXMODES=20 MAXLINE=512")
ssend("CAPAB END")
ssend(f"SERVER {NAME} {PASS} 0 {SID} :Chonkline Test")
ssend(f":{SID} BURST {ts}")
ssend(f":{SID} UID {UID} {ts} chonkuser 127.0.0.1 127.0.0.1 chonk 127.0.0.1 {ts} + :Chonkline User")
ssend(f":{SID} ENDBURST")
time.sleep(2.5)
results["linked"] = any("ENDBURST" in l for l in slines)

# ---- 2. a real client on InspIRCd's client port ----
cli = socket.create_connection(("127.0.0.1", 7000), timeout=10)
clines = []
threading.Thread(target=rd, args=(cli, clines, stop), daemon=True).start()
def csend(l): cli.sendall((l + "\r\n").encode())
csend("NICK localuser")
csend("USER localuser 0 * :Local User")
time.sleep(2.5)
results["client_registered"] = any(" 001 " in l for l in clines)

# ---- 3. does InspIRCd know about OUR user? ----
clines.clear()
csend("WHOIS chonkuser")
time.sleep(2)
whois = [l for l in clines if " 311 " in l or " 312 " in l or " 401 " in l]
results["whois_sees_remote_user"] = any(" 311 " in l for l in whois)
results["whois_server_field"] = next((l for l in clines if " 312 " in l), "")

# ---- 4. client joins a channel -> we should get FJOIN ----
slines.clear()
csend("JOIN #linktest")
time.sleep(2)
results["got_fjoin"] = any(" FJOIN " in l for l in slines)
results["fjoin_line"] = next((l for l in slines if " FJOIN " in l), "")

# ---- 5. our remote user joins and speaks -> client must see both ----
clines.clear()
ssend(f":{SID} FJOIN #linktest {ts} +nt :,{UID}")
time.sleep(1)
ssend(f":{UID} PRIVMSG #linktest :hello from chonkline")
time.sleep(2)
results["client_saw_remote_join"] = any("JOIN" in l and "chonkuser" in l for l in clines)
results["client_saw_remote_msg"] = any("hello from chonkline" in l for l in clines)

# ---- 6. client speaks -> we must receive it ----
slines.clear()
csend("PRIVMSG #linktest :hello from inspircd client")
time.sleep(2)
results["we_saw_client_msg"] = any("hello from inspircd client" in l for l in slines)

# ---- 7. tolerance: does InspIRCd send modes we never advertised? ----
results["modes_we_never_advertised"] = [l for l in slines + clines if " FMODE " in l][:2]

stop.set()
try: srv.close(); cli.close()
except Exception: pass

print("=" * 64)
for k in ["linked", "client_registered", "whois_sees_remote_user",
          "got_fjoin", "client_saw_remote_join", "client_saw_remote_msg",
          "we_saw_client_msg"]:
    v = results.get(k)
    print(f"  {'PASS' if v else 'FAIL'}  {k}")
print("=" * 64)
print("WHOIS 312 :", results.get("whois_server_field","")[:110])
print("FJOIN recv:", results.get("fjoin_line","")[:110])
