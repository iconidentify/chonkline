#!/usr/bin/env python3
"""Battle test: link a real chonkline to a real InspIRCd and pass traffic.

Starts both daemons, waits for the link, then puts a client on each side and
checks that they can see and talk to each other across the link.
"""
import os, socket, subprocess, sys, threading, time, signal

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CHONK = os.path.join(ROOT, "target", "release", "irc-server")

INSP_CLIENT, INSP_LINK = 7000, 7001
CHONK_CLIENT = 7100

def reader(sock, store, stop):
    buf = b""
    while not stop.is_set():
        try:
            c = sock.recv(8192)
        except Exception:
            break
        if not c: break
        buf += c
        while b"\n" in buf:
            ln, _, buf = buf.partition(b"\n")
            ln = ln.decode("utf-8", "replace").rstrip("\r")
            if ln: store.append(ln)

class Client:
    def __init__(self, port, nick):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.lines = []
        self.stop = threading.Event()
        threading.Thread(target=reader, args=(self.s, self.lines, self.stop), daemon=True).start()
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick}")
    def send(self, l): self.s.sendall((l + "\r\n").encode())
    def wait(self, needle, secs=6):
        end = time.time() + secs
        while time.time() < end:
            if any(needle in l for l in self.lines): return True
            time.sleep(0.15)
        return False
    def close(self):
        self.stop.set()
        try: self.s.close()
        except Exception: pass

procs = []
def cleanup():
    for p in procs:
        try: p.terminate()
        except Exception: pass
    time.sleep(0.5)
    for p in procs:
        try: p.kill()
        except Exception: pass

results = {}
try:
    subprocess.run(["pkill", "-f", "inspircd --config"], capture_output=True)
    subprocess.run(["pkill", "-f", "target/release/irc-server"], capture_output=True)
    time.sleep(1)

    insp = subprocess.Popen(
        ["/opt/homebrew/bin/inspircd", "--config", "conf/inspircd.conf", "--nofork", "--nolog"],
        cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(insp)
    time.sleep(6)

    env = dict(os.environ,
        IRC_PORT=str(CHONK_CLIENT),
        IRC_SID="2CH",
        IRC_SERVER_NAME="chonk.test",
        IRC_LINK_PASSWORD="linkpass",
        IRC_LINK_PEERS=f"127.0.0.1:{INSP_LINK}",
        IRC_LOG_LEVEL="info",
        IRC_HTTP_PORT="0",
    )
    env.pop("IRC_TLS_PORT", None)
    chonk_log = open(os.path.join(HERE, "chonkline.log"), "w")
    chonk = subprocess.Popen([CHONK], env=env, stdout=chonk_log, stderr=subprocess.STDOUT)
    procs.append(chonk)
    time.sleep(8)

    log = open(os.path.join(HERE, "chonkline.log")).read()
    results["chonkline_started"] = "listening" in log
    results["link_registered"] = "link.registered" in log

    # a client on each side
    ci = Client(INSP_CLIENT, "inspuser")
    cc = Client(CHONK_CLIENT, "chonkuser")
    results["insp_client_ok"] = ci.wait(" 001 ")
    results["chonk_client_ok"] = cc.wait(" 001 ")

    # chonkline's user should be visible to InspIRCd
    time.sleep(2)
    ci.lines.clear()
    ci.send("WHOIS chonkuser")
    results["insp_sees_chonk_user"] = ci.wait(" 311 ", 6)

    # shared channel, both join
    ci.send("JOIN #bridge"); time.sleep(1.5)
    cc.send("JOIN #bridge"); time.sleep(2.5)

    ci.lines.clear(); cc.lines.clear()
    cc.send("PRIVMSG #bridge :hello from chonkline")
    results["insp_client_got_chonk_msg"] = ci.wait("hello from chonkline", 6)

    ci.lines.clear(); cc.lines.clear()
    ci.send("PRIVMSG #bridge :hello from inspircd")
    results["chonk_client_got_insp_msg"] = cc.wait("hello from inspircd", 6)

    ci.close(); cc.close()
finally:
    cleanup()

print("=" * 60)
order = ["chonkline_started","link_registered","insp_client_ok","chonk_client_ok",
         "insp_sees_chonk_user","insp_client_got_chonk_msg","chonk_client_got_insp_msg"]
for k in order:
    v = results.get(k)
    print(f"  {'PASS' if v else 'FAIL'}  {k}")
print("=" * 60)
sys.exit(0 if all(results.get(k) for k in order) else 1)
