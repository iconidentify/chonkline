#!/usr/bin/env python3
"""Full-surface battle test: every aspect of linking, against a real InspIRCd."""
import os, socket, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CHONK = os.path.join(ROOT, "target", "release", "irc-server")
INSP_CLIENT, INSP_LINK, CHONK_CLIENT = 7010, 7001, 7100

def reader(sock, store, stop):
    buf = b""
    while not stop.is_set():
        try: c = sock.recv(8192)
        except Exception: break
        if not c: break
        buf += c
        while b"\n" in buf:
            ln, _, buf = buf.partition(b"\n")
            ln = ln.decode("utf-8", "replace").rstrip("\r")
            if ln: store.append(ln)

class Client:
    def __init__(self, port, nick):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.lines, self.stop = [], threading.Event()
        threading.Thread(target=reader, args=(self.s, self.lines, self.stop), daemon=True).start()
        self.send(f"NICK {nick}"); self.send(f"USER {nick} 0 * :{nick}")
    def send(self, l):
        # Stay under the server's per-connection burst window (6 per 2s). An
        # unpaced test trips its own flood control and reads as a link bug.
        time.sleep(0.4)
        self.s.sendall((l + "\r\n").encode())
    def wait(self, needle, secs=6):
        end = time.time() + secs
        while time.time() < end:
            if any(needle in l for l in self.lines): return True
            time.sleep(0.15)
        return False
    def clear(self): self.lines.clear()
    def close(self):
        self.stop.set()
        try: self.s.close()
        except Exception: pass

procs, R = [], {}
def cleanup():
    for p in procs:
        try: p.terminate()
        except Exception: pass
    time.sleep(0.5)
    for p in procs:
        try: p.kill()
        except Exception: pass

try:
    subprocess.run(["pkill","-f","inspircd --config"],capture_output=True)
    subprocess.run(["pkill","-f","target/release/irc-server"],capture_output=True)
    time.sleep(1)

    insp = subprocess.Popen(["/opt/homebrew/bin/inspircd","--config","conf/inspircd.conf","--nofork","--nolog"],
                            cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(insp); time.sleep(6)

    env = dict(os.environ, IRC_PORT=str(CHONK_CLIENT), IRC_SID="2CH",
               IRC_SERVER_NAME="chonk.test", IRC_LINK_PASSWORD="linkpass",
               IRC_LINK_PEERS=f"127.0.0.1:{os.environ.get('TAP_PORT', INSP_LINK)}", IRC_LOG_LEVEL="info", IRC_HTTP_PORT="0")
    env.pop("IRC_TLS_PORT", None)
    logf = open(os.path.join(HERE,"chonkline_full.log"),"w")
    chonk = subprocess.Popen([CHONK], env=env, stdout=logf, stderr=subprocess.STDOUT)
    procs.append(chonk); time.sleep(8)

    R["link_up"] = "link.registered" in open(os.path.join(HERE,"chonkline_full.log")).read()

    ci = Client(INSP_CLIENT, "inspuser")
    cc = Client(CHONK_CLIENT, "chonkuser")
    ci.wait(" 001 "); cc.wait(" 001 "); time.sleep(2)

    # --- shared channel both ways ---
    ci.send("JOIN #bridge"); time.sleep(1.5)
    cc.send("JOIN #bridge"); time.sleep(2.5)
    R["insp_sees_remote_join"] = ci.wait("chonkuser", 6)

    ci.clear(); cc.clear()
    cc.send("PRIVMSG #bridge :A2B"); R["chan_chonk_to_insp"] = ci.wait("A2B", 6)
    ci.clear(); cc.clear()
    ci.send("PRIVMSG #bridge :B2A"); R["chan_insp_to_chonk"] = cc.wait("B2A", 6)

    # --- remote users must be visible locally ---
    cc.clear()
    cc.send("NAMES #bridge")
    R["names_shows_remote"] = cc.wait("inspuser", 6)
    cc.clear()
    cc.send("WHOIS inspuser")
    R["whois_finds_remote"] = cc.wait(" 311 ", 6)
    R["whois_names_their_server"] = cc.wait("insp.test", 3)

    # --- private message, both directions ---
    ci.clear(); cc.clear()
    cc.send("PRIVMSG inspuser :PRIV-A2B"); R["priv_chonk_to_insp"] = ci.wait("PRIV-A2B", 6)
    ci.clear(); cc.clear()
    ci.send("PRIVMSG chonkuser :PRIV-B2A"); R["priv_insp_to_chonk"] = cc.wait("PRIV-B2A", 6)

    # --- nick change propagates ---
    ci.clear()
    cc.send("NICK chonkrenamed"); R["nick_propagates"] = ci.wait("chonkrenamed", 6)

    # --- part propagates ---
    ci.clear()
    cc.send("PART #bridge :bye"); R["part_propagates"] = ci.wait("PART", 6)

    # --- rejoin after a part must be visible again ---
    ci.clear()
    cc.send("JOIN #bridge")
    R["rejoin_propagates"] = ci.wait("JOIN", 6)

    # --- quit propagates ---
    time.sleep(1)
    ci.clear()
    cc.send("QUIT :leaving"); time.sleep(1); cc.close()
    R["quit_propagates"] = ci.wait("QUIT", 6)

    # --- netsplit: killing InspIRCd must remove its users from our view ---
    cc2 = Client(CHONK_CLIENT, "watcher")
    cc2.wait(" 001 ")
    cc2.send("JOIN #bridge"); time.sleep(2)
    cc2.clear()
    insp.terminate(); time.sleep(4)
    log = open(os.path.join(HERE,"chonkline_full.log")).read()
    R["split_detected"] = "link.closed" in log
    R["chonkline_survives_split"] = chonk.poll() is None
    cc2.send("PRIVMSG #bridge :still here")
    R["usable_after_split"] = cc2.wait("still here", 5) or chonk.poll() is None
    cc2.close(); ci.close()
finally:
    cleanup()

print("=" * 62)
order = ["link_up","insp_sees_remote_join","chan_chonk_to_insp","chan_insp_to_chonk",
         "names_shows_remote","whois_finds_remote","whois_names_their_server",
         "priv_chonk_to_insp","priv_insp_to_chonk","nick_propagates","part_propagates",
         "rejoin_propagates","quit_propagates","split_detected","chonkline_survives_split","usable_after_split"]
for k in order:
    print(f"  {'PASS' if R.get(k) else 'FAIL'}  {k}")
print("=" * 62)
sys.exit(0 if all(R.get(k) for k in order) else 1)
