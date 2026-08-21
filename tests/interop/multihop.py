#!/usr/bin/env python3
"""Multi-hop routing: chonkline -- insp1 -- insp2.

Traffic between chonkline and insp2 must traverse insp1, so this exercises the
paths a single-peer test cannot: a server introduced by another server, users
behind an intermediate hop, and a split that takes a whole subtree rather than
one neighbour.
"""
import os, socket, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CHONK = os.path.join(ROOT, "target", "release", "irc-server")
INSP = "/opt/homebrew/bin/inspircd"

I1_CLIENT, I1_LINK = 7010, 7001
I2_CLIENT, I2_LINK = 7020, 7021
CHONK_CLIENT = 7100


def reader(sock, store, stop):
    buf = b""
    while not stop.is_set():
        try:
            c = sock.recv(8192)
        except Exception:
            break
        if not c:
            break
        buf += c
        while b"\n" in buf:
            ln, _, buf = buf.partition(b"\n")
            ln = ln.decode("utf-8", "replace").rstrip("\r")
            if ln:
                store.append(ln)


class Client:
    def __init__(self, port, nick):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.lines, self.stop = [], threading.Event()
        threading.Thread(target=reader, args=(self.s, self.lines, self.stop), daemon=True).start()
        self.send(f"NICK {nick}")
        self.send(f"USER {nick} 0 * :{nick}")

    def send(self, l):
        # Pace under the server's burst window; an unpaced test throttles itself
        # and the symptom looks like a routing failure.
        time.sleep(0.4)
        try:
            self.s.sendall((l + "\r\n").encode())
        except Exception:
            pass

    def wait(self, needle, secs=8):
        end = time.time() + secs
        while time.time() < end:
            if any(needle in l for l in self.lines):
                return True
            time.sleep(0.15)
        return False

    def clear(self):
        self.lines.clear()

    def close(self):
        self.stop.set()
        try:
            self.s.close()
        except Exception:
            pass


procs, R = [], {}


def cleanup():
    for p in procs:
        try: p.terminate()
        except Exception: pass
    time.sleep(0.6)
    for p in procs:
        try: p.kill()
        except Exception: pass


try:
    subprocess.run(["pkill", "-f", "inspircd --config"], capture_output=True)
    subprocess.run(["pkill", "-f", "target/release/irc-server"], capture_output=True)
    time.sleep(1)

    i2 = subprocess.Popen([INSP, "--config", "conf2/inspircd.conf", "--nofork", "--nolog"],
                          cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(i2)
    time.sleep(4)
    i1 = subprocess.Popen([INSP, "--config", "conf/inspircd.conf", "--nofork", "--nolog"],
                          cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(i1)
    # Wait for insp1 -> insp2 to actually link before starting chonkline. The
    # autoconnect is periodic, so this polls rather than guessing a duration --
    # an unformed topology makes every later check fail for the wrong reason.
    linked = False
    for _ in range(30):
        time.sleep(2)
        try:
            probe = socket.create_connection(("127.0.0.1", I1_CLIENT), timeout=5)
            probe.sendall(b"NICK tp\r\nUSER tp 0 * :tp\r\n")
            time.sleep(1.5)
            probe.sendall(b"LINKS\r\n")
            time.sleep(1.5)
            data = probe.recv(65536).decode("utf-8", "replace")
            probe.close()
            if "insp2.test" in data:
                linked = True
                break
        except Exception:
            pass
    R["insp_topology_formed"] = linked

    env = dict(os.environ, IRC_PORT=str(CHONK_CLIENT), IRC_SID="2CH",
               IRC_SERVER_NAME="chonk.test", IRC_LINK_PASSWORD="linkpass",
               IRC_LINK_PEERS=f"127.0.0.1:{I1_LINK}", IRC_LOG_LEVEL="info",
               IRC_HTTP_PORT="0")
    env.pop("IRC_TLS_PORT", None)
    logf = open(os.path.join(HERE, "multihop.log"), "w")
    chonk = subprocess.Popen([CHONK], env=env, stdout=logf, stderr=subprocess.STDOUT)
    procs.append(chonk)
    time.sleep(9)

    log = open(os.path.join(HERE, "multihop.log")).read()
    R["chonk_linked"] = "link.registered" in log

    # A user on each of the three servers.
    c_chonk = Client(CHONK_CLIENT, "chk")
    c_i1 = Client(I1_CLIENT, "one")
    c_i2 = Client(I2_CLIENT, "two")
    R["all_registered"] = all(c.wait(" 001 ") for c in (c_chonk, c_i1, c_i2))
    time.sleep(3)

    # chonkline must know about insp2, which it never linked to directly.
    c_chonk.clear()
    c_chonk.send("WHOIS two")
    R["sees_user_two_hops_away"] = c_chonk.wait(" 311 ", 8)
    R["attributes_to_far_server"] = c_chonk.wait("insp2.test", 4)

    # Shared channel across all three.
    for c in (c_i2, c_i1, c_chonk):
        c.send("JOIN #hop")
    time.sleep(5)

    # chonkline -> insp2, traversing insp1.
    c_i2.clear()
    c_chonk.send("PRIVMSG #hop :FROM-CHONK")
    R["chonk_to_two_hops"] = c_i2.wait("FROM-CHONK", 8)

    # insp2 -> chonkline, the other way through insp1.
    c_chonk.clear()
    c_i2.send("PRIVMSG #hop :FROM-TWO")
    R["two_hops_to_chonk"] = c_chonk.wait("FROM-TWO", 8)

    # Private message across two hops.
    c_i2.clear()
    c_chonk.send("PRIVMSG two :PRIV-ACROSS")
    R["priv_across_two_hops"] = c_i2.wait("PRIV-ACROSS", 8)

    # NAMES on chonkline should list users from both remote servers.
    c_chonk.clear()
    c_chonk.send("NAMES #hop")
    R["names_lists_both_servers"] = c_chonk.wait("one", 6) and c_chonk.wait("two", 3)

    # Killing insp2 must remove ONLY its users, leaving insp1's intact.
    c_chonk.clear()
    i2.terminate()
    time.sleep(8)
    R["far_split_seen"] = c_chonk.wait("two", 8)          # a QUIT naming that user
    c_chonk.clear()
    c_chonk.send("WHOIS two")
    R["far_user_gone"] = c_chonk.wait(" 401 ", 6)
    c_chonk.clear()
    c_chonk.send("WHOIS one")
    R["near_user_survives"] = c_chonk.wait(" 311 ", 6)

    # And the near link still passes traffic.
    c_i1.clear()
    c_chonk.send("PRIVMSG #hop :AFTER-FAR-SPLIT")
    R["usable_after_far_split"] = c_i1.wait("AFTER-FAR-SPLIT", 8)

    for c in (c_chonk, c_i1, c_i2):
        c.close()
    R["chonk_alive"] = chonk.poll() is None
finally:
    cleanup()

print("=" * 62)
order = ["insp_topology_formed", "chonk_linked", "all_registered", "sees_user_two_hops_away",
         "attributes_to_far_server", "chonk_to_two_hops", "two_hops_to_chonk",
         "priv_across_two_hops", "names_lists_both_servers", "far_split_seen",
         "far_user_gone", "near_user_survives", "usable_after_far_split",
         "chonk_alive"]
for k in order:
    print(f"  {'PASS' if R.get(k) else 'FAIL'}  {k}")
print("=" * 62)
sys.exit(0 if all(R.get(k) for k in order) else 1)
