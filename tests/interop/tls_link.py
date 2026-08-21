#!/usr/bin/env python3
"""Server links over TLS, authenticated by pinned certificate fingerprint.

Links carry every user's traffic and the link password, so plaintext is not a
serious option between servers on anything but a loopback test. Certificates on
a server link are routinely self-signed, so the trust model is a pinned
fingerprint rather than a CA chain -- this checks both that a correct pin links
and that a wrong one is refused.
"""
import os, socket, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CHONK = os.path.join(ROOT, "target", "release", "irc-server")

A_CLIENT, A_LINK = 7200, 7201   # hub: listens for links, holds the certificate
B_CLIENT = 7300                 # leaf: dials out over TLS

CERT = os.path.join(HERE, "linkcert.crt")
KEY = os.path.join(HERE, "linkcert.key")

procs, R = [], {}


def cleanup():
    for p in procs:
        try: p.terminate()
        except Exception: pass
    time.sleep(0.5)
    for p in procs:
        try: p.kill()
        except Exception: pass


def gen_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return True
    out = subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", KEY, "-out", CERT, "-days", "2", "-nodes",
        "-subj", "/CN=link.test",
        "-addext", "basicConstraints=critical,CA:FALSE",
    ], capture_output=True)
    return out.returncode == 0


def fingerprint():
    out = subprocess.check_output(
        ["openssl", "x509", "-in", CERT, "-noout", "-fingerprint", "-sha256"], text=True)
    return out.strip().split("=", 1)[1].replace(":", "").lower()


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
        time.sleep(0.4)
        try: self.s.sendall((l + "\r\n").encode())
        except Exception: pass
    def wait(self, needle, secs=8):
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


def start_hub():
    env = dict(os.environ, IRC_PORT=str(A_CLIENT), IRC_SID="4CH",
               IRC_SERVER_NAME="hub.test", IRC_LINK_PASSWORD="tlspass",
               IRC_LINK_PORT=str(A_LINK), IRC_LINK_TLS="1",
               IRC_TLS_PORT="0", IRC_TLS_CERT=CERT, IRC_TLS_KEY=KEY,
               IRC_HTTP_PORT="0", IRC_LOG_LEVEL="info")
    # IRC_TLS_PORT=0 keeps the client TLS listener off; the cert is here for the
    # link listener, which reads the same paths.
    env["IRC_TLS_PORT"] = "7202"
    log = open(os.path.join(HERE, "tls_hub.log"), "w")
    p = subprocess.Popen([CHONK], env=env, stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def start_leaf(peer_spec):
    env = dict(os.environ, IRC_PORT=str(B_CLIENT), IRC_SID="5CH",
               IRC_SERVER_NAME="leaf.test", IRC_LINK_PASSWORD="tlspass",
               IRC_LINK_PEERS=peer_spec, IRC_LINK_TLS="1",
               IRC_HTTP_PORT="0", IRC_LOG_LEVEL="info")
    env.pop("IRC_TLS_PORT", None)
    log = open(os.path.join(HERE, "tls_leaf.log"), "w")
    p = subprocess.Popen([CHONK], env=env, stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    return p


try:
    subprocess.run(["pkill", "-f", "target/release/irc-server"], capture_output=True)
    time.sleep(1)
    R["cert_generated"] = gen_cert()
    fp = fingerprint()
    R["fingerprint_read"] = len(fp) == 64

    # --- correct pin: the link must come up and pass traffic ---
    start_hub(); time.sleep(6)
    start_leaf(f"127.0.0.1:{A_LINK}:{fp}"); time.sleep(9)

    leaf_log = open(os.path.join(HERE, "tls_leaf.log")).read()
    hub_log = open(os.path.join(HERE, "tls_hub.log")).read()
    R["tls_link_established"] = "link.registered" in leaf_log
    R["hub_saw_link"] = "link.registered" in hub_log
    R["hub_advertises_fingerprint"] = "link.fingerprint" in hub_log

    ca = Client(A_CLIENT, "hubuser")
    cb = Client(B_CLIENT, "leafuser")
    R["clients_registered"] = ca.wait(" 001 ") and cb.wait(" 001 ")
    time.sleep(2)

    ca.send("JOIN #tls"); cb.send("JOIN #tls"); time.sleep(4)
    ca.clear()
    cb.send("PRIVMSG #tls :OVER-TLS")
    R["traffic_over_tls"] = ca.wait("OVER-TLS", 8)

    cb.clear()
    ca.send("PRIVMSG #tls :BACK-OVER-TLS")
    R["traffic_back_over_tls"] = cb.wait("BACK-OVER-TLS", 8)

    ca.close(); cb.close()
    cleanup(); procs.clear(); time.sleep(2)

    # --- wrong pin: the link must be refused ---
    start_hub(); time.sleep(6)
    bad = "ab" * 32
    start_leaf(f"127.0.0.1:{A_LINK}:{bad}"); time.sleep(9)
    leaf_log = open(os.path.join(HERE, "tls_leaf.log")).read()
    R["wrong_pin_refused"] = "link.registered" not in leaf_log
    R["wrong_pin_reported"] = "tls_failed" in leaf_log or "fingerprint" in leaf_log.lower()
finally:
    cleanup()

print("=" * 62)
order = ["cert_generated", "fingerprint_read", "tls_link_established", "hub_saw_link",
         "hub_advertises_fingerprint", "clients_registered", "traffic_over_tls",
         "traffic_back_over_tls", "wrong_pin_refused", "wrong_pin_reported"]
for k in order:
    print(f"  {'PASS' if R.get(k) else 'FAIL'}  {k}")
print("=" * 62)
sys.exit(0 if all(R.get(k) for k in order) else 1)
