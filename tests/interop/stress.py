#!/usr/bin/env python3
"""Load and stress the server, and the link, looking for failure under volume.

Scenarios escalate: local load first, then the same load crossing a real
InspIRCd link, then churn and a split under load. Each reports what it measured
rather than just pass/fail, because the interesting failures here are partial --
messages that mostly arrive, memory that mostly settles.
"""
import argparse, asyncio, os, resource, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CHONK = os.path.join(ROOT, "target", "release", "irc-server")
INSP = "/opt/homebrew/bin/inspircd"
CHONK_PORT, INSP_CLIENT, INSP_LINK = 7100, 7010, 7001


class Conn:
    def __init__(self, nick):
        self.nick = nick
        self.r = self.w = None
        self.seen = []
        self.closed = False
        self.registered = False
        self.joined = False

    async def connect(self, port):
        self.r, self.w = await asyncio.open_connection("127.0.0.1", port)
        await self.send(f"NICK {self.nick}")
        await self.send(f"USER {self.nick} 0 * :{self.nick}")

    async def send(self, line):
        if self.w is None or self.closed:
            return
        try:
            self.w.write((line + "\r\n").encode())
            await self.w.drain()
        except Exception:
            self.closed = True

    async def pump(self, stop, collect=None):
        # Also tracks registration and joins, so a scenario can verify its own
        # preconditions. Measuring delivery without checking that the clients
        # actually registered produces a confident zero and a false bug report.
        while not stop.is_set():
            try:
                line = await asyncio.wait_for(self.r.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            if not line:
                break
            text = line.decode("utf-8", "replace").rstrip()
            if text.startswith("PING "):
                await self.send("PONG " + text.split(" ", 1)[1])
            else:
                if " 001 " in text:
                    self.registered = True
                if " JOIN " in text or text.endswith("JOIN"):
                    self.joined = True
                if collect is not None and collect in text:
                    self.seen.append(text)

    async def close(self):
        self.closed = True
        try:
            self.w.close()
        except Exception:
            pass


def rss_mb(pid):
    try:
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
        return int(out.strip()) / 1024.0
    except Exception:
        return -1.0


async def wait_registered(conns, secs=30):
    """Registration is paced by the server's own fakelag, so allow for it."""
    end = time.time() + secs
    while time.time() < end:
        if all(c.w is not None for c in conns):
            return True
        await asyncio.sleep(0.2)
    return False


async def scenario_local_load(n, msgs, chonk_pid, report):
    """N clients in one channel, each sending `msgs` messages."""
    stop = asyncio.Event()
    conns = [Conn(f"load{i}") for i in range(n)]
    before = rss_mb(chonk_pid)

    connected = 0
    for c in conns:
        try:
            await c.connect(CHONK_PORT)
            connected += 1
        except Exception:
            pass
    pumps = [asyncio.create_task(c.pump(stop, collect="STRESSMSG")) for c in conns if c.w]
    await asyncio.sleep(6)
    report["local_registered"] = sum(1 for c in conns if c.registered)

    for c in conns:
        await c.send("JOIN #load")
    await asyncio.sleep(8)
    report["local_joined"] = sum(1 for c in conns if c.joined)

    t0 = time.time()
    sent = 0
    for round_i in range(msgs):
        for c in conns:
            await c.send(f"PRIVMSG #load :STRESSMSG {round_i}")
            sent += 1
    elapsed = time.time() - t0
    await asyncio.sleep(8)

    received = sum(len(c.seen) for c in conns)
    peak = rss_mb(chonk_pid)
    stop.set()
    await asyncio.gather(*pumps, return_exceptions=True)
    for c in conns:
        await c.close()
    await asyncio.sleep(3)
    after = rss_mb(chonk_pid)

    # Every message reaches every member EXCEPT its sender: IRC does not echo a
    # channel message back to the client that sent it. Counting the sender makes
    # a perfect run look like a 1.7% loss.
    joined = len([c for c in conns if c.joined])
    expected = sent * max(joined - 1, 0)
    report["local_connected"] = connected
    report["local_sent"] = sent
    report["local_delivered"] = received
    report["local_delivery_pct"] = round(100.0 * received / expected, 1) if expected else 0.0
    report["local_send_rate"] = round(sent / elapsed, 1) if elapsed else 0
    report["local_rss_before"] = round(before, 1)
    report["local_rss_peak"] = round(peak, 1)
    report["local_rss_after"] = round(after, 1)
    report["local_alive"] = peak > 0


async def scenario_churn(rounds, per_round, chonk_pid, report):
    """Rapid connect/disconnect, which is what a reconnect storm looks like."""
    before = rss_mb(chonk_pid)
    failures = 0
    for r in range(rounds):
        conns = [Conn(f"churn{r}_{i}") for i in range(per_round)]
        for c in conns:
            try:
                await c.connect(CHONK_PORT)
            except Exception:
                failures += 1
        await asyncio.sleep(0.5)
        for c in conns:
            await c.close()
        await asyncio.sleep(0.3)
    await asyncio.sleep(5)
    after = rss_mb(chonk_pid)
    report["churn_cycles"] = rounds * per_round
    report["churn_connect_failures"] = failures
    report["churn_rss_before"] = round(before, 1)
    report["churn_rss_after"] = round(after, 1)
    # A leak shows as memory that never comes back down after everyone leaves.
    report["churn_rss_growth"] = round(after - before, 1)


async def scenario_link_load(n, msgs, chonk_pid, report):
    """The same load, but crossing a real InspIRCd link."""
    stop = asyncio.Event()
    chonk_side = [Conn(f"cl{i}") for i in range(n)]
    insp_side = [Conn(f"il{i}") for i in range(n)]

    for c in chonk_side:
        try:
            await c.connect(CHONK_PORT)
        except Exception:
            pass
    for c in insp_side:
        try:
            await c.connect(INSP_CLIENT)
        except Exception:
            pass
    pumps = [asyncio.create_task(c.pump(stop, collect="LINKMSG"))
             for c in chonk_side + insp_side if c.w]
    # Registration is not instant on either side: chonkline paces bursts with
    # fakelag, and InspIRCd performs a hostname lookup unless told not to.
    for _ in range(30):
        if all(c.registered for c in chonk_side + insp_side if c.w):
            break
        await asyncio.sleep(1)

    # Verify registration before measuring anything.
    report["link_registered_near"] = sum(1 for c in chonk_side if c.registered)
    report["link_registered_far"] = sum(1 for c in insp_side if c.registered)

    for c in chonk_side + insp_side:
        await c.send("JOIN #linkload")
    await asyncio.sleep(12)
    report["link_joined_near"] = sum(1 for c in chonk_side if c.joined)
    report["link_joined_far"] = sum(1 for c in insp_side if c.joined)

    sent = 0
    for round_i in range(msgs):
        for c in chonk_side:
            await c.send(f"PRIVMSG #linkload :LINKMSG {round_i}")
            sent += 1
    await asyncio.sleep(12)

    # The interesting number: did messages from our side reach the far side?
    far = sum(len(c.seen) for c in insp_side)
    near = sum(len(c.seen) for c in chonk_side)
    # Only count clients that actually got into the channel.
    live_far = len([c for c in insp_side if c.joined])
    expected_far = sent * live_far
    stop.set()
    await asyncio.gather(*pumps, return_exceptions=True)
    for c in chonk_side + insp_side:
        await c.close()

    report["link_sent"] = sent
    report["link_delivered_far"] = far
    report["link_delivered_near"] = near
    report["link_far_pct"] = round(100.0 * far / expected_far, 1) if expected_far else 0.0
    report["link_rss"] = round(rss_mb(chonk_pid), 1)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=100)
    ap.add_argument("--msgs", type=int, default=5)
    ap.add_argument("--link-clients", type=int, default=25)
    ap.add_argument("--churn-rounds", type=int, default=15)
    ap.add_argument("--churn-per", type=int, default=20)
    args = ap.parse_args()

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 8192), hard))

    subprocess.run(["pkill", "-f", "inspircd --config"], capture_output=True)
    subprocess.run(["pkill", "-f", "target/release/irc-server"], capture_output=True)
    await asyncio.sleep(1)

    insp = subprocess.Popen([INSP, "--config", "conf/inspircd.conf", "--nofork", "--nolog"],
                            cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    await asyncio.sleep(6)

    env = dict(os.environ, IRC_PORT=str(CHONK_PORT), IRC_SID="2CH",
               IRC_SERVER_NAME="chonk.test", IRC_LINK_PASSWORD="linkpass",
               IRC_LINK_PEERS=f"127.0.0.1:{INSP_LINK}", IRC_LOG_LEVEL="info",
               IRC_HTTP_PORT="0", IRC_MAX_CLIENTS="2000")
    env.pop("IRC_TLS_PORT", None)
    logf = open(os.path.join(HERE, "stress.log"), "w")
    chonk = subprocess.Popen([CHONK], env=env, stdout=logf, stderr=subprocess.STDOUT)
    await asyncio.sleep(8)

    report = {}
    try:
        await scenario_local_load(args.clients, args.msgs, chonk.pid, report)
        report["alive_after_local"] = chonk.poll() is None
        await scenario_churn(args.churn_rounds, args.churn_per, chonk.pid, report)
        report["alive_after_churn"] = chonk.poll() is None
        await scenario_link_load(args.link_clients, args.msgs, chonk.pid, report)
        report["alive_after_link"] = chonk.poll() is None

        # Split under load: kill the peer while the channel is populated.
        insp.terminate()
        await asyncio.sleep(6)
        report["alive_after_split"] = chonk.poll() is None
        probe = Conn("postsplit")
        try:
            await probe.connect(CHONK_PORT)
            await asyncio.sleep(2)
            report["usable_after_split"] = True
            await probe.close()
        except Exception:
            report["usable_after_split"] = False
        report["final_rss"] = round(rss_mb(chonk.pid), 1)
    finally:
        for p in (chonk, insp):
            try: p.terminate()
            except Exception: pass
        await asyncio.sleep(1)
        for p in (chonk, insp):
            try: p.kill()
            except Exception: pass

    print("=" * 66)
    for k, v in report.items():
        print(f"  {k:26s} {v}")
    print("=" * 66)

    log = open(os.path.join(HERE, "stress.log")).read()
    bad = [l for l in log.splitlines() if "ERROR" in l or "panic" in l.lower()]
    print(f"  server error lines: {len(bad)}")
    for l in bad[:5]:
        print("   ", l[:120])

    ok = (report.get("alive_after_local") and report.get("alive_after_churn")
          and report.get("alive_after_link") and report.get("alive_after_split")
          and report.get("usable_after_split") and not bad)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
