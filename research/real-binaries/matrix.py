#!/usr/bin/env python3
"""#130 PR B: the three real binaries as separate processes on loopback, old against new.

    ingress --submitblock RPC--> ingress --UDP--> relay-node --UDP--> relay-sidecar --> Zebra

Everything between the first RPC and the last one is the shipped code of whichever build a
cell names, with real keys, real sessions and real Equihash, on the one real mainnet block
the repository has. The only stand-in is Zebra, and it says what a test tells it to, so
nothing here says anything about a real node, a real network, loss, or load.

"Old" is whatever directory --old names. A build is only as old as its source: this says
nothing of what a fleet runs. Each cell starts every process it needs and gets one block,
because a record of that one block would otherwise stop the next cell.

    python3 -I matrix.py --old DIR --new DIR --block FILE [--only WORD] [--out FILE]

--block is crates/zcash-pool-common/testdata/mainnet_block_3470793.txt. No private endpoint
or key is used: the key is a constant for loopback, and every address is 127.0.0.1.
"""

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

KEY = "42" * 32
HEIGHT = 3470793
# Time for a block to come through a cell it can come through. A cell that shows nothing
# arrived rests on this, so it is long against the second or so a block takes here.
ARRIVAL_SECS = 8.0
# Time for a second copy to show up after the first.
SETTLE_SECS = 1.5
HEADER_BYTES = 1487


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as held:
        held.bind(("127.0.0.1", 0))
        return held.getsockname()[1]


def display_hash(raw):
    first = hashlib.sha256(raw[:HEADER_BYTES]).digest()
    return hashlib.sha256(first).digest()[::-1].hex()


class Zebra:
    """Answers as told, and writes down what it was asked."""

    def __init__(self, block, refuse_first=0, fail_first=0):
        self.block = block
        self.hash = display_hash(block)
        self.parent = block[4:36][::-1].hex()
        self.refuse_first = refuse_first
        self.fail_first = fail_first
        self.calls = []
        self.took = False
        zebra = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", 0))
                request = json.loads(self.rfile.read(length))
                body = json.dumps(zebra.answer(request)).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, request):
        method, params = request.get("method"), request.get("params", [])
        reply = {"jsonrpc": "2.0", "id": request.get("id")}
        if method == "submitblock":
            self.calls.append(params[0])
            if self.fail_first > 0:
                self.fail_first -= 1
                return {**reply, "error": {"code": -32000, "message": "not ready"}}
            if self.refuse_first > 0:
                self.refuse_first -= 1
                return {**reply, "result": "rejected"}
            self.took = True
            return {**reply, "result": None}
        if method == "getblockchaininfo":
            tip = {"blocks": HEIGHT - 1, "headers": HEIGHT - 1, "bestblockhash": self.parent}
            return {**reply, "result": tip}
        if method == "getblockheader":
            if params[0] == self.hash and not self.took:
                return {**reply, "error": {"code": -5, "message": "not found"}}
            header = {"hash": params[0], "height": HEIGHT - 1, "confirmations": 1}
            return {**reply, "result": header}
        if method == "getrawmempool":
            return {**reply, "result": []}
        return {**reply, "error": {"code": -32601, "message": "not here"}}

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class SilentPeer(socketserver.ThreadingTCPServer):
    """Somewhere for the ingress to connect, so it has a peer and stays up. Says nothing."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                while self.request.recv(4096):
                    pass

        super().__init__(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def addr(self):
        return f"127.0.0.1:{self.server_address[1]}"


class Process:
    def __init__(self, name, argv, env, work):
        self.name = name
        self.path = pathlib.Path(work) / f"{name}-{time.monotonic_ns()}.log"
        self.out = open(self.path, "wb")
        log_level = os.environ.get("MATRIX_RUST_LOG", "info")
        full_env = {"PATH": os.environ["PATH"], "RUST_LOG": log_level, "NO_COLOR": "1", **env}
        self.process = subprocess.Popen(
            argv, env=full_env, stdout=self.out, stderr=subprocess.STDOUT, cwd=work
        )

    def text(self):
        return self.path.read_text(errors="replace")

    def alive(self):
        return self.process.poll() is None

    def stop(self):
        if self.alive():
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.out.close()


class Build:
    """One side of a cell: a directory of binaries, and how it is switched."""

    def __init__(self, directory, name, bound=False):
        self.directory = pathlib.Path(directory)
        self.name = name
        self.bound = bound

    def path(self, binary):
        return str(self.directory / binary)

    def __str__(self):
        return f"{self.name}+bound" if self.bound else self.name

    def __eq__(self, other):
        return str(self) == str(other)


class Fleet:
    def __init__(self, work):
        self.work = work
        self.relay_port = free_port(socket.SOCK_DGRAM)
        self.relay = None
        self.peer = SilentPeer()

    def wait_for(self, what, done, secs):
        end = time.monotonic() + secs
        while time.monotonic() < end:
            if done():
                return True
            time.sleep(0.02)
        raise TimeoutError(what)

    def start_relay(self, build):
        env = {
            "SOVRIGHT_RELAY_LISTEN_ADDR": f"127.0.0.1:{self.relay_port}",
            "SOVRIGHT_RELAY_AUTH_KEY_HEX": KEY,
        }
        if build.bound:
            env["SOVRIGHT_RELAY_BOUND_RAW"] = "1"
        self.relay = Process("relay", [build.path("relay-node")], env, self.work)
        self.wait_for(
            "the relay", lambda: "Sovright relay listening" in self.relay.text(), 10
        )

    def stop_relay(self):
        if self.relay:
            self.relay.stop()
            self.relay = None

    def peers_seen(self):
        return len(re.findall(r"Authenticated new (?:keepalive session|peer)", self.relay.text()))

    def start_sidecar(self, build, zebra, wait=True):
        config = pathlib.Path(self.work) / f"sidecar-{time.monotonic_ns()}.toml"
        config.write_text(
            f"""
zebra_url = "{zebra.url}"
relay_peers = ["127.0.0.1:{self.relay_port}"]
auth_key = "{KEY}"
bind_addr = "127.0.0.1:0"
receive_relay_blocks = true
enable_submitblock = true
announce_templates = false

[submit_gate]
enabled = true
"""
        )
        env = {"SOVRIGHT_RELAY_BOUND_RAW": "1"} if build.bound else {}
        before = self.peers_seen()
        sidecar = Process(
            "sidecar", [build.path("relay-sidecar"), "--config", str(config)], env, self.work
        )
        if wait:
            started = time.monotonic()
            # Its first keepalive makes the session, and if that one is lost the next is 60s
            # away. It has happened here, so it is written down and not put down to chance.
            self.wait_for("the sidecar's session", lambda: self.peers_seen() > before, 75)
            waited = time.monotonic() - started
            if waited > 10:
                print(f"slow session: {waited:.0f}s", flush=True)
        return sidecar

    def start_ingress(self, build, wire, zebra, window_secs=30):
        port = free_port(socket.SOCK_STREAM)
        env = {
            "SOVRIGHT_P2P_NETWORK": "mainnet",
            "SOVRIGHT_P2P_DNS_SEEDS": "",
            "SOVRIGHT_P2P_PEERS": self.peer.addr,
            "SOVRIGHT_P2P_ACCEPT_NONSTANDARD_PORTS": "true",
            "SOVRIGHT_P2P_PEER_RUNTIME_SECS": "3600",
            "SOVRIGHT_P2P_CONNECT_TIMEOUT_SECS": "60",
            "SOVRIGHT_P2P_CRAWLER_ENABLED": "true",
            "SOVRIGHT_P2P_RELAY_PEERS": f"127.0.0.1:{self.relay_port}",
            "SOVRIGHT_P2P_RELAY_BIND_ADDR": "127.0.0.1:0",
            "SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX": KEY,
            "SOVRIGHT_P2P_RELAY_FORWARD_DEDUP_WINDOW_SECS": str(window_secs),
            "SOVRIGHT_P2P_SUBMITBLOCK_RPC_BIND_ADDR": f"127.0.0.1:{port}",
            "SOVRIGHT_P2P_SUBMITBLOCK_ZEBRA_URL": zebra.url,
            "SOVRIGHT_P2P_SUBMITBLOCK_MAX_REQUESTS_PER_MINUTE": "120",
            "SOVRIGHT_P2P_SUBMITBLOCK_RELAY_TIMEOUT_MILLIS": "10000",
        }
        if wire != "legacy":
            env["SOVRIGHT_P2P_RELAY_RAW_WIRE"] = wire
        ingress = Process("ingress", [build.path("sovright-p2p-ingress")], env, self.work)

        def listening():
            with socket.socket() as probe:
                probe.settimeout(0.2)
                return probe.connect_ex(("127.0.0.1", port)) == 0

        self.wait_for("the ingress RPC", listening, 15)
        return ingress, f"http://127.0.0.1:{port}"

    def stop(self):
        self.stop_relay()
        self.peer.shutdown()
        self.peer.server_close()


def submit(url, block_hex):
    request = urllib.request.Request(
        url,
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "submitblock", "params": [block_hex]}
        ).encode(),
        {"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as answer:
        reply = json.loads(answer.read())
    if "error" in reply:
        raise RuntimeError(f"submitblock: {reply['error']}")


def copies_at_zebra(zebra, least=1, secs=ARRIVAL_SECS):
    end = time.monotonic() + secs
    while time.monotonic() < end and len(zebra.calls) < least:
        time.sleep(0.02)
    if len(zebra.calls) >= least:
        time.sleep(SETTLE_SECS)
    return len(zebra.calls)


class Cell:
    def __init__(self, sender, wire, relay, receiver, expected, note=""):
        self.sender, self.wire = sender, wire
        self.relay, self.receiver = relay, receiver
        self.expected, self.note = expected, note

    def send(self, fleet, raw):
        sink = Zebra(raw)
        zebra = Zebra(raw)
        sidecar = fleet.start_sidecar(self.receiver, zebra)
        ingress, url = fleet.start_ingress(self.sender, self.wire, sink)
        try:
            submit(url, raw.hex())
            copies = copies_at_zebra(zebra)
            alive = sidecar.alive() and ingress.alive() and fleet.relay.alive()
            return copies, zebra, alive
        finally:
            ingress.stop()
            sidecar.stop()
            sink.stop()
            zebra.stop()


def run_cell(cell, raw, work):
    fleet = Fleet(work)
    try:
        fleet.start_relay(cell.relay)
        copies, zebra, alive = cell.send(fleet, raw)
        byte_for_byte = all(call == raw.hex() for call in zebra.calls)
    finally:
        fleet.stop()
    return copies, alive and byte_for_byte


def expected_copies(wire, relay, receiver):
    """What the design says a cell comes to, written before any of this runs."""
    if wire != "bound":
        return 1
    return 1 if relay.bound and receiver.bound else 0


def matrix(old, new):
    relays = [Build(old.directory, old.name), Build(new.directory, "new"),
              Build(new.directory, "new", True)]
    receivers = list(relays)
    senders = [(old, "legacy"), (Build(new.directory, "new"), "legacy"),
               (Build(new.directory, "new"), "dual"), (Build(new.directory, "new"), "bound")]
    return [
        Cell(sender, wire, relay, receiver, expected_copies(wire, relay, receiver))
        for sender, wire in senders
        for relay in relays
        for receiver in receivers
    ]


def sequence(steps, raw, work):
    """One relay stays up across steps that do not change it, as it would in a rollout.
    The clients start again at each step: with one real block, a client that stayed would
    drop it as the block it already has."""
    fleet = Fleet(work)
    rows = []
    try:
        current = None
        for name, sender, wire, relay, receiver, expected in steps:
            if str(relay) != current:
                fleet.stop_relay()
                fleet.start_relay(relay)
                current = str(relay)
            cell = Cell(sender, wire, relay, receiver, expected)
            copies, zebra, alive = cell.send(fleet, raw)
            rows.append(
                {
                    "step": name,
                    "sender": f"{sender}/{wire}",
                    "relay": str(relay),
                    "receiver": str(receiver),
                    "expected": expected,
                    "copies": copies,
                    "ok": copies == expected and alive,
                }
            )
    finally:
        fleet.stop()
    return rows


def rollout(old, new, raw, work):
    off, on = Build(new.directory, "new"), Build(new.directory, "new", True)
    return sequence(
        [
            ("start: all old", old, "legacy", old, old, 1),
            ("relay to new, off", old, "legacy", off, old, 1),
            ("receiver to new, off", old, "legacy", off, off, 1),
            ("relay on", old, "legacy", on, off, 1),
            ("receiver on", old, "legacy", on, on, 1),
            ("sender to new, legacy", off, "legacy", on, on, 1),
            ("sender dual", off, "dual", on, on, 1),
            ("sender bound", off, "bound", on, on, 1),
            ("back: sender dual", off, "dual", on, on, 1),
            ("back: sender legacy", off, "legacy", on, on, 1),
            ("back: sender old", old, "legacy", on, on, 1),
            ("back: receiver off", old, "legacy", on, off, 1),
            ("back: receiver old", old, "legacy", on, old, 1),
            ("back: relay off", old, "legacy", off, old, 1),
            ("back: relay old", old, "legacy", old, old, 1),
        ],
        raw,
        work,
    )


def wrong_order(old, new, raw, work):
    """What the order is for. These lose the block, and the rollback has to avoid them."""
    on = Build(new.directory, "new", True)
    return sequence(
        [
            ("receiver back before sender", on, "bound", on, old, 0),
            ("relay back before sender", on, "bound", old, on, 0),
            ("same, sender dual first", on, "dual", old, on, 1),
        ],
        raw,
        work,
    )


def swap_relay(first, second, sender, wire, receiver, raw, work):
    """The relay changes under clients that stay up, and only then the block comes."""
    fleet = Fleet(work)
    sink, zebra = Zebra(raw), Zebra(raw)
    try:
        fleet.start_relay(first)
        sidecar = fleet.start_sidecar(receiver, zebra)
        ingress, url = fleet.start_ingress(sender, wire, sink)
        try:
            fleet.stop_relay()
            fleet.start_relay(second)
            # A client finds a new relay by its next keepalive, which comes every 60s, so
            # for up to that long a block has no way through here, on either path.
            fleet.wait_for("the sidecar's session", lambda: fleet.peers_seen() > 0, 75)
            submit(url, raw.hex())
            return copies_at_zebra(zebra)
        finally:
            ingress.stop()
            sidecar.stop()
    finally:
        fleet.stop()
        sink.stop()
        zebra.stop()


def swaps(old, new, raw, work):
    on = Build(new.directory, "new", True)
    rows = []
    for name, first, second, sender, wire, receiver, expected in [
        ("old to new under old clients", old, on, old, "legacy", old, 1),
        ("new to old under new clients", on, old, on, "dual", on, 1),
    ]:
        copies = swap_relay(first, second, sender, wire, receiver, raw, work)
        rows.append({"step": name, "expected": expected, "copies": copies,
                     "ok": copies == expected})
    return rows


def resend(builds, wire, zebra_args, raw, work, wait_secs=3.0):
    """The same ingress, so the same connection, sends the same block a second time, once
    its own record and the node's short hold have passed. Zebra said no to the first."""
    fleet = Fleet(work)
    sink, zebra = Zebra(raw), Zebra(raw, **zebra_args)
    sender, relay, receiver = builds
    try:
        fleet.start_relay(relay)
        sidecar = fleet.start_sidecar(receiver, zebra)
        ingress, url = fleet.start_ingress(sender, wire, sink, window_secs=1)
        try:
            submit(url, raw.hex())
            first = copies_at_zebra(zebra)
            # The ingress record is 1s and the node's hold is 2s, and the receiver needs a
            # moment to let go of the first copy.
            time.sleep(wait_secs)
            if wait_secs > 60:
                # An ingress gives up on a peer that says nothing after 90s, and stops when it
                # has none. That is this stand-in's doing, and the next send is on a new
                # connection. What this case is for is on the receiver's side.
                ingress.stop()
                ingress, url = fleet.start_ingress(sender, wire, sink, window_secs=1)
            submit(url, raw.hex())
            copies_at_zebra(zebra, least=first + 1)
            return {"first": first, "calls": len(zebra.calls), "took": zebra.took}
        finally:
            ingress.stop()
            sidecar.stop()
    finally:
        fleet.stop()
        sink.stop()
        zebra.stop()


def resends(old, new, raw, work):
    on = Build(new.directory, "new", True)
    rows = []
    for name, builds, wire, zebra_args, wanted in [
        ("bound: Zebra refused, same connection", (on, on, on), "bound",
         {"refuse_first": 1}, (2, True)),
        ("bound: Zebra error, same connection", (on, on, on), "bound",
         {"fail_first": 1}, (2, True)),
        ("old: Zebra refused, same connection", (old, old, old), "legacy",
         {"refuse_first": 1}, (1, False)),
    ]:
        result = resend(builds, wire, zebra_args, raw, work)
        ok = (result["calls"], result["took"]) == wanted
        rows.append({"step": name, **result, "wanted": list(wanted), "ok": ok})
    return rows


def gate_on_legacy(old, new, raw, work):
    """Every bound switch off, so what differs is only the sidecar's build. Zebra says no
    once, and the same body comes again past the 120s records of the legacy path, the one
    way a legacy receiver sees a block twice. What it comes to is the gate's doing."""
    off = Build(new.directory, "new")
    rows = []
    for name, sidecar, wanted in [
        ("old sidecar", old, (1, False)),
        ("new sidecar, switches off", off, (2, True)),
    ]:
        result = resend((old, old, sidecar), "legacy", {"refuse_first": 1}, raw, work, 125.0)
        ok = (result["calls"], result["took"]) == wanted
        rows.append({"step": name, **result, "wanted": list(wanted), "ok": ok})
    return rows


def read_block(path):
    """The fixture is the header on line 1, then one transaction a line."""
    lines = [line.strip() for line in pathlib.Path(path).read_text().splitlines()]
    header, *transactions = [bytes.fromhex(line) for line in lines if line]
    if len(transactions) >= 0xfd:
        raise ValueError("this fixture has fewer transactions than a one-byte count holds")
    return header + bytes([len(transactions)]) + b"".join(transactions)


def print_rows(title, rows):
    print(f"\n## {title}")
    for row in rows:
        mark = "ok  " if row.get("ok") else "FAIL"
        rest = {key: value for key, value in row.items() if key not in ("ok",)}
        print(mark, json.dumps(rest))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", required=True)
    parser.add_argument("--old-name", default="old")
    parser.add_argument("--new", required=True)
    parser.add_argument("--block", required=True)
    parser.add_argument("--only", default="")
    parser.add_argument("--out")
    args = parser.parse_args()

    raw = read_block(args.block)
    old, new = Build(args.old, args.old_name), Build(args.new, "new")
    results = {}
    work = tempfile.mkdtemp(dir=os.environ.get("MATRIX_WORK"))
    print(f"logs in {work}")
    wanted = lambda part: not args.only or args.only == part
    if wanted("matrix"):
        rows = []
        for cell in matrix(old, new):
            copies, sound = run_cell(cell, raw, work)
            rows.append(
                {
                    "sender": f"{cell.sender}/{cell.wire}",
                    "relay": str(cell.relay),
                    "receiver": str(cell.receiver),
                    "expected": cell.expected,
                    "copies": copies,
                    "ok": copies == cell.expected and sound,
                }
            )
            print_rows("cell", rows[-1:])
            sys.stdout.flush()
        results["matrix"] = rows
    for part, run in [("rollout", rollout), ("wrong_order", wrong_order),
                      ("swaps", swaps), ("resends", resends),
                      ("gate_on_legacy", gate_on_legacy)]:
        if wanted(part):
            results[part] = run(old, new, raw, work)
            print_rows(part, results[part])
            sys.stdout.flush()
    every = [row for rows in results.values() for row in rows]
    failed = [row for row in every if not row.get("ok")]
    print(f"\n{len(every) - len(failed)} of {len(every)} as expected")
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(results, indent=2))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
