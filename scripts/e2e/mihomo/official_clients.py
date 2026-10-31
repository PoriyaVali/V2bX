#!/usr/bin/env python3
"""Connect an official Mihomo client through each managed node, from the
user's real subscription.

The audit client (client/main.go) is built from the fork that V2bX embeds, so
it speaks whatever the fork speaks. Users run official Mihomo builds: when
upstream changed the Sudoku wire format in v1.19.33, the audit stayed green
while every official client failed. Run this beside the audit, against the
same panel and a running V2bX, with an official binary:

    python3 scripts/e2e/mihomo/official_clients.py \\
        --mihomo /path/to/official/mihomo --panel http://127.0.0.1:6600 \\
        --server 127.0.0.1 --target http://127.0.0.1:18181/ --expect hello

Each user's entry is taken from the subscription as served, with only the
server address replaced and certificate checks relaxed for the audit's
private CA. The target must be reachable from V2bX (AllowPrivateDestinations
for a local one). Exit status is the number of protocols that failed.
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

PROTOCOLS = ["http", "socks5", "mieru", "shadowquic", "sudoku", "snell"]
TLS_PROTOCOLS = {"http", "socks5"}


def subscription_entry(panel, protocol, token):
    request = urllib.request.Request(
        panel.rstrip("/") + "/api/v1/client/subscribe?token=" + token,
        headers={"User-Agent": "clash-verge/v2.0 mihomo/1.19.33"},
    )
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    body = direct.open(request, timeout=20).read().decode()
    match = re.search(r"^\s*- (\{ name: [^\n]*type: " + protocol + r",[^\n]*\})\s*$", body, re.M)
    if not match:
        raise RuntimeError("no " + protocol + " entry in the subscription")
    return match.group(1)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rewrite(entry, protocol, server):
    entry = re.sub(r"name: [^,]+,", "name: p,", entry, count=1)
    entry = re.sub(r"server: [^,}]+", "server: " + server, entry, count=1)
    if protocol in TLS_PROTOCOLS:
        entry = entry.replace("skip-cert-verify: false", "skip-cert-verify: true")
    if protocol == "snell":
        entry = entry.replace("version: 3, host:", "version: 3, skip-cert-verify: true, host:")
    return entry


def try_protocol(args, protocol, token):
    entry = rewrite(subscription_entry(args.panel, protocol, token), protocol, args.server)
    directory = tempfile.mkdtemp(prefix="official-" + protocol + "-")
    port = free_port()
    with open(os.path.join(directory, "config.yaml"), "w") as f:
        f.write("mixed-port: %d\nlog-level: warning\nipv6: false\nproxies:\n  - %s\nrules:\n  - MATCH,p\n" % (port, entry))
    log = open(os.path.join(directory, "client.log"), "w")
    client = subprocess.Popen([args.mihomo, "-d", directory, "-f", os.path.join(directory, "config.yaml")], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), 0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://127.0.0.1:%d" % port}))
        last = None
        for _ in range(3):
            try:
                body = opener.open(args.target, timeout=10).read().decode(errors="replace")
                if args.expect in body:
                    return True, ""
                last = "unexpected body"
            except Exception as error:  # report what the client saw
                last = str(error)
            time.sleep(1)
        return False, last
    finally:
        client.terminate()
        client.wait(10)
        log.close()
        if args.keep:
            print("  kept", directory)
        else:
            shutil.rmtree(directory, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", required=True, help="official Mihomo binary")
    parser.add_argument("--panel", default="http://127.0.0.1:6600")
    parser.add_argument("--server", default="127.0.0.1", help="address that reaches V2bX's listeners")
    parser.add_argument("--target", required=True, help="URL fetched through each node")
    parser.add_argument("--expect", required=True, help="text the target's body contains")
    parser.add_argument("--tokens", default="", help="JSON map protocol -> subscription token (default e2e-sub-<protocol>)")
    parser.add_argument("--keep", action="store_true", help="keep each client's directory and log")
    args = parser.parse_args()
    # A NO_PROXY naming the target would send each request around the client
    # and pass every protocol without testing one.
    for name in ("no_proxy", "NO_PROXY"):
        os.environ.pop(name, None)
    tokens = json.loads(args.tokens) if args.tokens else {}
    version = subprocess.run([args.mihomo, "-v"], capture_output=True, text=True).stdout.strip().splitlines()[:1]
    print("client:", version[0] if version else args.mihomo)
    failed = 0
    for protocol in PROTOCOLS:
        try:
            ok, reason = try_protocol(args, protocol, tokens.get(protocol, "e2e-sub-" + protocol))
        except Exception as error:
            ok, reason = False, str(error)
        failed += not ok
        print("%-11s %s %s" % (protocol, "PASS" if ok else "FAIL", reason))
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
