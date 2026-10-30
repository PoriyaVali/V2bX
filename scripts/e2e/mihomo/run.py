#!/usr/bin/env python3
"""Opt-in audit against the disposable Webman/MariaDB/Redis deployment.

All requests reach the real panel. The HTTP gateway only records exchanges and
can deliberately lose an acknowledgement to verify idempotent traffic reports.
"""

import argparse
import collections
import copy
import hashlib
import http.client
import http.server
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROTOCOLS = [
    "http",
    "socks5",
    "mieru",
    "shadowquic",
    "sudoku",
    "snell",
    "vmess",
    "vless",
    "trojan",
    "tuic",
    "hysteria2",
    "anytls",
    "trusttunnel",
    "shadowsocks",
    "hysteria",
]
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Audit:
    def __init__(self, args):
        self.args, self.work = args, Path(args.work)
        self.seed = json.loads((self.work / "runtime/seed.json").read_text())
        self.nodes = {
            n["name"].removeprefix("e2e-"): n
            for n in json.loads((self.work / "runtime/nodes.json").read_text())["data"]
        }
        self.token = (self.work / "runtime/admin-token").read_text()
        image_file = self.work / "runtime/php-image"
        self.php_image = args.php_image or (
            image_file.read_text().strip()
            if image_file.exists()
            else "irboard-php82-test:latest"
        )
        if Path(args.client).resolve() != (self.work / "runtime/client").resolve():
            shutil.copy2(args.client, self.work / "runtime/client")
        self.results, self.profiles = [], {}
        self.expected = collections.defaultdict(lambda: [0, 0])
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.gateway_events, self.drop_uid, self.unavailable = [], None, False
        self.processes = []
        for name in [
            "logs/client.jsonl",
            "logs/panel-exchanges.jsonl",
            "results/checks.jsonl",
        ]:
            (self.work / name).write_text("")

    def record(self, name, passed, detail=None):
        row = {
            "time": time.time(),
            "check": name,
            "passed": bool(passed),
            "detail": copy.deepcopy(detail),
        }
        self.results.append(row)
        with (self.work / "results/checks.jsonl").open("a") as f:
            f.write(json.dumps(row) + "\n")
        print(
            ("PASS " if passed else "FAIL ")
            + name
            + (" " + str(detail)[:200] if detail is not None else ""),
            flush=True,
        )

    def api(self, path, body=None, admin=False, expected=200):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if admin:
            headers["Authorization"] = self.token
        request = urllib.request.Request(
            "http://127.0.0.1:6600" + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
        )
        try:
            with OPENER.open(request, timeout=15) as response:
                code, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            code, raw = error.code, error.read()
        if code != expected:
            raise RuntimeError(
                f"{path.split('?')[0]}: HTTP {code}, expected {expected}: {raw[:500]!r}"
            )
        return json.loads(raw)

    def endpoint(self, protocol, action):
        return (
            "/api/v1/server/UniProxy/"
            + action
            + "?"
            + urllib.parse.urlencode(
                {
                    "node_type": protocol,
                    "node_id": self.nodes[protocol]["id"],
                    "token": "isolated-e2e-node-token",
                }
            )
        )

    def edit(self, protocol, **attrs):
        user = self.seed[protocol]["user"]
        self.api(
            "/api/v1/e2e-admin/user/update",
            {
                "id": user["id"],
                "email": user["email"],
                "banned": 0,
                "is_admin": 0,
                "is_staff": 0,
                **attrs,
            },
            admin=True,
        )

    def cli(self, *args):
        return subprocess.check_output(
            ["docker", "exec", "irboard-v2bx-e2e-panel", "php", *args],
            text=True,
            timeout=20,
        )

    def snapshot(self):
        return json.loads(self.cli("/e2e/panel.php", "snapshot"))

    def wait(self, predicate, timeout=12):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = predicate()
            if value:
                return value
            time.sleep(0.25)
        return False

    def command(self, **command):
        self.client.stdin.write(json.dumps(command) + "\n")
        self.client.stdin.flush()
        line = self.client.stdout.readline()
        if not line:
            raise RuntimeError("wire client stopped")
        result = json.loads(line)
        with (self.work / "logs/client.jsonl").open("a") as f:
            f.write(
                json.dumps(
                    {
                        "action": command["action"],
                        "id": command.get("id"),
                        "result": result,
                    }
                )
                + "\n"
            )
        return result

    def transfer(self, protocol, action="tcp", upload=101, download=307, **extra):
        result = self.command(
            action=action, id=protocol, upload=upload, download=download, **extra
        )
        if result["ok"]:
            self.expected[protocol][0] += result.get("upload", 0)
            self.expected[protocol][1] += result.get("download", 0)
        return result

    def spawn(self, name, args, **kwargs):
        log = (self.work / ("logs/" + name + ".log")).open("w")
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, **kwargs)
        self.processes.append(process)
        return process

    def gateway(self):
        audit = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                parsed = urllib.parse.urlparse(self.path)
                query = urllib.parse.parse_qs(parsed.query)
                data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if audit.unavailable:
                    self.send_response(503)
                    self.end_headers()
                    return
                conn = http.client.HTTPConnection("127.0.0.1", 6600, timeout=15)
                try:
                    conn.request(
                        self.command,
                        self.path,
                        data,
                        {
                            k: v
                            for k, v in self.headers.items()
                            if k.lower() not in ["host", "connection"]
                        },
                    )
                    response = conn.getresponse()
                    body = response.read()
                    event = {
                        "time": time.time(),
                        "method": self.command,
                        "path": parsed.path,
                        "node_type": query.get("node_type", [""])[0],
                        "node_id": query.get("node_id", [""])[0],
                        "status": response.status,
                        "report_id": self.headers.get("X-Report-ID"),
                        "bytes": len(body),
                    }
                    if parsed.path.endswith(("/push", "/alive", "/status")):
                        try:
                            event["data"] = json.loads(data)
                        except ValueError:
                            pass
                    lose_ack = (
                        parsed.path.endswith("/push")
                        and audit.drop_uid is not None
                        and str(audit.drop_uid) in event.get("data", {})
                    )
                    if lose_ack:
                        audit.drop_uid = None
                        event["lost_ack"] = True
                    with audit.lock:
                        audit.gateway_events.append(event)
                        with (audit.work / "logs/panel-exchanges.jsonl").open("a") as f:
                            f.write(json.dumps(event) + "\n")
                    if lose_ack:
                        self.connection.shutdown(2)
                        self.connection.close()
                        return
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in [
                            "transfer-encoding",
                            "connection",
                            "content-length",
                        ]:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    conn.close()

        self.proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Handler)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()

    def start(self):
        self.client = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--name",
                "irboard-v2bx-e2e-client",
                "--network",
                "irboard-v2bx-e2e-clients",
                "--ip",
                "172.28.90.2",
                "--add-host",
                "node.e2e.test:172.28.90.1",
                "-e",
                "E2E_DEVICE_IP=172.28.90.2",
                "-v",
                str(self.work) + ":/audit:ro",
                self.php_image,
                "/audit/runtime/client",
                "/audit/certs/ca.pem",
                "/audit/certs/decoy.pem",
                "/audit/certs/decoy.key",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=(self.work / "logs/client-stderr.log").open("w"),
            text=True,
        )
        self.processes.append(self.client)
        ready = json.loads(self.client.stdout.readline())
        (self.work / "runtime/destinations.json").write_text(
            json.dumps(ready, indent=2)
        )
        self.gateway()
        provenance_file = self.work / "runtime/panel-provenance.json"
        manifest = {
            "started_at": time.time(),
            "php_image": self.php_image,
            "v2bx_sha256": hashlib.sha256(
                Path(self.args.v2bx).read_bytes()
            ).hexdigest(),
            "client_sha256": hashlib.sha256(
                (self.work / "runtime/client").read_bytes()
            ).hexdigest(),
            "panel": json.loads(provenance_file.read_text())
            if provenance_file.exists()
            else None,
            "private_test_ca": True,
            "public_acme_tested": False,
        }
        (self.work / "results/manifest.json").write_text(json.dumps(manifest, indent=2))
        self.spawn(
            "queue-worker",
            [
                "docker",
                "exec",
                "irboard-v2bx-e2e-panel",
                "php",
                "artisan",
                "queue:work",
                "redis",
                "--queue=traffic_fetch,stat,default",
                "--sleep=1",
                "--tries=3",
            ],
        )

        def drain():
            with (self.work / "logs/traffic-drain.log").open("w") as log:
                while not self.stop.wait(0.7):
                    subprocess.run(
                        [
                            "docker",
                            "exec",
                            "irboard-v2bx-e2e-panel",
                            "php",
                            "artisan",
                            "traffic:update",
                        ],
                        stdout=log,
                        stderr=log,
                        timeout=15,
                        check=True,
                    )

        self.drainer = threading.Thread(target=drain, daemon=True)
        self.drainer.start()
        cfg = {
            "Log": {"Level": "debug"},
            "Memory": {"LimitPercent": 30},
            "Cores": [
                {
                    "Type": "mihomo",
                    "AllowPrivateDestinations": True,
                    "DialTimeout": 4,
                    "UDPTimeout": 3,
                },
                {
                    "Type": "sing",
                    "AllowPrivateDestinations": True,
                    "Log": {"Level": "debug"},
                },
                {"Type": "mdns"},
            ],
            "Nodes": [],
        }
        for protocol in PROTOCOLS + ["mdns"]:
            node = {
                "Core": "sing"
                if protocol in ["shadowsocks", "hysteria"]
                else "mdns"
                if protocol == "mdns"
                else "mihomo",
                "ApiHost": "http://127.0.0.1:18080",
                "ApiKey": "isolated-e2e-node-token",
                "NodeType": protocol,
                "NodeID": self.nodes[protocol]["id"],
                "ListenIP": "::",
                "Timeout": 5,
                "LimitConfig": {"ConnLimit": 4},
                "CertConfig": {
                    "CertMode": "file",
                    "CertDomain": "node.e2e.test",
                    "CertFile": str(self.work / "certs/node.pem"),
                    "KeyFile": str(self.work / "certs/node.key"),
                },
                "SingOptions": {"DecoySite": False},
            }
            if protocol == "shadowquic":
                node["MihomoOptions"] = {
                    "JLSUpstream": {"Addr": ready["decoy"], "SNI": "node.e2e.test"}
                }
            if protocol == "snell":
                # The panel's obfs-opts host is node.e2e.test; its site runs
                # beside the client.
                node["MihomoOptions"] = {"ShadowTLSHandshake": ready["handshake"]}
            cfg["Nodes"].append(node)
        (self.work / "runtime/v2bx.json").write_text(json.dumps(cfg, indent=2))
        self.v2bx = self.spawn(
            "v2bx",
            [
                self.args.v2bx,
                "server",
                "--watch=false",
                "-c",
                str(self.work / "runtime/v2bx.json"),
            ],
        )
        started = self.wait(
            lambda: (
                "Nodes started" in (self.work / "logs/v2bx.log").read_text()
                or self.v2bx.poll() is not None
            ),
            30,
        )
        if not started or self.v2bx.poll() is not None:
            raise RuntimeError("V2bX startup failed; see logs/v2bx.log")
        self.record(
            "real-daemons-started",
            True,
            {
                "nodes": len(cfg["Nodes"]),
                "panel": "Webman",
                "database": "MariaDB 10.6",
                "cache_queue": "Redis",
            },
        )

    def profile(self, protocol):
        url = (
            "http://127.0.0.1:6600/api/v1/client/subscribe?flag=mihomo&token="
            + self.seed[protocol]["user"]["token"]
        )
        with OPENER.open(url, timeout=15) as response:
            body = response.read()
        (self.work / "runtime" / ("subscription-" + protocol + ".yaml")).write_bytes(
            body
        )
        result = self.command(
            action="profile",
            url="file:///audit/runtime/subscription-" + protocol + ".yaml",
            name="e2e-" + protocol,
        )
        if not result["ok"]:
            raise RuntimeError(result)
        self.profiles[protocol] = result["profile"]
        (self.work / "results" / ("subscription-" + protocol + ".json")).write_text(
            json.dumps(result["profile"], indent=2)
        )
        return result["profile"]

    def exact_usage(self, name):
        def check():
            users = self.snapshot()["users"]
            return all(
                [
                    users[str(self.seed[p]["user"]["id"])]["u"],
                    users[str(self.seed[p]["user"]["id"])]["d"],
                ]
                == v
                for p, v in self.expected.items()
            )

        passed = bool(self.wait(check, 16))
        users = self.snapshot()["users"]
        detail = {
            p: {
                "expected": v,
                "actual": [
                    users[str(self.seed[p]["user"]["id"])]["u"],
                    users[str(self.seed[p]["user"]["id"])]["d"],
                ],
            }
            for p, v in self.expected.items()
        }
        self.record(name, passed, detail)

    def certificate_checks(self):
        cases = [
            (p, "tcp")
            for p in [
                "http",
                "socks5",
                "vmess",
                "vless",
                "trojan",
                "anytls",
                "trusttunnel",
            ]
        ]
        cases += [(p, "quic") for p in ["tuic", "hysteria2", "trusttunnel", "hysteria"]]

        def check(label, serial):
            for protocol, transport in cases:
                result = self.command(
                    action="tls",
                    address="node.e2e.test:" + str(self.nodes[protocol]["server_port"]),
                    domain="node.e2e.test",
                    transport=transport,
                    alpn=["hysteria"] if protocol == "hysteria" else ["h3"],
                )
                self.record(
                    protocol + "/" + transport + "/" + label,
                    result["ok"] and result.get("serial") == str(serial),
                    result,
                )

        check("verified-initial-certificate", 101)
        cert = self.work / "certs"

        def issue(stem, serial, domain):
            ext = cert / (stem + ".extensions")
            ext.write_text(
                "subjectAltName=DNS:"
                + domain
                + "\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n"
            )
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-keyout",
                    str(cert / (stem + ".key")),
                    "-out",
                    str(cert / (stem + ".csr")),
                    "-subj",
                    "/CN=" + domain,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(cert / (stem + ".csr")),
                    "-CA",
                    str(cert / "ca.pem"),
                    "-CAkey",
                    str(cert / "ca.key"),
                    "-set_serial",
                    str(serial),
                    "-out",
                    str(cert / (stem + ".pem")),
                    "-days",
                    "90",
                    "-extfile",
                    str(ext),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        def install(stem, which):
            target = cert / ("node." + which)
            shutil.copy2(cert / (stem + "." + which), cert / ("candidate." + which))
            os.replace(cert / ("candidate." + which), target)

        issue("rotated", 102, "node.e2e.test")
        install("rotated", "key")
        time.sleep(2)
        check("partial-pair-keeps-current-certificate", 101)
        install("rotated", "pem")
        time.sleep(2)
        check("live-certificate-rotation", 102)
        issue("unrelated", 103, "unrelated.e2e.test")
        install("unrelated", "key")
        install("unrelated", "pem")
        time.sleep(2)
        check("wrong-domain-keeps-last-valid-certificate", 102)
        issue("recovered", 104, "node.e2e.test")
        install("recovered", "key")
        install("recovered", "pem")
        time.sleep(2)
        check("certificate-recovery", 104)
        result = self.command(
            action="tls",
            address="node.e2e.test:" + str(self.nodes["shadowquic"]["server_port"]),
            domain="node.e2e.test",
            transport="quic",
        )
        self.record(
            "shadowquic/unauthenticated-probe-reaches-real-quic-decoy",
            result["ok"] and result.get("serial") == "201",
            result,
        )
        for protocol in self.profiles:
            result = self.transfer(protocol, upload=31, download=71)
            self.record(
                protocol + "/session-survives-certificate-rotation",
                result["ok"],
                result,
            )
        self.exact_usage("certificate-operations-do-not-bill-infrastructure")

    def eligibility_checks(self):
        for phase, disable, restore in [
            (
                "expired",
                {"expired_at": int(time.time()) - 60},
                {"expired_at": int(time.time()) + 86400},
            ),
            (
                "quota-exhausted",
                {"transfer_enable": 0},
                {"transfer_enable": 100 * 1073741824},
            ),
        ]:
            for protocol in PROTOCOLS:
                self.edit(protocol, **disable)
            time.sleep(2)
            for protocol, profile in self.profiles.items():
                users = self.api(self.endpoint(protocol, "user"))["users"]
                self.record(
                    protocol + "/" + phase + "/removed-from-eligible-list",
                    len(users) == 0,
                )
                result = self.command(action="tcp", id=protocol, upload=7, download=13)
                self.record(
                    protocol + "/" + phase + "/active-session-revoked",
                    not result["ok"],
                    result,
                )
                result = self.command(
                    action="probe", profile=profile, upload=7, download=13
                )
                self.record(
                    protocol + "/" + phase + "/cached-credentials-rejected",
                    not result["ok"],
                    result,
                )
                self.command(action="close", id=protocol)
            for protocol in PROTOCOLS:
                self.edit(protocol, **restore)
            time.sleep(2)
            for protocol, profile in self.profiles.items():
                result = self.transfer(
                    protocol, "open", profile=profile, upload=19, download=43
                )
                self.record(
                    protocol + "/" + phase + "/access-restored", result["ok"], result
                )
            self.exact_usage(phase + "/exact-accounting")

    def mdns_checks(self):
        if not (self.work / "runtime/mdns-client").exists():
            self.record(
                "mdns/native-client-available",
                False,
                "Build masterdnsvpn-go/cmd/client into runtime/mdns-client",
            )
            return
        # This core intentionally blocks RFC1918/loopback egress. A separately
        # owned, internal-only TEST-NET interface exercises forwarding without
        # changing the production guard or contacting a public destination.
        network = "irboard-v2bx-mdns-targets"
        found = (
            subprocess.run(
                ["docker", "network", "inspect", network],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )
        if not found:
            subprocess.run(
                [
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    "--subnet",
                    "192.0.2.0/24",
                    network,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        subprocess.run(
            [
                "docker",
                "network",
                "connect",
                "--ip",
                "192.0.2.2",
                network,
                "irboard-v2bx-e2e-client",
            ],
            check=True,
        )
        ready = json.loads((self.work / "runtime/destinations.json").read_text())
        target = "192.0.2.2:" + ready["tcp_target"].rsplit(":", 1)[1]
        config = self.api(self.endpoint("mdns", "config"))
        cfg = {
            "DOMAINS": config["domain"],
            "DATA_ENCRYPTION_METHOD": config["encryption_method"],
            "ENCRYPTION_KEY": config["encryption_key"],
            "UUID": self.seed["mdns"]["user"]["uuid"],
            "NODE_SECRET": config["node_secret"],
            "SESSION_V2": "on",
            "LISTEN_IP": "127.0.0.1",
            "LISTEN_PORT": 18000,
            "SOCKS5_AUTH": False,
            "LOCAL_DNS_ENABLED": False,
            "RESOLVERS": ["172.28.90.1:" + str(self.nodes["mdns"]["server_port"])],
            "PACKET_DUPLICATION_COUNT": 1,
            "SETUP_PACKET_DUPLICATION_COUNT": 1,
            "SAVE_MTU_SERVERS_TO_FILE": False,
            "LOCAL_DNS_CACHE_PERSIST_TO_FILE": False,
            "RX_TX_WORKERS": 2,
            "TUNNEL_PROCESS_WORKERS": 2,
        }
        (self.work / "runtime/mdns.toml").write_text(
            "\n".join(key + " = " + json.dumps(value) for key, value in cfg.items())
            + "\n"
        )
        self.spawn(
            "mdns-client",
            [
                "docker",
                "exec",
                "-e",
                "GOMAXPROCS=2",
                "irboard-v2bx-e2e-client",
                "/audit/runtime/mdns-client",
                "-config",
                "/audit/runtime/mdns.toml",
            ],
        )
        profile = {
            "name": "native-mdns",
            "type": "socks5",
            "server": "127.0.0.1",
            "port": 18000,
            "udp": True,
        }
        result = None

        def probe():
            nonlocal result
            result = self.command(
                action="open",
                id="mdns",
                profile=profile,
                address=target,
                upload=101,
                download=307,
            )
            return result["ok"]

        connected = bool(self.wait(probe, 35))
        self.record("mdns/native-client-tcp-through-real-node", connected, result)
        if connected:
            self.expected["mdns"][0] += result["upload"]
            self.expected["mdns"][1] += result["download"]
            users = self.wait(
                lambda: self.snapshot()["users"][
                    str(self.seed["mdns"]["user"]["id"])
                ].get("alive"),
                8,
            )
            self.record(
                "mdns/native-online-device-in-panel",
                bool((users or {}).get("alive_ip")),
                users,
            )

    def admission_checks(self):
        protocol = "socks5"
        profile = self.profiles[protocol]
        # Four simultaneous forwarding streams are allowed by this node config.
        for i in range(3):
            result = self.command(
                action="open",
                id="extra-" + str(i),
                profile=profile,
                upload=7,
                download=13,
            )
            self.record("connection-cap/allowed-stream-" + str(i), result["ok"], result)
            if result["ok"]:
                self.expected[protocol][0] += result["upload"]
                self.expected[protocol][1] += result["download"]
        result = self.command(action="probe", profile=profile, upload=7, download=13)
        self.record(
            "connection-cap/fifth-forwarding-stream-rejected", not result["ok"], result
        )
        for i in range(3):
            self.command(action="close", id="extra-" + str(i))
        self.edit(protocol, device_limit=1)
        time.sleep(2)
        second = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--name",
                "irboard-v2bx-e2e-second-client",
                "--network",
                "irboard-v2bx-e2e-clients",
                "--ip",
                "172.28.90.3",
                "--add-host",
                "node.e2e.test:172.28.90.1",
                "-e",
                "E2E_DEVICE_IP=172.28.90.3",
                "-v",
                str(self.work) + ":/audit:ro",
                self.php_image,
                "/audit/runtime/client",
                "/audit/certs/ca.pem",
                "/audit/certs/decoy.pem",
                "/audit/certs/decoy.key",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=(self.work / "logs/second-client.log").open("w"),
            text=True,
        )
        self.processes.append(second)
        json.loads(second.stdout.readline())

        def command():
            second.stdin.write(
                json.dumps(
                    {"action": "probe", "profile": profile, "upload": 7, "download": 13}
                )
                + "\n"
            )
            second.stdin.flush()
            return json.loads(second.stdout.readline())

        result = command()
        self.record(
            "device-cap/second-real-source-ip-rejected", not result["ok"], result
        )
        self.edit(protocol, device_limit=2)
        time.sleep(2)
        result = command()
        self.record(
            "device-cap/second-ip-accepted-after-panel-edit", result["ok"], result
        )
        if result["ok"]:
            self.expected[protocol][0] += result["upload"]
            self.expected[protocol][1] += result["download"]
        second.stdin.close()
        second.wait(timeout=12)
        self.exact_usage("admission/exact-uid-accounting")

    def control_checks(self):
        protocol = "socks5"
        payload = {**self.seed[protocol]["payload"], "id": self.nodes[protocol]["id"]}
        target = json.loads((self.work / "runtime/destinations.json").read_text())[
            "tcp_target"
        ]
        target_port = target.rsplit(":", 1)[1]
        remarks = "e2e destination block " + str(time.time_ns())
        self.api(
            "/api/v1/e2e-admin/server/route/save",
            {
                "remarks": remarks,
                "action": "block_port",
                "match": [target_port],
            },
            admin=True,
        )
        routes = self.api("/api/v1/e2e-admin/server/route/fetch", admin=True)["data"]
        route_id = next(r["id"] for r in routes if r["remarks"] == remarks)
        self.api(
            "/api/v1/e2e-admin/server/socks5/save",
            {**payload, "route_id": [str(route_id)]},
            admin=True,
        )
        time.sleep(2)
        result = self.command(
            action="probe", profile=self.profiles[protocol], upload=7, download=13
        )
        self.record(
            "destination-policy/blocked-port-from-panel-rejected",
            not result["ok"],
            result,
        )
        self.api(
            "/api/v1/e2e-admin/server/socks5/save",
            {**payload, "route_id": []},
            admin=True,
        )
        time.sleep(2)
        result = self.transfer(
            protocol, "open", profile=self.profiles[protocol], upload=7, download=13
        )
        self.record(
            "destination-policy/removing-rule-restores-access", result["ok"], result
        )
        self.exact_usage("destination-policy/no-phantom-payload-billing")
        protocol = "http"
        payload = {**self.seed[protocol]["payload"], "id": self.nodes[protocol]["id"]}
        self.command(action="close", id=protocol)
        self.exact_usage("node-rate/baseline-flushed")
        self.api(
            "/api/v1/e2e-admin/server/http/save", {**payload, "rate": 1.5}, admin=True
        )
        time.sleep(2)
        result = self.command(
            action="open",
            id=protocol,
            profile=self.profiles[protocol],
            upload=100,
            download=200,
        )
        self.record("node-rate/weighted-transfer-connects", result["ok"], result)
        if result["ok"]:
            self.expected[protocol][0] += 162
            self.expected[protocol][1] += 300
        self.exact_usage("node-rate/1.5-multiplier-in-both-directions")
        self.api(
            "/api/v1/e2e-admin/server/http/save",
            {**payload, "port": 25000, "server_port": 25000, "rate": 1},
            admin=True,
        )
        time.sleep(2)
        old = self.profiles[protocol]
        result = self.command(action="probe", profile=old, upload=7, download=13)
        self.record("node-port/old-listener-retired", not result["ok"], result)
        updated = self.profile(protocol)
        self.record("node-port/subscription-follows-new-port", updated["port"] == 25000)
        result = self.transfer(
            protocol, "open", profile=updated, upload=23, download=59
        )
        self.record("node-port/new-listener-serves-same-user", result["ok"], result)
        self.exact_usage("node-port/accounting-survives-reload")
        self.api("/api/v1/e2e-admin/server/http/save", payload, admin=True)
        time.sleep(2)
        result = self.transfer(
            protocol, "open", profile=self.profile(protocol), upload=23, download=59
        )
        self.record("node-port/original-setting-restored", result["ok"], result)
        self.exact_usage("node-control/final-exact-accounting")

    def run_controls(self):
        baseline = self.snapshot()["users"]
        for protocol in PROTOCOLS:
            uid = str(self.seed[protocol]["user"]["id"])
            self.expected[protocol] = [baseline[uid]["u"], baseline[uid]["d"]]
            self.seed[protocol]["user"].update(
                uuid=baseline[uid]["uuid"], token=baseline[uid]["token"]
            )
        self.start()
        for protocol in ["http", "socks5"]:
            result = self.transfer(
                protocol, "open", profile=self.profile(protocol), upload=23, download=59
            )
            self.record(protocol + "/control-baseline-connects", result["ok"], result)
        self.exact_usage("node-control/baseline-accounting")
        self.control_checks()

    def isolation_checks(self):
        protocol = "socks5"
        self.unavailable = True
        result = self.transfer(protocol, upload=23, download=53)
        self.record("panel-outage/live-session-kept", result["ok"], result)
        time.sleep(2)
        self.unavailable = False
        self.exact_usage("panel-outage/queued-traffic-recovered-once")
        # Malformed counter types must stay invalid across the worker bridge.
        for counts in [[-1, 3], [1.5, 3], ["1", 3], [1, 2, 3]]:
            self.api(
                self.endpoint(protocol, "push"),
                {str(self.seed[protocol]["user"]["id"]): counts},
                expected=422,
            )
        self.record("webman/rejects-invalid-counter-types", True)
        self.exact_usage("webman/rejected-reports-do-not-change-usage")
        old_profile = self.profiles[protocol]
        self.api(
            "/api/v1/e2e-admin/user/resetSecret",
            {"id": self.seed[protocol]["user"]["id"]},
            admin=True,
        )
        user = self.snapshot()["users"][str(self.seed[protocol]["user"]["id"])]
        self.seed[protocol]["user"].update(uuid=user["uuid"], token=user["token"])
        time.sleep(2)
        result = self.command(
            action="probe", profile=old_profile, upload=7, download=13
        )
        self.record("credential-rotation/old-secret-rejected", not result["ok"], result)
        self.command(action="close", id=protocol)
        result = self.transfer(
            protocol, "open", profile=self.profile(protocol), upload=29, download=61
        )
        self.record(
            "credential-rotation/new-subscription-connects", result["ok"], result
        )
        self.exact_usage("credential-rotation/uid-accounting-retained")

    def run(self):
        self.start()
        for protocol in PROTOCOLS:
            try:
                profile = self.profile(protocol)
                if protocol not in ["mieru", "shadowquic", "sudoku", "shadowsocks"]:
                    self.record(
                        protocol + "/subscription-verifies-certificates",
                        profile.get("skip-cert-verify") is not True,
                        {
                            "server": profile.get("server"),
                            "sni": profile.get("sni", profile.get("servername")),
                        },
                    )
                result = self.transfer(protocol, "open", profile=profile)
                self.record(
                    protocol + "/tcp-from-real-subscription", result["ok"], result
                )
                if result["ok"] and protocol != "http":
                    result = self.transfer(protocol, "udp", upload=137, download=509)
                    self.record(
                        protocol + "/udp-from-real-subscription", result["ok"], result
                    )
            # Preserve independent protocol outcomes when one client fails.
            except Exception as error:  # noqa: BLE001
                self.record(protocol + "/subscription", False, str(error))
        self.exact_usage("exact-directional-usage-in-MariaDB")
        users = self.snapshot()["users"]
        for protocol in self.profiles:
            uid = str(self.seed[protocol]["user"]["id"])
            self.record(
                protocol + "/online-in-panel",
                bool((users[uid]["alive"] or {}).get("alive_ip")),
                users[uid]["alive"],
            )
        # Real report accepted by Irboard, acknowledgement deliberately lost.
        if "socks5" in self.profiles:
            self.drop_uid = self.seed["socks5"]["user"]["id"]
            result = self.transfer("socks5", upload=211, download=701)
            self.record("lost-ack/transfer", result["ok"], result)
            self.wait(lambda: self.drop_uid is None, 8)
            time.sleep(2)
            events = [
                e
                for e in self.gateway_events
                if e.get("report_id") and e["path"].endswith("/push")
            ]
            lost = [e for e in events if e.get("lost_ack")]
            self.record(
                "lost-ack/retried-same-report-id",
                bool(lost)
                and sum(e["report_id"] == lost[0]["report_id"] for e in events) >= 2,
            )
            self.exact_usage("lost-ack/no-double-billing")
        # In-place user-limit edits must affect established connections.
        for protocol in PROTOCOLS:
            self.edit(protocol, speed_limit=1)
        time.sleep(2)
        for protocol in self.profiles:
            result = self.transfer(protocol, upload=128 * 1024, download=128 * 1024)
            self.record(
                protocol + "/1mbps-on-existing-session",
                result["ok"] and 1000 <= result.get("elapsed_ms", 0) <= 10000,
                result,
            )
        for protocol in PROTOCOLS:
            self.edit(protocol, speed_limit=20)
        time.sleep(2)
        for protocol in self.profiles:
            result = self.transfer(protocol, upload=128 * 1024, download=128 * 1024)
            self.record(
                protocol + "/live-upgrade-on-same-session",
                result["ok"] and result.get("elapsed_ms", 10000) < 2000,
                result,
            )
        self.exact_usage("exact-usage-after-live-speed-edits")
        for protocol in PROTOCOLS:
            self.edit(protocol, banned=1)
        time.sleep(2)
        for protocol, profile in self.profiles.items():
            result = self.command(action="tcp", id=protocol, upload=11, download=29)
            self.record(
                protocol + "/ban-closes-active-session", not result["ok"], result
            )
            result = self.command(
                action="probe", profile=profile, upload=7, download=13
            )
            self.record(
                protocol + "/ban-rejects-cached-credentials", not result["ok"], result
            )
            self.command(action="close", id=protocol)
        for protocol in PROTOCOLS:
            self.edit(protocol, banned=0)
        time.sleep(2)
        for protocol, profile in self.profiles.items():
            result = self.transfer(
                protocol, "open", profile=profile, upload=17, download=41
            )
            self.record(protocol + "/unban-restores-access", result["ok"], result)
        self.exact_usage("exact-usage-after-unban")
        self.certificate_checks()
        self.admission_checks()
        self.eligibility_checks()
        self.isolation_checks()
        self.mdns_checks()
        nodes = self.api("/api/v1/e2e-admin/server/manage/getNodes", admin=True)["data"]
        for protocol in PROTOCOLS + ["mdns"]:
            node = next(n for n in nodes if n["name"] == "e2e-" + protocol)
            self.record(
                protocol + "/heartbeat-and-load",
                node.get("available_status") == 2 and bool(node.get("load_status")),
                {
                    "status": node.get("available_status"),
                    "load": node.get("load_status"),
                },
            )
        for protocol in self.seed:
            if protocol in PROTOCOLS + ["mdns"]:
                continue
            self.api(self.endpoint(protocol, "config"), expected=501)
            self.record(protocol + "/unsupported-server-rejected", True)
        for protocol in self.profiles:
            self.command(action="close", id=protocol)
        self.exact_usage("final-exact-usage")
        self.record("no-failed-queue-jobs", self.snapshot()["failed_jobs"] == 0)

    def close(self):
        self.stop.set()
        if hasattr(self, "drainer"):
            self.drainer.join(timeout=20)
        try:
            self.cli("artisan", "queue:restart")
        except (OSError, subprocess.SubprocessError):
            pass
        if hasattr(self, "client"):
            try:
                self.client.stdin.close()
            except OSError:
                pass
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if hasattr(self, "proxy"):
            self.proxy.shutdown()
        summary = {
            "passed": sum(r["passed"] for r in self.results),
            "failed": sum(not r["passed"] for r in self.results),
            "results": self.results,
        }
        (self.work / "results/summary.json").write_text(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True)
    parser.add_argument("--v2bx", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--php-image")
    parser.add_argument("--controls-only", action="store_true")
    args = parser.parse_args()
    audit = Audit(args)
    try:
        if args.controls_only:
            audit.run_controls()
        else:
            audit.run()
    # Always record unexpected harness failures before the cleanup/final report.
    except Exception as error:  # noqa: BLE001
        audit.record("audit-fatal", False, str(error))
    finally:
        audit.close()
    raise SystemExit(1 if any(not row["passed"] for row in audit.results) else 0)


if __name__ == "__main__":
    main()
