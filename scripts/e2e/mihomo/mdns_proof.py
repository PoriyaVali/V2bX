#!/usr/bin/env python3
"""Native MDNS proof with an owned TEST-NET target on an internal Docker LAN.

The embedded MasterDnsVPN rejects private egress intentionally. An echo target
using the documentation address 192.0.2.2 exercises payload forwarding while
leaving that production policy unchanged. This script must run while the main
audit's V2bX/client processes are stopped. It does not reset the panel database.
"""

import argparse
import json
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

PARSER = argparse.ArgumentParser(description=__doc__)
PARSER.add_argument("--work", default="/workspace/scratch/irboard-v2bx-e2e")
PARSER.add_argument("--v2bx", required=True)
PARSER.add_argument("--php-image", default="irboard-php82-test:latest")
ARGS = PARSER.parse_args()
WORK = Path(ARGS.work).resolve()
OUT = WORK / "mdns-proof"
OUT.mkdir(exist_ok=True)
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
NETWORK = "irboard-v2bx-mdns-targets"
CLIENT = "irboard-v2bx-mdns-proof-client"
ECHO = "irboard-v2bx-mdns-proof-echo"
processes = []
created = []


def command(*args):
    return subprocess.check_output(list(map(str, args)), text=True).strip()


def api(path):
    with OPENER.open("http://127.0.0.1:6600" + path, timeout=10) as response:
        return json.load(response)


def snapshot():
    return json.loads(
        command(
            "docker",
            "exec",
            "irboard-v2bx-e2e-panel",
            "php",
            "/e2e/panel.php",
            "snapshot",
        )
    )


def receive(conn, size):
    data = b""
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def socks_connect(host, port):
    conn = socket.create_connection(("172.28.90.4", 18000), timeout=5)
    conn.settimeout(10)
    conn.sendall(b"\x05\x01\x00")
    assert receive(conn, 2) == b"\x05\x00", "SOCKS method rejected"
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port))
    header = receive(conn, 4)
    if header[1] != 0:
        conn.close()
        raise RuntimeError(f"SOCKS CONNECT rejected: {header[1]}")
    if header[3] == 1:
        receive(conn, 6)
    elif header[3] == 4:
        receive(conn, 18)
    else:
        size = receive(conn, 1)[0]
        receive(conn, size + 2)
    return conn


def spawn(name, args):
    log = (OUT / (name + ".log")).open("w")
    process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    processes.append(process)
    return process


def main():
    if not (WORK / ".isolated-irboard-v2bx-e2e").exists():
        raise RuntimeError("Use the disposable integration deployment work directory")
    seed = json.loads((WORK / "runtime/seed.json").read_text())
    uid = str(seed["mdns"]["user"]["id"])
    query = urllib.parse.urlencode(
        {"node_type": "mdns", "node_id": 1, "token": "isolated-e2e-node-token"}
    )
    config = api("/api/v1/server/UniProxy/config?" + query)
    before = snapshot()["users"][uid]
    (OUT / "baseline.json").write_text(json.dumps(before, indent=2))
    result = subprocess.run(
        ["docker", "network", "inspect", NETWORK],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode:
        command(
            "docker",
            "network",
            "create",
            "--internal",
            "--subnet",
            "192.0.2.0/24",
            NETWORK,
        )
    echo = r"""<?php
function readn($c, $n) { $s=''; while (strlen($s)<$n) { $b=fread($c,$n-strlen($s)); if ($b===false||$b==='') return null; $s.=$b; } return $s; }
$s=stream_socket_server('tcp://0.0.0.0:29001',$e,$m); if (!$s) exit(1);
pcntl_signal(SIGCHLD,SIG_IGN);
while($c=stream_socket_accept($s,-1)) { $pid=pcntl_fork(); if ($pid>0) { fclose($c); continue; } if ($pid<0) exit(2); fclose($s); stream_set_timeout($c,10); while($h=readn($c,8)) { $v=unpack('Nup/Ndown',$h); if ($v['up']>1048576||$v['down']>1048576) break; $body=readn($c,$v['up']); if ($body===null) break; $out=str_repeat(chr(90),$v['down']); while ($out!=='') { $n=fwrite($c,$out); if (!$n) break 2; $out=substr($out,$n); } echo json_encode(['upload'=>$v['up']+8,'download'=>$v['down']]),"\n"; } fclose($c); exit(0); }
"""
    (OUT / "echo.php").write_text(echo)
    command(
        "docker",
        "run",
        "-d",
        "--name",
        ECHO,
        "--network",
        NETWORK,
        "--ip",
        "192.0.2.2",
        "-v",
        str(OUT) + ":/proof:ro",
        ARGS.php_image,
        "php",
        "/proof/echo.php",
    )
    created.append(ECHO)
    command(
        "docker",
        "network",
        "connect",
        "--ip",
        "172.28.90.5",
        "irboard-v2bx-e2e-clients",
        ECHO,
    )
    command(
        "docker",
        "run",
        "-d",
        "--name",
        CLIENT,
        "--network",
        "irboard-v2bx-e2e-clients",
        "--ip",
        "172.28.90.4",
        "-v",
        str(WORK) + ":/audit:ro",
        ARGS.php_image,
        "sleep",
        "infinity",
    )
    created.append(CLIENT)
    client = {
        "DOMAINS": config["domain"],
        "DATA_ENCRYPTION_METHOD": config["encryption_method"],
        "ENCRYPTION_KEY": config["encryption_key"],
        "UUID": seed["mdns"]["user"]["uuid"],
        "NODE_SECRET": config["node_secret"],
        "SESSION_V2": "on",
        "LISTEN_IP": "0.0.0.0",
        "LISTEN_PORT": 18000,
        "SOCKS5_AUTH": False,
        "LOCAL_DNS_ENABLED": False,
        "RESOLVERS": ["172.28.90.1:" + str(config["server_port"])],
        "PACKET_DUPLICATION_COUNT": 1,
        "SETUP_PACKET_DUPLICATION_COUNT": 1,
        "SAVE_MTU_SERVERS_TO_FILE": False,
        "LOCAL_DNS_CACHE_PERSIST_TO_FILE": False,
        "RX_TX_WORKERS": 2,
        "TUNNEL_PROCESS_WORKERS": 2,
        "LOG_LEVEL": "DEBUG",
    }
    (OUT / "client.toml").write_text(
        "\n".join(key + " = " + json.dumps(value) for key, value in client.items())
        + "\n"
    )
    node = {
        "Log": {"Level": "debug"},
        "Memory": {"LimitPercent": 30},
        "Cores": [{"Type": "mdns"}],
        "Nodes": [
            {
                "Core": "mdns",
                "ApiHost": "http://127.0.0.1:6600",
                "ApiKey": "isolated-e2e-node-token",
                "NodeType": "mdns",
                "NodeID": 1,
                "ListenIP": "::",
                "Timeout": 5,
                "LimitConfig": {"ConnLimit": 4},
            }
        ],
    }
    (OUT / "v2bx.json").write_text(json.dumps(node, indent=2))
    server = spawn(
        "v2bx",
        [
            str(Path(ARGS.v2bx).resolve()),
            "server",
            "--watch=false",
            "-c",
            str(OUT / "v2bx.json"),
        ],
    )
    for _ in range(60):
        if "Nodes started" in (OUT / "v2bx.log").read_text():
            break
        if server.poll() is not None:
            raise RuntimeError("V2bX startup failed")
        time.sleep(0.1)
    spawn(
        "queue",
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
    spawn(
        "client",
        [
            "docker",
            "exec",
            "-e",
            "GOMAXPROCS=2",
            CLIENT,
            "/audit/runtime/mdns-client",
            "-config",
            "/audit/mdns-proof/client.toml",
        ],
    )
    conn = None
    for _ in range(50):
        try:
            conn = socks_connect("192.0.2.2", 29001)
            break
        except (OSError, RuntimeError):
            time.sleep(0.2)
    if conn is None:
        raise RuntimeError("native MDNS connection did not become ready")
    up, down = 101, 307
    conn.sendall(struct.pack("!II", up, down) + b"B" * up)
    data = receive(conn, down)
    assert data == b"Z" * down, "MDNS payload corrupted"
    report = {
        "tcp_payload_verified": True,
        "expected_upload": up + 8,
        "expected_download": down,
        "private_target_refused": None,
    }
    for _ in range(35):
        command(
            "docker",
            "exec",
            "irboard-v2bx-e2e-panel",
            "php",
            "artisan",
            "traffic:update",
        )
        after = snapshot()["users"][uid]
        delta = [after["u"] - before["u"], after["d"] - before["d"]]
        if delta == [up + 8, down] and (after.get("alive") or {}).get("alive_ip"):
            break
        time.sleep(0.2)
    report["actual_delta"] = delta
    report["online"] = after.get("alive")
    report["exact_traffic"] = delta == [up + 8, down]
    # The native local proxy can return a successful optimistic SOCKS reply
    # before the remote guard rejects the target. Judge payload forwarding,
    # and first establish that this private destination actually is reachable.
    with socket.create_connection(("172.28.90.5", 29001), timeout=5) as direct:
        direct.sendall(struct.pack("!II", up, down) + b"B" * up)
        assert receive(direct, down) == b"Z" * down
    blocked = None
    try:
        blocked = socks_connect("172.28.90.5", 29001)
        blocked.sendall(struct.pack("!II", up, down) + b"B" * up)
        report["private_target_refused"] = receive(blocked, down) != b"Z" * down
    except (OSError, RuntimeError):
        report["private_target_refused"] = True
    finally:
        if blocked is not None:
            blocked.close()
    conn.close()
    (OUT / "result.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2), flush=True)
    assert report["exact_traffic"] and report["private_target_refused"], (
        "native proof failed"
    )


if __name__ == "__main__":
    try:
        main()
    finally:
        subprocess.run(
            [
                "docker",
                "exec",
                "irboard-v2bx-e2e-panel",
                "php",
                "artisan",
                "queue:restart",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for name in reversed(created):
            if name == ECHO:
                with (OUT / "echo.log").open("w") as log:
                    subprocess.run(
                        ["docker", "logs", name], stdout=log, stderr=log, check=False
                    )
            subprocess.run(
                ["docker", "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
