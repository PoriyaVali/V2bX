#!/usr/bin/env python3
"""Prepare only the named, disposable local integration deployment.

Requires the PHP test image (PHP 8.2 with MySQL/Redis/pcntl and panel extensions),
MariaDB 10.6, Redis 7, a checked-out Irboard and its installed vendor directory.
The marker prevents resetting a directory not created for this audit.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(*args, **kwargs):
    return subprocess.check_output(list(map(str, args)), text=True, **kwargs).strip()


def exists(name):
    return (
        subprocess.run(
            ["docker", "inspect", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--php-image", default="irboard-php82-test:latest")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    work = Path(args.work).resolve()
    source = Path(args.panel).resolve()
    if work == source or work / "panel" == source:
        raise SystemExit(
            "The audit workspace must be separate from the source checkout."
        )
    work.mkdir(parents=True, exist_ok=True)
    marker = work / ".isolated-irboard-v2bx-e2e"
    resources = work / "runtime/resources.json"
    known = json.loads(resources.read_text()) if resources.exists() else {}
    owned = marker.exists() and marker.read_text() == "disposable irboard_e2e only\n"
    if (work / "panel").exists() and not owned:
        raise SystemExit("Refusing to replace an unowned panel checkout.")
    names = [
        "irboard-v2bx-e2e-panel",
        "irboard-v2bx-e2e-db",
        "irboard-v2bx-e2e-redis",
        "irboard-v2bx-e2e-clients",
    ]
    for name in names:
        if not exists(name):
            continue
        identity = run("docker", "inspect", "--format", "{{.Id}}", name)
        if not owned or known.get(name) != identity:
            raise SystemExit("Refusing to reuse unowned resource: " + name)
    if any(exists(name) for name in names) and not args.reset:
        raise SystemExit(
            "Existing deployment: use its original work directory and --reset."
        )
    marker.write_text("disposable irboard_e2e only\n")
    for name in ["runtime", "logs", "results", "certs"]:
        (work / name).mkdir(exist_ok=True)
    if exists("irboard-v2bx-e2e-panel"):
        run("docker", "rm", "-f", "irboard-v2bx-e2e-panel")
    source_head = run("git", "-C", source, "rev-parse", "HEAD")
    if (work / "panel").exists() and run(
        "git", "-C", work / "panel", "rev-parse", "HEAD"
    ) != source_head:
        run("git", "-C", source, "worktree", "remove", "--force", work / "panel")
    if not (work / "panel").exists():
        run("git", "-C", source, "worktree", "add", "--detach", work / "panel", "HEAD")
    # Include the reviewed local runtime bridge when auditing before commit.
    for relative in ["start.php", "app/Http/WebmanRequest.php"]:
        if (source / relative).exists():
            (work / "panel" / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, work / "panel" / relative)
    files = [
        "start.php",
        "webman.php",
        "app/Http/WebmanRequest.php",
        "database/install.sql",
    ]
    provenance = {
        "source_head": run("git", "-C", source, "rev-parse", "HEAD"),
        "worktree_base_head": run("git", "-C", work / "panel", "rev-parse", "HEAD"),
        "runtime_files_sha256": {
            name: hashlib.sha256((work / "panel" / name).read_bytes()).hexdigest()
            for name in files
            if (work / "panel" / name).exists()
        },
    }
    (work / "runtime/panel-provenance.json").write_text(
        json.dumps(provenance, indent=2)
    )
    env = [
        "APP_NAME=IrboardE2E",
        "APP_ENV=local",
        "APP_DEBUG=false",
        "APP_KEY=base64:" + base64.b64encode(b"e" * 32).decode(),
        "APP_URL=http://127.0.0.1:6600",
        "DB_CONNECTION=mysql",
        "DB_HOST=127.0.0.1",
        "DB_PORT=23306",
        "DB_DATABASE=irboard_e2e",
        "DB_USERNAME=root",
        "DB_PASSWORD=isolated-e2e-root",
        "REDIS_HOST=127.0.0.1",
        "REDIS_PORT=26379",
        "REDIS_PREFIX=irboard_e2e_",
        "CACHE_PREFIX=irboard_e2e_cache",
        "CACHE_DRIVER=redis",
        "QUEUE_CONNECTION=redis",
        "SESSION_DRIVER=array",
        "MAIL_DRIVER=log",
        "V2BX_E2E_ISOLATED=1",
    ]
    (work / "runtime/panel.env").write_text("\n".join(env) + "\n")
    (work / "runtime/panel.env").chmod(0o600)
    (work / "panel/config/v2board.php").write_text(
        "<?php return ['app_name'=>'Irboard E2E','secure_path'=>'e2e-admin','server_token'=>'isolated-e2e-node-token','server_push_interval'=>1,'server_pull_interval'=>1,'server_node_report_min_traffic'=>0,'server_device_online_min_traffic'=>0,'device_limit_mode'=>0,'show_info_to_server_enable'=>0,'show_subscribe_method'=>0];\n"
    )
    for relative in [
        "storage/logs",
        "storage/framework/cache/data",
        "storage/framework/sessions",
        "storage/framework/views",
        "bootstrap/cache",
    ]:
        (work / "panel" / relative).mkdir(parents=True, exist_ok=True)
    if not exists("irboard-v2bx-e2e-db"):
        run(
            "docker",
            "run",
            "-d",
            "--name",
            "irboard-v2bx-e2e-db",
            "-p",
            "127.0.0.1:23306:3306",
            "-e",
            "MARIADB_ROOT_PASSWORD=isolated-e2e-root",
            "-e",
            "MARIADB_DATABASE=irboard_e2e",
            "mariadb:10.6",
        )
    if not exists("irboard-v2bx-e2e-redis"):
        run(
            "docker",
            "run",
            "-d",
            "--name",
            "irboard-v2bx-e2e-redis",
            "-p",
            "127.0.0.1:26379:6379",
            "redis:7-alpine",
            "redis-server",
            "--save",
            "",
            "--appendonly",
            "no",
        )
    run("docker", "start", "irboard-v2bx-e2e-db", "irboard-v2bx-e2e-redis")
    # A first start answers ping from the entrypoint's temporary server, before
    # the root password and database exist; wait until both are usable.
    for _ in range(120):
        if (
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "irboard-v2bx-e2e-db",
                    "mariadb",
                    "-uroot",
                    "-pisolated-e2e-root",
                    "--protocol=tcp",
                    "irboard_e2e",
                    "-e",
                    "SELECT 1",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        ):
            break
        time.sleep(0.5)
    with (source / "database/install.sql").open() as schema:
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                "irboard-v2bx-e2e-db",
                "mariadb",
                "-uroot",
                "-pisolated-e2e-root",
                "irboard_e2e",
            ],
            stdin=schema,
            check=True,
        )
    run("docker", "exec", "irboard-v2bx-e2e-redis", "redis-cli", "FLUSHALL")
    if not exists("irboard-v2bx-e2e-clients"):
        run(
            "docker",
            "network",
            "create",
            "--subnet",
            "172.28.90.0/24",
            "irboard-v2bx-e2e-clients",
        )
    run(
        "docker",
        "run",
        "-d",
        "--name",
        "irboard-v2bx-e2e-panel",
        "--network",
        "host",
        "--cpuset-cpus",
        min(os.sched_getaffinity(0)),
        "--env-file",
        work / "runtime/panel.env",
        "-v",
        str(work / "panel") + ":/app",
        "-v",
        str(source / "vendor") + ":/app/vendor:ro",
        "-v",
        str(HERE) + ":/e2e:ro",
        "-v",
        str(work / "certs") + ":/certs:ro",
        "-w",
        "/app",
        args.php_image,
        "php",
        "-c",
        "cli-php.ini",
        "webman.php",
        "start",
    )
    resources.write_text(
        json.dumps(
            {
                name: run("docker", "inspect", "--format", "{{.Id}}", name)
                for name in names
            },
            indent=2,
        )
    )
    (work / "runtime/php-image").write_text(args.php_image)
    seed = json.loads(
        run("docker", "exec", "irboard-v2bx-e2e-panel", "php", "/e2e/panel.php", "seed")
    )
    (work / "runtime/seed.json").write_text(json.dumps(seed, indent=2))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(path, body=None, token=None):
        request = urllib.request.Request(
            "http://127.0.0.1:6600" + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                **({"Authorization": token} if token else {}),
            },
        )
        with opener.open(request, timeout=15) as response:
            return json.load(response)

    login = None
    last_error = None
    for _ in range(40):
        try:
            login = api(
                "/api/v1/passport/auth/login",
                {"email": "admin@e2e.invalid", "password": "isolated-e2e-password"},
            )
            break
        except OSError as error:
            last_error = error
            time.sleep(0.25)
    if login is None:
        raise RuntimeError("Webman login did not become ready: " + str(last_error))
    token = login["data"]["auth_data"]
    (work / "runtime/admin-token").write_text(token)
    creation = []
    for protocol, row in seed.items():
        route = "hysteria" if protocol == "hysteria2" else protocol
        response = api(
            "/api/v1/e2e-admin/server/" + route + "/save", row["payload"], token
        )
        creation.append({"protocol": protocol, "status": 200, "response": response})
    (work / "results/node-creation.json").write_text(json.dumps(creation, indent=2))
    nodes = api("/api/v1/e2e-admin/server/manage/getNodes", token=token)
    (work / "runtime/nodes.json").write_text(json.dumps(nodes, indent=2))
    cert = work / "certs"
    (cert / "extensions.cnf").write_text(
        "subjectAltName=DNS:node.e2e.test,DNS:localhost,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n"
    )
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(cert / "ca.key"),
            "-out",
            str(cert / "ca.pem"),
            "-days",
            "365",
            "-subj",
            "/CN=Local Irboard V2bX E2E CA",
        ],
        check=True,
        **quiet,
    )
    for name, serial in [("node", 101), ("decoy", 201)]:
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
                str(cert / (name + ".key")),
                "-out",
                str(cert / (name + ".csr")),
                "-subj",
                "/CN=node.e2e.test",
            ],
            check=True,
            **quiet,
        )
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(cert / (name + ".csr")),
                "-CA",
                str(cert / "ca.pem"),
                "-CAkey",
                str(cert / "ca.key"),
                "-set_serial",
                str(serial),
                "-out",
                str(cert / (name + ".pem")),
                "-days",
                "90",
                "-extfile",
                str(cert / "extensions.cnf"),
            ],
            check=True,
            **quiet,
        )
    for key in cert.glob("*.key"):
        key.chmod(0o600)
    print(
        "Created",
        len(nodes["data"]),
        "real panel nodes; isolated deployment ready.",
        flush=True,
    )


if __name__ == "__main__":
    main()
