# Irboard / V2bX integration audit

This opt-in harness runs Irboard's actual Webman workers, MariaDB 10.6, Redis,
the real queue worker and a release-tagged V2bX binary. It creates nodes through
the admin HTTP API. The Mihomo client reads each user's actual subscription;
its TCP/UDP connections cross a separate Docker network namespace before they
reach the node. The native MasterDnsVPN client checks MDNS separately.

Use a disposable Linux Docker host. The harness owns these fixed resource
names and ports, so only one deployment can run at a time:

| Resource | Name or address |
| --- | --- |
| Panel | `irboard-v2bx-e2e-panel`, Webman on `127.0.0.1:6600` |
| Database | `irboard-v2bx-e2e-db`, database `irboard_e2e`, `127.0.0.1:23306` |
| Cache and queue | `irboard-v2bx-e2e-redis`, `127.0.0.1:26379` |
| Report recorder | `127.0.0.1:18080` |
| Client network | `irboard-v2bx-e2e-clients`, `172.28.90.0/24` |
| Main and second clients | `irboard-v2bx-e2e-client`, `irboard-v2bx-e2e-second-client` |
| Test certificate identity | `node.e2e.test`, signed by a local private CA |

`prepare.py --reset` reloads the dedicated database from `install.sql` and
clears the dedicated Redis instance. It also replaces test identities and
certificates. The working directory's ownership marker must be present before
an existing deployment can be reset. Do not point this harness at an installed
panel or reuse its resource names for another service.

## Requirements and build

- Go 1.27.1 or a compatible toolchain satisfying `go.mod`.
- Python 3.9+, OpenSSL, Git and a local Docker daemon.
- A checkout of the companion Irboard changes, with Composer dependencies
  installed **including development autoloading** (`Tests\\Fixtures` supplies
  fictional protocol examples).
- A PHP 8.2 CLI image with the panel's extensions, including MySQL, Redis,
  igbinary, mbstring, bcmath, curl, XML, pcntl and OPcache. The audit environment
  uses `irboard-php82-test:latest`; select an equivalent image with `--php-image`.
  The panel starts with its checked-in `cli-php.ini` and two Webman workers.
- Docker images `mariadb:10.6` and `redis:7-alpine`.

Run these commands from the V2bX checkout. Set `panel_source` to the companion
Irboard checkout and keep the absolute `audit_work` path for later commands.
No local scratch wrapper is required:

```sh
panel_source=/absolute/path/to/Irboard
audit_work=$(mktemp -d /tmp/irboard-v2bx-e2e.XXXXXX)
mkdir -p "$audit_work/runtime"

export GOEXPERIMENT=jsonv2
python3 scripts/prepare_tls_dependencies.py --allow-download \
  > "$audit_work/runtime/tls-preparation.json"
audit_mod=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_mod"])' \
  "$audit_work/runtime/tls-preparation.json")
audit_tags='sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor mdns trusttunnel mihomo'

go build -mod=readonly -modfile="$audit_mod" -tags "$audit_tags" \
  -ldflags '-X github.com/PoriyaVali/V2bX/cmd.version=v0.0.0-e2e' \
  -o "$audit_work/runtime/V2bX" .
go build -mod=readonly -modfile="$audit_mod" \
  -o "$audit_work/runtime/client" ./scripts/e2e/mihomo/client
go build -mod=readonly -modfile="$audit_mod" \
  -o "$audit_work/runtime/mdns-client" masterdnsvpn-go/cmd/client

python3 scripts/e2e/mihomo/prepare.py \
  --work "$audit_work" --panel "$panel_source" \
  --php-image irboard-php82-test:latest
python3 scripts/e2e/mihomo/run.py \
  --work "$audit_work" \
  --v2bx "$audit_work/runtime/V2bX" \
  --client "$audit_work/runtime/client" \
  --php-image irboard-php82-test:latest
```

The TLS dependency preparation selects verified dependency repairs through its
returned modfile. A plain build without that modfile does not reproduce the
release's dependency graph. Build/runtime network access must use the host's
configured proxy and CA trust; test traffic stays on the local Docker network.

Archive the previous `logs/` and `results/` before repeating the audit. A full
run changes user credentials, eligibility and certificate serials, so rerun
preparation with `--reset` before another full matrix:

```sh
python3 scripts/e2e/mihomo/prepare.py \
  --work "$audit_work" --panel "$panel_source" --reset
```

The additional node-control phase checks destination-port rules, the traffic
rate multiplier and changing a node's listening port. Run it after the full
matrix has stopped, using a separate evidence directory so the main outcomes
remain intact. It reads current database counters as its baseline and does not
reset the panel:

```sh
controls_work="$audit_work/evidence/final-controls"
mkdir -p "$controls_work/logs" "$controls_work/results"
cp -a "$audit_work/runtime" "$audit_work/certs" "$controls_work/"
python3 scripts/e2e/mihomo/run.py \
  --work "$controls_work" --controls-only \
  --v2bx "$controls_work/runtime/V2bX" \
  --client "$controls_work/runtime/client"
```

Render the final Persian report and consolidated JSON from the recorded
evidence without starting or changing services:

```sh
python3 scripts/e2e/mihomo/report.py \
  --work "$audit_work" --controls-dir "$controls_work"
```

The outputs are `results/report-fa.md` and `results/consolidated.json`. The
report command exits nonzero when required coverage is missing, a recorded
check failed or its recorded accounting values contradict its success flag.

## What is checked

Preparation creates all 25 protocol variants exposed by the tested panel,
including separate Hysteria 1/2 variants in their shared native table.

| Server path | Protocols |
| --- | --- |
| Embedded Mihomo | HTTP, SOCKS5, Mieru, ShadowQUIC, VMess, VLESS, Trojan, TUIC, Hysteria2, AnyTLS, TrustTunnel |
| Existing Sing core | Shadowsocks, Hysteria 1 |
| Existing native core | MDNS with the MasterDnsVPN client |
| Catalog entries without a managed server | SSR, Snell, WireGuard, GOST Relay, SSH, Sudoku, MASQUE, OpenVPN, Tailscale, ZeroTier, EasyTier |

The last row is checked for an explicit unsupported-server response, currently
HTTP 501. Creating an external profile does not establish a multi-user server
implementation for that protocol.

The main matrix checks:

- Actual subscription credentials, TCP payloads and supported UDP payloads.
- Directional byte counts from the client through the node and queue into
  MariaDB, including per-user isolation and final reports.
- Real panel online-device records, heartbeat and load metadata.
- A lost report acknowledgement: the panel accepts the first report and the
  recorder drops its reply; retries must retain the report ID and bill once.
- Limits changed through the panel while a connection stays open: measured
  1 Mbps pacing followed by an upgrade on the same session.
- Ban/unban, expired accounts and exhausted quotas: active sessions close,
  cached credentials stop working and restored accounts can reconnect.
- Concurrent forwarding limits and a device limit using two real source IPs.
- A temporary panel outage, invalid traffic counter types and secret rotation.
- CA/hostname-verified certificates actually served on TCP and QUIC; partial
  cert/key replacement, valid live rotation, an unrelated-domain candidate and
  recovery. TrustTunnel's TCP and QUIC paths are both probed.
- ShadowQUIC's unauthenticated QUIC probe reaching its real local decoy without
  charging that infrastructure traffic to a subscriber.

MDNS uses its native client configuration obtained from the panel's node API;
it is not a Mihomo outbound. Its separate checks report their own outcome.
The matrix is evidence for the configurations it exercises, not every possible
transport, routing option, operating system or failure sequence.

## Evidence and cleanup

`results/summary.json` and `results/checks.jsonl` contain the complete outcomes.
`logs/panel-exchanges.jsonl` records the actual server API exchanges without
logging token query parameters. The client, V2bX, queue worker and traffic
drain have separate logs. Generated subscriptions and the source/binary
provenance manifest let a reviewer identify the tested build and inputs.

Keep private CA/server keys, `runtime/panel.env`, admin tokens and runtime
configuration out of shared evidence bundles. The fixtures use fictional
accounts, but their credentials still grant access to this local deployment.

The runner stops its temporary V2bX/client processes. The panel, MariaDB and
Redis remain available for inspection. After archiving the evidence, remove
only the deployment's named resources:

```sh
docker rm -f irboard-v2bx-e2e-client irboard-v2bx-e2e-second-client \
  irboard-v2bx-e2e-panel irboard-v2bx-e2e-db irboard-v2bx-e2e-redis
docker network rm irboard-v2bx-e2e-clients
docker network rm irboard-v2bx-mdns-targets
```

Certificate probes use a private local CA. They establish domain validation,
live file replacement and failure retention; they do not establish public
HTTP-01/DNS-01 issuance, DNS propagation, public reachability or renewal by a
real public authority for an operator's domain. Shared certificate-manager
tests cover due/not-due decisions, retries and issuance with a local issuer.
Public ACME validation remains a separate deployment check.
