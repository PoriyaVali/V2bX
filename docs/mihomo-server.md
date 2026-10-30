# Mihomo server core

The `mihomo` core embeds the server listeners in
[`PoriyaVali/mihomo`](https://github.com/PoriyaVali/mihomo). It runs a separate
listener, authentication table, limiter bridge, and traffic ledger for each
panel node. It does not start Mihomo's client proxy ports or HTTP controller.

## Supported protocols

| Panel node type | TCP payloads | UDP payloads | Server settings |
|---|---|---|---|
| `http` | CONNECT and HTTP proxy | No | Optional TLS |
| `socks5` | Yes | Authenticated UDP association | Optional TLS |
| `mieru` | Yes | UDP over its session | TCP or UDP transport |
| `shadowquic` | Yes | Yes | Explicit JLS decoy required |
| `vmess`, `vless` | Yes | Yes | TCP, WebSocket, gRPC; optional TLS |
| `trojan` | Yes | Yes | TCP, WebSocket, gRPC; TLS required |
| `tuic`, `hysteria2`, `anytls` | Yes | Yes | TLS required |
| `trusttunnel` | Yes | Yes | Embedded HTTP/2 and QUIC; TLS required |

Irboard's four new server types require the companion managed-server panel
change. Select **Manage users with V2bX / Mihomo** in the node form. Leave the
username and password blank, or use `{{uuid}}`; the panel renders each user's
subscription and the server renders the same credentials. `{{user_id}}` is
also recognized, for example in a readable username, but it is a public
sequence number: the username or the password must contain `{{uuid}}` (a blank
field means `{{uuid}}`), so a node with only `{{user_id}}` credentials is
rejected. Fixed credentials shared by multiple subscribers are rejected.
The HTTP listener attributes each request to the identity its connection
verified; a request whose credentials fail is refused rather than billed to
the account it names.
The panel's client certificate/private-key fields are never server key paths.
Configure V2bX against the root node ID; children inherit its subscription
settings and are not separate managed listeners.

The existing protocol types can explicitly select `Core: "mihomo"`; their
other core implementations remain available. This core does not implement
SSR, WireGuard, GOST Relay, SSH, MASQUE, OpenVPN, Tailscale, ZeroTier, EasyTier,
or Hysteria v1 servers. Snell, Sudoku, and this fork's Shadowsocks listener use
one server key and are not exposed as separately billable multi-user nodes.

## Configuration

Build with the `mihomo` tag in addition to other desired cores. Docker and
release builds include it. The fork root and its patched smux submodule are pinned to the same commit;
Go does not inherit replacements from dependencies. The usual TLS dependency
preparation still applies:

```sh
python3 scripts/prepare_tls_dependencies.py --allow-download
# Use the returned audit_mod for go build/test, as in the CI workflow.
```

An example configuration (replace placeholders locally):

```json
{
  "Log": {"Level": "info"},
  "Cores": [{"Type": "mihomo", "DialTimeout": 10, "UDPTimeout": 120}],
  "Nodes": [{
    "Core": "mihomo",
    "ApiHost": "https://panel.example.com",
    "ApiKey": "YOUR_PANEL_KEY",
    "NodeType": "socks5",
    "NodeID": 1,
    "ListenIP": "::",
    "CertConfig": {
      "CertMode": "file",
      "CertDomain": "node.example.com",
      "CertFile": "/etc/V2bX/certs/fullchain.pem",
      "KeyFile": "/etc/V2bX/certs/private.key"
    }
  }]
}
```

`CertConfig` is required when the panel enables TLS, including embedded
TrustTunnel. Normal V2bX issuance, renewal, and file certificate modes apply.
The certificate loader is scoped to the configured server key pair and reloads
renewed files without widening Mihomo's global safe paths.
The shared loader validates the configured `CertDomain`, validity dates, server
authentication usage and matching private key before serving a replacement.
An invalid or partially written replacement retains the latest valid pair.
The same policy applies to SOCKS-over-TLS and to the fork's TCP/QUIC listeners.

For `http` and `dns` certificate modes, V2bX checks every six hours and renews
within 30 days of expiry; failed attempts are retried on subsequent checks.
`file` mode consumes externally issued files: their external owner, such as
Certbot, must renew them. Configure the domain you control in `CertDomain`;
the wizard does not infer certificate ownership from a different client SNI.

For ShadowQUIC add per-node options:

```json
{"MihomoOptions":{"JLSUpstream":{"Addr":"decoy.example.com:443","SNI":"decoy.example.com"}}}
```

The decoy must actually serve QUIC. Its infrastructure packets are separate
from subscriber billing. The configure wizard supports the Mihomo core and
`--mihomo-jls-upstream` / `--mihomo-jls-sni`. Use `--cert-domain` when the
panel does not provide a certificate hostname.

Private, loopback, link-local, multicast, and unspecified destination addresses
are denied by default. For intentionally reachable private services set
`AllowPrivateDestinations: true` in the **core** configuration. Unspecified and
multicast destinations remain denied. DNS results are checked and the checked
IPs are dialed directly, avoiding another lookup between validation and dialing.
TCP tries them in resolver order, and an unreachable address family falls back
to the other one after 300 ms. A UDP flow resolves and dials on its own
goroutine, so a slow lookup delays only that flow.
`SendIP`, user/node speed limits, dynamic speed updates, connection caps,
device admission, and panel domain/IP/port blocks are supported.

## Lifecycle and current limits

Upload is subscriber-to-destination payload; download is destination-to-subscriber
payload. Protocol/TLS headers are excluded. Reports atomically drain counters;
removed identities keep their original panel UID until both ledgers drain.
Online addresses and separate per-device traffic reports come from live flows.
TCP forwarding preserves half-close when the transport supports it, including
responses returned after request EOF. Revocation closes active TCP/UDP forwarding,
and retirement waits for final
accounting before returning its last report.

An empty eligible-user list leaves the listener port closed. SOCKS UDP uses a
separate relay per authenticated TCP association, pins its source IP/port, and
closes its forwarding flows when the control connection ends. The source IP is
the control connection's. The port is the one UDP ASSOCIATE requests when the
request names that IP, as RFC 1928 clients do; otherwise, as for clients behind
NAT or older sing-based clients naming their first destination, it is the first
datagram's. UDP NAT keys keep
SDK session identities and relay addresses, so simultaneous streams sharing a
source socket remain isolated. A UDP mapping expires after `UDPTimeout`
without traffic in either direction. Queues are
bounded, with at most 16 MiB of queued outbound UDP payload per node.

HTTP, SOCKS5, Mieru and ShadowQUIC nodes change users in place: a user joining
or leaving disconnects nobody else. A removed user's TCP/UDP forwarding closes
and admission refuses the name at once, so a Mieru or ShadowQUIC session or an
HTTP keep-alive connection the user still holds can open nothing new. The node
remembers removed names with their passwords, at most 4,096, and replaces the
listener when one returns with another password (a username template without
`{{uuid}}` does that when a UUID is reset), so such a session cannot regain
access under the name. Gaining a first or losing a last user also replaces it.
The other protocols' SDK authentication tables are fixed when their listener
starts, so their membership changes rebuild that node's listener and disconnect
its sessions; clients must reconnect. Removing users the node does not have
changes nothing. Rebuilds and retirement close the node's sockets before
awaiting its flows, so a client that stopped reading cannot hold one up with a
blocked write; an in-place removal does not wait for the removed flows.
Other nodes are isolated. Preparation failures keep the existing listener;
bind failures attempt rollback and return any rollback error. Speed/device
limit edits do not rebuild listeners or disconnect established sessions.

Panel REALITY/ECH/VLESS encryption translation, XHTTP and other transports,
custom panel DNS, custom outbound routes, sniffed-protocol blocks, and
`RejectUnknownSni` are currently rejected with explicit errors. Client-only
outbound options are not automatically server settings. The core has no V2bX
cover-site integration. These limits are not advertised as supported features.

## Validation

`core/mihomo` tests use real fork clients, TLS certificates, TCP sockets, and
UDP echo servers. They cover all 11 protocols, optional TLS, Mieru UDP
transport, exact byte direction/counts, active revocation and re-admission,
in-place membership changes that keep other users' TCP and UDP sessions,
final reports, bidirectional TCP half-close, separate node/UID ledgers, device admission, destination rules,
and measured 1 Mbps transfers with an upgrade on the same open connection.
Run them with the prepared module graph and `go test -race ./core/mihomo`.

`TestMihomoVerifiedCertificateRotation` uses a private CA and hostname-verified
handshakes for all nine certificate-based protocols, including both TCP and
QUIC on TrustTunnel. It checks initial identity, rejection of a wrong client
hostname, live replacement, retention after a wrong-domain candidate and later
recovery. Shared certificate-manager tests simulate HTTP/DNS issuance, renewal
and authority failure. These local tests do not establish public HTTP-01/DNS-01
challenge success for an operator's real domain.

Panel decoding and wizard tests cover the configuration contract. The fork's
own server regression tests additionally exercise concurrent AnyTLS and
VLESS Vision stream shutdown.

The [opt-in full-stack audit](../scripts/e2e/mihomo/README.md) runs actual
Webman, MariaDB, Redis, queue workers and V2bX with clients on a separate
Docker network. It creates all 25 panel protocol types and distinguishes the
14 available server protocols from the 11 profiles without a managed server.
Its report includes subscription-based TCP/UDP transfers, exact database
accounting, admission limits, account eligibility, live certificate changes
and the native MDNS client. The harness uses only disposable data and a local CA.

Changes are reviewable code; no production deployment or release is implied.
