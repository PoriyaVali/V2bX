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
| `sudoku` | Yes | UDP over TCP | Master key from the panel; HTTP mask modes; cover site |
| `snell` | Yes | Versions 3-5 | ShadowTLS v3 required |
| `vmess`, `vless` | Yes | Yes | TCP, WebSocket, gRPC; optional TLS |
| `trojan` | Yes | Yes | TCP, WebSocket, gRPC; TLS required |
| `tuic`, `hysteria2`, `anytls` | Yes | Yes | TLS required |
| `trusttunnel` | Yes | Yes | Embedded HTTP/2 and QUIC; TLS required |

Irboard's six managed server types require the companion managed-server panel
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
or Hysteria v1 servers. This fork's Shadowsocks listener uses one server key
and is not exposed as a separately billable multi-user node.

### Sudoku

A Sudoku server derives its obfuscation tables and AEAD keys from a public key,
and a client from the public key its key belongs to. Each subscriber holds
their own split `r || x-r` of the node's master private key `x`, and the hash
of the split, sent in the client hello, names the user. The panel generates
the master key, sends it to the node, and renders each user's split; V2bX
derives the same splits from the master key and the users' UUIDs
(`core/mihomo/sudoku.go`, `app/Protocols/Mihomo/SudokuKeys.php` in Irboard)
and accepts only the current users' hashes. An unlisted split, the bare public
key and any other master are refused before the replay cache keeps state.
Every holder of a split can recover the master: it keeps strangers out and
tells users apart, while the per-user secret is the UUID inside the split.
A user who can read another user's traffic can learn that user's hash; use
TLS (an HTTP mask tunnel behind a CDN) where users share a network path.

All HTTP mask modes (legacy, stream, poll, auto, ws), session mux and UDP over
TCP are supported, and connections through HTTP tunnels and mux streams carry
the client's address for device limits and online reports. A failed handshake
is relayed to the node's cover site, so a prober finds a web site; set
`"DecoySite": false` to close such connections instead. The node has no TLS;
`http-mask-tls` profiles need a CDN or TLS proxy in front of it.

### Snell

Snell has no user identity, and its argon2 key derivation makes trying every
user's PSK per connection too slow. A managed Snell node therefore requires
ShadowTLS v3 (`obfs-opts` mode `shadow-tls`, version 3 and a host): its
handshake names the user, whose PSK, also their ShadowTLS password, opens the
Snell stream. The handshake, and any stranger in strict mode, is relayed to the
host on port 443, or to `MihomoOptions.ShadowTLSHandshake`:

```json
{"MihomoOptions":{"ShadowTLSHandshake":"127.0.0.1:8443"}}
```

That server must serve TLS 1.3 with the host's certificate, which clients
verify. Such relays stay outside the traffic ledger; past 4 MiB in a direction
they are held to 64 KiB/s. Clients must support Snell over ShadowTLS: Surge,
and Mihomo (v1.19.33 and this fork) do. Versions 3 to 5 carry UDP.

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
  "Cores": [{"Type": "mihomo", "Log": {"Level": "warn"}, "DialTimeout": 10, "UDPTimeout": 120}],
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

ShadowQUIC hands probers to a real QUIC site. By default that is the SNI the
panel gives the clients, on port 443, so set the node's SNI to a domain whose
site serves HTTP/3. To use another site add per-node options:

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
device admission, and panel domain/IP/port and protocol blocks are supported.
Protocol rules, and domain rules for a connection made to an address, apply to
what sniffing finds, with the sniffers and 300 ms timeout of the sing core: TLS
and QUIC SNI, the HTTP Host, BitTorrent, DNS, SSH, RDP, STUN, DTLS and NTP. A
QUIC ClientHello split across packets is followed until it names its server. A
`udp` protocol rule refuses every UDP flow. Only a node with such a rule sniffs,
and never on the server-first SMTP, IMAP and POP3 ports, so other connections
do not wait for their client's first bytes.

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

HTTP, SOCKS5, Mieru, ShadowQUIC, Sudoku and Snell nodes change users in place:
a user joining or leaving disconnects nobody else. A removed user's TCP/UDP forwarding closes
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
custom panel DNS, custom outbound routes, and `RejectUnknownSni` are
currently rejected with explicit errors. Client-only
outbound options are not automatically server settings. Of this core's
listeners, only Sudoku's fallback uses the V2bX cover site. These limits are
not advertised as supported features.

## Validation

`core/mihomo` tests use real fork clients, TLS certificates, TCP sockets, and
UDP echo servers. They cover all 13 protocols, optional TLS, Mieru UDP
transport, Sudoku HTTP mask modes and mux, Snell versions over ShadowTLS v3, exact byte direction/counts, active revocation and re-admission,
in-place membership changes that keep other users' TCP and UDP sessions,
final reports, bidirectional TCP half-close, separate node/UID ledgers, device admission, destination rules,
sniffed protocol and domain rules on every protocol's TCP streams and on UDP,
including a split QUIC ClientHello,
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

## Logs and node health

`v2bx log` shows the Mihomo core's lines with `core=mihomo` and the node's
`tag`. The core's own `Log.Level` decides how much: `warn` (the default) shows
refused clients, such as a Sudoku key of another master or a request that does
not match the HTTP mask; `info` adds each refused user (device or connection
limit) and each request a panel rule blocks; `debug` adds every connection.
Repeated warnings of one kind are cut to ten a minute, and the next line says
how many were dropped. Log lines name users by their panel ID, never by their
credentials. Lines about the node itself, such as a listener that opens with
its address and user count, follow V2bX's own `Log.Level`.

A Mihomo node keeps its port closed while the panel lists nobody who may use
it, and logs when it opens and closes it. A port another program or node
already holds is reported as such.

When the panel deletes a node, V2bX stops serving it at once, closes its port
and logs one warning; it keeps checking quietly and serves the node again if
the panel has it again. A node that has no users' traffic to report still
reports, empty, so the panel shows it as healthy. Each status report carries
the node's health: whether it serves, how many users it has, and its current
problem, such as a port in use or a certificate that cannot be issued.
