# Irboard's nodes on every V2bX core — review 2026-11-07

Every node Irboard's admin forms make, served as Irboard serves it, on every
V2bX core that can serve it, reached by the clients Irboard's subscriptions
configure.

## How it was tested

`Irboard/tests/Feature/ServedNodeContractTest.php` saves 35 nodes through the
admin forms' own routes, posted as the browser's form encoder sends them:

- VLESS over TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP and mKCP, with TLS,
  REALITY, Vision and VLESS encryption;
- VMess over TCP, TCP with the HTTP header, WebSocket, gRPC, mKCP,
  HTTPUpgrade and XHTTP;
- Trojan over TCP, WebSocket and gRPC;
- Shadowsocks with AEAD and 2022 ciphers;
- Hysteria, Hysteria2 (plain, Salamander, bandwidth), TUIC and AnyTLS
  (TLS and REALITY).

It exports what the panel then serves (`api/panel/testdata/irboard/served.json`):
- the node's config and user list from UniProxy, as V2bX fetches them;
- the subscriber's Clash Meta proxy, sing-box outbound and share link.

`cmd/irboard_served_test.go` starts each node through V2bX's node controller,
from that config and user list, on each core the setup wizard accepts for it:
xray, sing, mihomo and hysteria2. Three clients then connect through each one:
- mihomo, with the Clash Meta proxy;
- sing-box, with the outbound;
- Xray, with the share link.

Each client sends TCP to an echo server, and UDP to two (`internal/udpecho`):
a short datagram, one of 1350 bytes as QUIC sends, and one to the second
server over the same session, as full-cone clients (STUN, games) send. A
control run pointing every client at a port with no node behind it failed all
of them, so the datagrams do go through the node.

`TestIrboardServedNodesRefuseBlockedDatagrams` then gives a node of each UDP
encoding (XUDP for VLESS, with and without Vision, and VMess; Trojan;
Shadowsocks and Shadowsocks 2022; Hysteria; Hysteria2; TUIC; AnyTLS's UDP over
TCP) a panel rule blocking the second echo server's port. Every client opens a
session at the first server, sends to the second, and must get no answer while
the session keeps working.

CI runs both without build tags under the race detector, and again with the
release tags.

## Bugs found and fixed

In V2bX:

1. **Every WebSocket, HTTPUpgrade and HTTP node on the sing core refused every
   user, from v1.10.0 on.**
   - Cause: sing-box hands a connection taken over from an HTTP request on with
     a fresh context (`v2rayhttp.DupContext`), which dropped the node
     generation V2bX's hook requires.
   - Effect: the hook closed each connection without a word. TCP and gRPC
     nodes kept working.
   - Fix: `DupContext` now keeps the request's values and drops only its
     cancellation (sing-box patch), and the hook logs such a refusal.
2. **VLESS REALITY nodes with `xtls-rprx-vision` refused every user on the
   sing core.**
   - Cause: the fork's VLESS inbound uses `github.com/wyx2685/sing-vmess`,
     whose Vision knew only crypto/tls and xtls/reality connections. sing-box
     1.13's REALITY server makes metacubex/utls ones.
   - Why it mattered: the wizard places these nodes on the sing core.
   - Fix: a pinned copy in `third_party/sing-vmess` registers them.
3. **Shadowsocks 2022 nodes on the sing core refused connections from loopback.**
   - Who: local tunnels, and the relay whenever its PROXY header and the
     client's first bytes shared a segment.
   - Cause: the PROXY-protocol reader read ahead into 52 bytes, and Shadowsocks
     2022 takes its 59- or 75-byte request header from one read.
   - Fix: the reader now reads ahead up to 4 KiB, then hands reads to the
     connection (sing-box patch).
4. **The Hysteria2 core let users reach anything the node can reach**: its own
   services on 127.0.0.1, its private network and the provider's metadata
   address. It also applied none of the panel's audit rules.
   - Fix: a destination guard now refuses private addresses, and blocked
     domains, addresses, ports and UDP. It checks each TCP connection, each UDP
     session and each datagram.
   - Both the hysteria2 and xray cores now take `AllowPrivateDestinations`, as
     the sing and Mihomo cores do.
   - The warning a node logs when its core does not apply the panel's rules
     went on counting every rule for this core. It now counts only what the
     guard does not apply: protocol rules other than UDP, which needs
     sniffing, and outbound routes.
5. **Xray core (xray patch):**
   - mKCP read a connection's receive buffer outside the lock its teardown
     takes: a data race whenever a node's listener closed.
   - Vision kept the TLS connection's address in a uintptr and turned it back
     into pointers, which Go's pointer checks end the process for under the
     race detector.
   - The gRPC client could run `CloseSend` during a `Send`.
6. **sing-box's gRPC client** read its response reader while another goroutine
   set it (sing-box patch).
7. **The sing and xray cores checked a UDP session's first destination only.**
   - A full-cone session (XUDP, Trojan, Shadowsocks, Hysteria, Hysteria2, TUIC,
     AnyTLS) names each datagram's destination, and the core sends it there.
     The panel's rules, and on the sing core the private-address block,
     judged the destination the session opened with.
   - Effect: a user blocked from a port or an address reached it by sending
     one datagram somewhere allowed first. On the sing core the same reached
     the node's own UDP services on 127.0.0.1 and its private network.
   - Fix: the sing hook checks each datagram the client sends
     (`core/sing/datagram_guard.go`); the xray dispatcher drops each datagram
     whose own destination the rules refuse (`udprules.go`), freedom already
     applying the private-address block per datagram. A refused datagram is
     dropped and the session goes on. The mihomo and hysteria2 cores already
     checked each destination.
8. **HTTPUpgrade nodes on the sing core lost what clients send right behind
   the upgrade request** (sing-box patch).
   - Cause: the server took the connection over with `Hijack` and dropped the
     reader it returns, which holds what Go's HTTP server had read ahead.
   - Who: Xray's client (v2rayN, v2rayNG) sends its protocol header right
     behind the request; over a real network the two arrive together. mihomo
     sends right after the 101 and was hit when its bytes arrived before the
     hijack. VMess answered "bad request" and closed the connection.
   - Fix: the server hands those bytes to the handler first, as its HTTP
     transport already did.
9. **A data race on every Hysteria2 node's UDP on the mihomo core.** sing-quic
   times out each UDP session with metacubex/sing's canceler, whose activity
   time the session's reader and V2bX's reply writer both wrote with no lock.
   A pinned copy (`third_party/metacubex-sing`) takes upstream sing's fix.

In Irboard:

10. **HTTPUpgrade nodes went to mihomo-based clients and sing-box as plain
   TCP**, which the node refuses. They are now WebSocket with
   `v2ray-http-upgrade` for mihomo, and sing-box's `httpupgrade` transport.
   Stash, which has no HTTPUpgrade, leaves them out.
11. **mKCP nodes**, VMess and VLESS, went to mihomo, Stash and sing-box as plain
   TCP to a UDP port. None of them has mKCP, so these nodes are now left out.
   Sing-box also no longer gets VLESS encryption nodes, which it cannot speak.
12. **sing-box and Hiddify could not use VMess TLS nodes on the Xray core.**
   - Cause: sing-box reads the cipher `auto` as `zero` over TLS, and Xray 26
     accepts only `aes-128-gcm` and `chacha20-poly1305`.
   - Fix: profiles and share links now name `aes-128-gcm` for a TLS node, or
     the cipher the admin chose.
13. **XHTTP nodes with padding obfuscation refused every mihomo client (400).**
    - Cause: mihomo has no defaults for where the padding goes, and sent none.
    - Fix: the profile now names Xray's defaults (`x_padding`, `X-Padding`,
      `queryInHeader`, `repeat-x`) unless the node sets its own.
14. **Clash Verge and Nyanpasu** built a node's VLESS encryption string with an
    operator-precedence error. It only showed where a setting was missing.
15. **VMess UDP from mihomo-based clients and sing-box was bound to its first
    destination.** Their profiles left XUDP off, so a second destination
    (STUN, games) over the same socket never answered, on every core. The
    profiles now name XUDP, which every V2bX core serves, as Xray clients and
    the VLESS profiles already used.

## Not covered

- Clients other than mihomo, sing-box and Xray, such as Stash, Shadowrocket,
  Surge, Loon and Quantumult X. For Stash, only what its profile leaves out
  is checked.
- The sing core's per-datagram private-address block is checked by a unit
  test only (`core/sing/datagram_guard_test.go`): a test has no public address
  to open a UDP session at. The panel-rule path runs end to end.
- sing-box's full gRPC client (`with_grpc`, which the test links) never gives
  up on a node that does not answer. That is a client's own problem, not a
  node's: V2bX serves gRPC and does not dial it, and sing-box's own builds use
  the lite gRPC client.
- The Hysteria2 core applied no per-user speed limit when this was written.
  It does since the review of 2026-11-12
  (`docs/billing-and-removal-review-2026-11-12.md`).
- sing-box's own VLESS client fails Go's pointer checks in Vision, so the run
  with the release tags runs without the race detector.
