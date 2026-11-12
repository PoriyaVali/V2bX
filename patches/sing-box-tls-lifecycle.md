# Sing TLS lifecycle repair

Local repair of exact pinned `github.com/PoriyaVali/sing-box`
`v1.13.21-v2bx.2`; package module path `github.com/sagernet/sing-box` is unchanged.
The JSON records module checksums and exact before/after source hashes. The
upstream license and all unchanged sources remain in the prepared module.

Actual VMess, VLESS, Trojan and AnyTLS handshakes reproduced data races between
`STDServerConfig.Server` and certificate pointer replacement. Independent file
callbacks could also update cached cert/key bytes concurrently. The repair
locks configuration reads, serializes reloads, reads both files together and
publishes only complete currently valid server certificates. An explicit domain
must remain covered; client-only EKUs are rejected. Bad candidates retain the
previous pair.

Relative paths are anchored before watching them. A local handshake check, at
most once per second, also handles missed notifications and external symlink
changes. Unchanged bytes are neither reparsed nor logged.

The earlier hypothesis that QUIC kept a stale config was disproved: its
`GetConfigForClient` callback follows the current config. Actual Hysteria1,
Hysteria2 and TUIC QUIC rotation passed on the original source. That hypothesis
is not a confirmed defect.

## PROXY-protocol reader and Shadowsocks 2022

The fork's PROXY-protocol reader (`common/listener/proxyproto.go`) sniffs every
connection from a loopback peer for a v2 header. It read ahead into a 52-byte
buffer and served the protocol above from that buffer first. Shadowsocks 2022
takes its whole request header, 59 or 75 bytes after the salt, from its first
read, and answers a split one with "bad header". So with `ProxyProtocol` on,
the node default, every Shadowsocks 2022 connection from loopback was refused:
a local tunnel's, which sends no header, and the relay's, whenever its header
and the client's first bytes arrived in one segment. Legacy AEAD ciphers,
VMess, VLESS, Trojan and the TLS-based protocols read their headers in full and
were unaffected.

The reader now reads ahead up to 4 KiB, which is whatever arrived first, as one
read of the socket would return it. Once the read-ahead is drained it reads the
connection directly and releases the buffer. `proxyproto_test.go` gains the
fork-level regression. V2bX's `core/sing/ss2022_proxy_protocol_test.go` runs
real Shadowsocks 2022 clients from loopback, with and without a header; both
failed before.

## Context of connections taken over from HTTP

`transport/v2rayhttp.DupContext` gives the WebSocket, HTTPUpgrade and HTTP
transports the context of each connection they take over from an HTTP request.
It started again from `context.Background()` and kept only the log ID, so every
value the inbound had set was lost on these transports, while TCP and gRPC
kept them. V2bX marks each listener's connections with the node generation
they belong to (`core/sing/retirement.go`), and since v1.10.0 the hook has
refused a connection without one. So every user of a VLESS, VMess or Trojan
node over WebSocket, HTTPUpgrade or HTTP was refused, and nothing reached the
log.

`DupContext` now returns `context.WithoutCancel(ctx)`: the request's values,
without the cancellation that comes when the handler returns.
`conn_context_test.go` is the fork-level regression.
`core/sing/http_transports_test.go` runs real clients through V2bX's sing core
over each transport; all of them failed before. The hook now logs a
connection it refuses for a missing generation.

## gRPC client reader

`transport/v2raygrpclite/conn.go`: a gRPC client connection gets its reader
when the response arrives, on another goroutine, and `read` tested the reader
for nil while that goroutine set it. That was a data race on every gRPC
connection a sing-box client made. `read` now waits on the connection's
`create` channel, which is set when the connection is made and closed by
`setup` (`conn_setup_test.go`).

## What follows an HTTPUpgrade request

`transport/v2rayhttpupgrade/server.go`: the server answered 101 and took the
connection over with `Hijack`, dropping the reader it returns. Go's HTTP server
reads the request through a buffer, and reads ahead while the handler runs, so
whatever the client sent right behind its request was in that reader. Xray's
client (v2rayN, v2rayNG) writes the proxy protocol's header right behind the
request and reads the 101 later; mihomo sends right after the 101, which can
still arrive before the hijack. Those bytes were lost: the tunnel began
mid-stream, VMess answered "bad request" and closed the connection. The server
now hands them to the handler first, as `v2rayhttp`'s server does
(`server_buffered_test.go`). `cmd/irboard_served_test.go` failed on it about
once in thirty runs under the race detector; over a real network, where the
request and the header arrive together, it is the common case.

## Closing a gRPC connection on the server

`transport/v2raygrpc/server.go` (the gRPC transport of builds with `with_grpc`,
which V2bX's are): a server-side connection's `Close` did nothing. A gRPC
stream ends when its handler returns, and the handler waited only for the
connection's own handler to finish. So closing a connection to end it, as V2bX
does when the panel removes a user, left the stream open and its reads waiting
for the client. The removed user kept the connection, and V2bX, which waits for
a closed connection's reads to end before it settles the user's traffic,
waited with it: the node applied no other change to its users until that
client went away. A user removed and added back in that time could not
connect. `Tun` now returns when the connection is closed
(`server_close_test.go`).

Use `scripts/prepare_tls_dependencies.py` to verify the complete pinned source
and apply the patch into an isolated directory. Test and release workflows
explicitly select the resulting alternate modfile. Standard `go.mod`/`go.sum`
retain upstream provenance; plain Go commands without the alternate modfile
do not select the repair. No published dependency or production change claimed.
