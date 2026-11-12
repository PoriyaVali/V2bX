# Xray TLS lifecycle patch

This is an uncommitted local patch against the exact dependency already pinned
by V2bX: `github.com/PoriyaVali/Xray-core v1.260909.1`, origin commit
`2d862f10203e86890ff035fc25516ca3193edb6f`. Its package module path remains
`github.com/xtls/xray-core`. The original source and MPL-2.0 LICENSE are retained
in the isolated prepared source; no third-party source license is replaced.
`xray-tls-lifecycle.json` records the module checksums and hashes of each changed
file. Apply the accompanying patch only after verifying those base hashes.

The ordinary TLS server path previously replaced a shared certificate pointer
without synchronization, permanently stopped reloading after a transient file
read failure, and published expired or unrelated certificate pairs. Local,
verified TLS handshakes reproduced the latter two failures against the pinned
source before modification. Existing V2bX decoy tests already document and skip
the pointer race under the race detector.

The patch changes ordinary serving certificates to immutable snapshots selected
through synchronized sources. File checks happen on new handshakes, at most
every five seconds (a shorter configured OCSP interval is also honored), and
retry after invalid or missing files. Complete pairs must be currently valid
and permit TLS server authentication. V2bX supplies its configured certificate
domain as the required identity, so renewal can discard obsolete extra SANs.
Generic callers without that explicit identity retain every DNS/IP identity
of the original pair. SNI matching uses SAN verification,
including the usual single-label wildcard rule. Unknown or absent SNI retains
the existing fallback policy unless `rejectUnknownSni` is enabled.

OCSP refreshes publish a new snapshot asynchronously and use a client with a
ten-second timeout. No certificate file watcher/ticker survives after its TLS
config is retired. One-time loading continues to avoid reloading or OCSP work.

V2bX separately validates enabled `file`, `http`, `dns`, and `self` modes before
starting an Xray inbound. This does not issue certificates from within Xray;
the shared certificate manager owns that work. Explicit `none` retains the
existing external TLS termination policy.

Local validation completed with Go 1.27.1, `GOEXPERIMENT=jsonv2`, and an alternate
modfile selecting the prepared fork without changing the normal pinned graph:

- `TestServingCertificate*` plus existing local `TestCertificateIssuing`,
  `TestExpiredCertificate`, and `TestInsecureCertificates`: race detector PASS.
- Actual verified TLS handshakes cover missing file recovery, mismatched and
  malformed pair retention, expiry rejection, SAN identity retention,
  different CN, wildcard boundaries, serial 1 -> 2, and concurrent rotations.
- V2bX `TestXray_TLSCertificateModesUseSameLivePaths`,
  `TestXray_RejectsInvalidTLSBeforeNodeStart`, and
  `TestXray_TLSLiveCertificateRotationWithoutRestart`: race detector PASS.
  These start real VMess, VLESS, and Trojan inbounds and verify their served
  certificates with a local CA.
- `git apply --check` against the pristine cached pinned module: PASS.

A full upstream TLS-package test was attempted and FAILED in the inherited
`TestECHDial`, which makes public DNS/Cloudflare requests and panicked on a
malformed ECHConfigList. It is not a passing offline package check; subsequent
commands explicitly select local tests. An initial direct-module compilation
requested an uncached transitive dependency; subsequent validation used the
parent's cached graph with `GOPROXY=off` and `GOSUMDB=off`.

Scope limits: public ACME issuance/renewal, public OCSP services, every Xray
transport, authority-issuance mode, and callers of the legacy exported
`BuildCertificates` snapshot helper were not validated by this patch. The
ordinary V2bX-generated encipherment TLS path uses the new source. Public
issuance tests and production deployment are not claimed. The normal pinned
dependency graph remains unchanged until the reproducible patch-preparation
workflow explicitly selects the prepared sources.

## mKCP receive buffer and Vision pointers

Two more repairs ride on this patch.

`transport/internet/kcp/receiving.go`: `ReadMultiBuffer` and `Read` took and
kept a partly read segment (`leftOver`) outside the worker's lock, which
`Release` clears it under when a connection is torn down. Closing a node's
mKCP listener while a connection was being read was a data race, which the
race detector reported (`receiving_release_test.go` reproduces it). Both now
work under the lock.

`proxy/vless/inbound/inbound.go` and `proxy/vless/outbound/outbound.go`: Vision
kept the TLS connection's address in a uintptr and turned it back into
pointers to the connection's input buffers. Go does not allow that conversion,
and its pointer checks, on under the race detector, end the process at the
first Vision connection. The address is now carried as an `unsafe.Pointer`
and offset with `unsafe.Add`. V2bX's `cmd/irboard_served_test.go` runs VLESS
Vision over TLS and REALITY, and mKCP, under the race detector.

`transport/internet/grpc/encoding/hunkconn.go` and `multiconn.go`: closing a
gRPC connection called `CloseSend` while its writer could still be in `Send`,
which a gRPC client stream does not allow, and the race detector reported it.
Both are now serialized by a send lock; `Close` still cancels the stream first,
so a `Send` held up by flow control returns (`closesend_test.go`).

`proxy/proxy.go`: a Vision connection's reader and its writer each run
`XtlsFilterTls` on what passes and read what it has learned (how many packets
are left to look at, whether the stream is TLS, whether to switch to direct
copy), on their own goroutines and with no lock. That is a data race on every
Vision connection carrying TLS in both directions at once, which is nearly all
of them; the served-node tests met it as soon as they sent TLS through a
Vision node while reading. The state is now behind a lock, and the writer
takes one consistent view of it for each write
(`vision_filter_race_test.go`).
