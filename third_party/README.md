# Pinned protocol sources

These local modules preserve the exact dependency versions selected by V2bX.
They carry small concurrency repairs without requiring a dependency upgrade.

| Local module | Upstream version | Changed source |
| --- | --- | --- |
| `sing-anytls` | [`github.com/anytls/sing-anytls@v0.0.11`](https://github.com/anytls/sing-anytls/tree/v0.0.11) | `service.go`: publish an immutable authentication table atomically; acknowledge a new stream (SYNACK) when it opens rather than after the dial; close a stream whose destination cannot be read. `session/session.go`: a control frame's write deadline covers only its own write; data larger than one frame is split |
| `sing-shadowsocks` | [`github.com/sagernet/sing-shadowsocks@v0.2.8`](https://github.com/SagerNet/sing-shadowsocks/tree/v0.2.8) | `shadowaead_2022/service_multi.go`: publish PSK, identity and cipher tables as one immutable generation |
| `sing-quic` | [`github.com/sagernet/sing-quic@v0.6.5`](https://github.com/SagerNet/sing-quic/tree/v0.6.5) | `tuic/service.go`: publish paired user/password tables atomically and admit one authentication stream per session |

Original licenses, module manifests and all other upstream files are retained.
`upstream-manifest.json` records every original file and both its upstream and
patched SHA256 for all 133 original files. The four declared source files are
the only changes to upstream files; the added TUIC and AnyTLS regression tests
are recorded separately with their hashes.
`go.mod` in the repository root selects these modules with relative replacements;
the upstream version requirements remain unchanged.

The Shadowsocks repair retains existing UDP NAT and session state. Authentication
and response encryption use the same table generation, and input keys are copied
before publication. AnyTLS readers use a single immutable password table. An
optional authenticated-session callback lets the patched sing-box inbound close
physical pooled sessions when their user is removed. TUIC readers obtain the
user and password from the same generation, and a compare-and-swap prevents two
authentication streams from closing the session's authentication signal twice.
None of these repairs holds a user-update lock during network I/O.

The AnyTLS weak-link repairs: a v2 client closes a reused session unless the
server acknowledges a new stream within three seconds, and the acknowledgement
used to wait for sniffing, DNS and the destination's dial, so slow sites and
lossy links killed healthy sessions (`core/sing/anytls_synack_test.go`). A
control frame's five-second deadline was set on the whole connection before
taking the write lock, cutting data writes still draining over a slow link and
then closing the session; and a write over 65535 bytes went out as one frame
with a wrapped length (`sing-anytls/session/write_test.go`).

Real protocol regressions live in `core/sing/ss2022_audit_test.go` and
`core/sing/anytls_users_audit_test.go`. Recheck these tests and the provenance
manifest when changing these pinned sources. The separate stable-identity fix
in Xray's Shadowsocks 2022 inbound is pinned by the root replacement to
`github.com/PoriyaVali/Xray-core@v1.260909.1`; the physical AnyTLS/TUIC retirement
fixes are pinned to `github.com/PoriyaVali/sing-box@v1.13.21-v2bx.2`.
