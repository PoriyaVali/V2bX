# Pinned protocol sources

These local modules preserve the exact dependency versions selected by V2bX.
They carry small concurrency repairs without requiring a dependency upgrade.

| Local module | Upstream version | Changed source |
| --- | --- | --- |
| `sing-anytls` | [`github.com/anytls/sing-anytls@v0.0.11`](https://github.com/anytls/sing-anytls/tree/v0.0.11) | `service.go`: publish an immutable authentication table atomically |
| `sing-shadowsocks` | [`github.com/sagernet/sing-shadowsocks@v0.2.8`](https://github.com/SagerNet/sing-shadowsocks/tree/v0.2.8) | `shadowaead_2022/service_multi.go`: publish PSK, identity and cipher tables as one immutable generation |

Original licenses, module manifests and all other upstream files are retained.
`upstream-manifest.json` records every original file and both its upstream and
patched SHA256. The two declared source files are the only upstream deviations.
`go.mod` in the repository root selects these modules with relative replacements;
the upstream version requirements remain unchanged.

The Shadowsocks repair retains existing UDP NAT and session state. Authentication
and response encryption use the same table generation, and input keys are copied
before publication. AnyTLS readers use a single immutable password table. Neither
repair holds a user-update lock during network I/O.

Real protocol regressions live in `core/sing/ss2022_audit_test.go` and
`core/sing/anytls_users_audit_test.go`. Recheck these tests and the provenance
manifest when changing either pinned source. This vendoring does not resolve the
separate mutable user-index issue in Xray's Shadowsocks 2022 inbound.
