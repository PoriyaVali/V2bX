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

Use `scripts/prepare_tls_dependencies.py` to verify the complete pinned source
and apply the patch into an isolated directory. Test and release workflows
explicitly select the resulting alternate modfile. Standard `go.mod`/`go.sum`
retain upstream provenance; plain Go commands without the alternate modfile
do not select the repair. No published dependency or production change claimed.
