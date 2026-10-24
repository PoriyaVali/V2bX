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
