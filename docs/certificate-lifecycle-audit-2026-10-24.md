# Certificate recognition and renewal audit â€” 2026-10-24

Codex/root and scoped Codex agents audited the exact V2bX `v1.9.2` source,
`bb5ccfca6b9d56c0269d6bafe9bdc639a6db0191`. Fresh connected GitHub reads on
2026-10-24 still identified that commit as `dev_new` and Latest `v1.9.2`.
Changes described below are **uncommitted local candidates**, not a deployed
or published release. Earlier TrustTunnel patch delivery remains unchanged.

## Finding

The original release cannot be described as correctly renewing every TLS
certificate. A successful issuance, a successful file replacement, and a new
certificate actually served to clients are three different checks. Real local
TLS/QUIC handshakes and the race detector exposed defects beyond the initial
TrustTunnel configuration issues.

| Generated node path | Recognition and live replacement tested | Renewal ownership after this local repair |
| --- | --- | --- |
| Sing VMess, VLESS, Trojan, AnyTLS | Real CA/hostname-verified TCP TLS, old/new serials without restarting; race fixed | Shared manager for HTTP/DNS/self; external tool for file mode |
| Sing Hysteria1, Hysteria2, TUIC | Real CA/hostname-verified QUIC, old/new serials without restarting | Same shared manager; the existing QUIC dynamic-config callback already handled replacement |
| Xray VMess, VLESS, Trojan | Real CA/hostname-verified TCP TLS for all four enabled modes; invalid replacements retain the working certificate | Shared manager; repaired dependency reload retries after missing/bad files |
| Dedicated Hysteria2 | Real QUIC, automatic TCP cover and configured HTTPS masquerade; all four modes and expanded paths | Shared manager plus domain-aware loader; file mode remains externally managed |
| TrustTunnel | Local manager, immutable snapshot and reload-queue tests; two real Linux tests compiled but **not executed** | Shared manager for `letsencrypt`/self; provided files polled and validated every five seconds |
| REALITY, Shadowsocks, mDNS, plaintext | No local inbound X.509 certificate managed by this path | No local certificate renewal applicable; external TLS termination remains external |

`file`/`provided` means V2bX loads a certificate issued and renewed by an external
owner, such as Certbot. It does not imply V2bX requests a replacement from a CA.
`none` retains the existing external-termination/plaintext policy; dedicated
Hysteria2 rejects it because that core requires TLS.

## Repairs and decisions

- Extracted a shared `common/certmanager` so the embedded cores and TrustTunnel
  use the same account persistence, local due checks, issuance and installation.
  Managed certificates are checked every six hours and renewed within the
  exact 30-day window. Failed managed TrustTunnel renewals retry hourly.
- Reject mismatched keys, wrong configured SAN, expired/future-dated leaves,
  and certificates whose EKU does not allow server authentication. A failed
  candidate cannot overwrite an active managed pair. Self certificates cover
  numeric IP SANs correctly, and combined cert/key PEM paths are supported.
- A long-lived self-signed certificate no longer satisfies a switch to
  HTTP/DNS ACME mode. Renewal requests only the explicitly configured domain,
  including explicit DNS wildcards; HTTP wildcards are rejected. Xray follows
  the configured domain during renewal, permitting obsolete incidental SANs
  to be removed. Without an explicit identity its generic source preserves
  the original SAN identities.
- Serialize shared-path issuance and self generation. Reject conflicting
  managed path/domain ownership before starting nodes. Read-only multi-SAN
  file sharing remains possible; independent automatic owners must not
  overwrite one another's files.
- Update renewal scheduling when node security/mode changes. Prepare a new
  certificate before retiring a working listener. On failure, keep the
  published old node information while still enforcing subscriber revocations.
- TrustTunnel no longer relies on its native wizard for ACME. The inspected
  native wizard issued once and discarded account credentials; the endpoint
  neither renewed nor watched certificate files. The shared manager now owns
  issuance/renewal. The wizard receives validated immutable snapshots, and a
  serialized hosts-file commit queues SIGHUP safely during startup. Partial
  external updates cannot be loaded accidentally by an unrelated user sync.
- Sing dependency repair synchronizes TLS config reads and concurrent file
  reload callbacks, validates both files together and anchors relative paths.
  A bounded local fallback catches missed notifications. Xray's dependency
  repair replaces unsynchronized pointers and a reload loop that stopped
  permanently on a transient read error with immutable retryable snapshots.
- Atomic file replacement retries short Windows sharing conflicts without
  deleting the active file. Real Windows handle-sharing tests exercise both
  transient recovery and permanent-error preservation.

The initial Sing QUIC stale-pointer hypothesis was **disproved** by real
Hysteria1/Hysteria2/TUIC rotation tests. The actual confirmed Sing defect was
concurrent TCP handshake/config access and concurrent cert/key callbacks.

## Reproducible build graph

The pinned upstream versions in `go.mod`/`go.sum` are unchanged. Repaired source
patches, base/patched hashes and module checksums live in `patches/`.
`scripts/prepare_tls_dependencies.py` verifies the complete pinned module and
prepared trees, preserves licenses, rejects tampered output, and selects them
through a separate modfile. Test/release workflow source now explicitly runs
this preparation. Hosted workflows have **not** been run for this candidate.

From this repository, with a Go toolchain satisfying `go.mod`:

```sh
python3 scripts/prepare_tls_dependencies.py > /tmp/v2bx-tls-preparation.json
MODFILE=$(python3 -c 'import json; print(json.load(open("/tmp/v2bx-tls-preparation.json"))["audit_mod"])')
GOEXPERIMENT=jsonv2 go test -mod=readonly -modfile="$MODFILE" -race -tags with_quic \
  ./common/certmanager ./common/file ./common/tlscert ./common/decoy \
  ./conf ./api/panel ./node ./core/sing ./core/xray ./core/hy2 ./core/trusttunnel ./cmd
```

Preparation is offline by default. Add `--allow-download` to permit retrieval
of missing pinned modules. A plain Go command without the returned modfile
still selects the original unpatched dependencies and must not be presented
as testing this repair.

## Validation actually performed

Go 1.27.1, `GOEXPERIMENT=jsonv2`, Windows amd64, race detector and `with_quic`:

- Final twelve-package combined run passed: **575 pass events including
  subtests, four skip events, zero failures**. The skips were two public ACME
  tests, one command test requiring a built host executable, and one Linux
  socket test. Two historical Xray TLS race skips were removed; both tests
  passed in the final combined run and in a separate targeted race run.
- Shared HTTP/DNS tests use an injected local issuer, a private CA, and actual
  verified TLS handshakes. They exercise issuance, account reuse, exact renewal
  scope, due/not-due behavior, failures preserving bytes, subsequent recovery,
  and serving the replacement serial. They do **not** prove a public challenge.
- Dedicated Hysteria2 tests exercise QUIC and both TCP certificate consumers;
  Sing covers four TCP and three QUIC protocols; Xray covers three TCP protocols.
- Scoped `go vet` passed. Full all-release-tags Linux amd64 build passed.
  Both native TrustTunnel Linux integration tests cross-compiled successfully.
- Nine preparation safety tests, complete module checksum/source-hash checks,
  a second independent prepared tree, idempotent `--check`, and both modified
  workflow YAML parses passed. Original `go.mod` and `go.sum` stayed unchanged.
- Explicit local Xray dependency TLS tests passed under race. An earlier full
  upstream TLS-package attempt failed in an inherited external ECH test; the
  full upstream package is **not** recorded as passing.

Preserved failed/limited checks include original Sing race reproduction,
initial generic-manager and Hysteria2 path/mode failures, stale metadata
rejection, Windows Git CRLF conversion during preparation, and an initially
unquoted PowerShell modfile argument that failed before tests started. These
were corrected before the final checks. Raw unified-patch context indentation
received a patch-data-only whitespace attribute; repaired Go source formatting
and exact source hashes remain checked. The prior Windows loader rename
failure is recorded in history; its sharing-error path now has passing tests.

## Remaining evidence required

1. Run both `TestNativeEndpoint_` integration tests on Linux with trusted
   compatible `trusttunnel_endpoint` and `setup_wizard` binaries. The tests
   check actual authentication, initial sync, provided-certificate rotation,
   partial-update preservation, and unchanged PID. This Windows environment
   has no working native Linux runtime, so execution remains unverified.
2. Public HTTP-01/DNS-01 issuance, propagation, renewal, network reachability
   and OCSP were not tested against production authorities/providers. The
   local issuer tests cannot establish those operational conditions.
3. Custom original core configuration, every transport/ECH branch, Xray
   authority-issuance mode and externally managed renewal tools were not all
   exercised. The matrix describes standard panel-generated server paths.
4. In-flight Lego/DNS work is not cancelled by closing the periodic task;
   shutdown can wait for provider/network timeouts. TrustTunnel keeps prior
   immutable snapshots for recovery; automatic pruning is not implemented.

No commit, push, published release, firewall change, live-node restart or
production certificate operation was performed. The findings invalidate a
blanket claim about `v1.9.2`; the tested local repair is reviewable, with the
operational limits above still explicit.
