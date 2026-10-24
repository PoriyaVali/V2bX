# TrustTunnel certificate and installer audit — 2026-10-23

Historical audit of the first local patch. The current candidate's certificate
ownership and renewal behavior is superseded by
[the all-core lifecycle audit](certificate-lifecycle-audit-2026-10-24.md).
In particular, TrustTunnel now uses the shared manager instead of native-wizard
ACME issuance. The previously delivered October 23 artifact remains unchanged.

Codex inspected V2bX baseline `bb5ccfc` and the local TrustTunnel source at
`5796f6870f4915b313de44c2e2de93a4c72f7a4a`. This report distinguishes source
inspection from executed tests. The changes described here are uncommitted;
they have not been released or installed on a live server.

## Startup and user synchronization repairs

The coordinated patch also honors `Options.ListenIP` with bracketed IPv6
formatting, rejects unknown certificate modes before executing the wizard,
and gives that subprocess a five-minute bound without logging its secrets.

Every endpoint launch now replaces stale credentials before starting the
process. When the panel has no users, a fresh unadvertised 256-bit password
keeps the native authenticator installed. An empty file is not an alternative:
the inspected native parser rejects it, and a failed reload retains old users.
The same random sentinel therefore handles removal of the final user.

Credential replacement, launch and reload signalling are serialized. A sync
between native credentials parsing and readiness remains pending and is
replayed when that exact process becomes ready. Readiness from a previous
process cannot signal a replacement process. Invalid panel credentials are
rejected before altering existing user state; snapshots use private unique
temporary files and atomic replacement.

`core/trusttunnel/native_integration_test.go` provides an opt-in Linux test with
real binaries and loopback traffic. It gates a successful metrics response to
place the first user update deterministically after native credentials parsing
but before V2bX readiness, then checks HTTP/2 CONNECT authentication and echo,
unknown/bootstrap rejection, final-user revocation, re-addition and unchanged
PID. The test was cross-compiled, **not executed** in this Windows environment.

```sh
V2BX_TEST_TRUSTTUNNEL_BIN=/path/to/endpoint-and-wizard \
  go test ./core/trusttunnel -run '^TestNativeEndpoint_' -count=1 -timeout=2m -v
```

The directory must contain trusted compatible `trusttunnel_endpoint` and
`setup_wizard` binaries. Public ACME issuance is not part of this loopback test.

## Certificate ownership and hostname selection

| Path | Source evidence | Result |
| --- | --- | --- |
| Guided and unattended native TLS setup | `cmd/configure.go`, `cmd/configure_certificate.go`, `cmd/configure_certificate_test.go` | Certificate issuance uses the node's `Common.Host` or an explicit/saved certificate domain. SNI is displayed separately and is not an ACME fallback. Existing table tests cover AnyTLS, VLESS, VMess, Trojan, TUIC, Hysteria and Hysteria2 in both setup modes. |
| Sing TLS protocols | `core/sing/node.go`, `getInboundOptions` | The common TLS branch assigns `CertFile` and `KeyFile` to a TLS options container shared by VMess, VLESS, Trojan, AnyTLS, TUIC, Hysteria and Hysteria2. REALITY uses its own branch. This was inspected; this audit did not run a separate authenticated session through every protocol. |
| Xray TLS | `core/xray/inbound.go` | The TLS branch assigns both paths to Xray's certificate configuration. REALITY has a separate configuration. |
| Dedicated Hysteria2 | `core/hy2/config.go`, `getTLSConfig` | The server obtains its certificate through `common/tlscert.Loader`, using both configured paths. Empty/none modes fail. |
| TrustTunnel | `api/panel/node.go`, `core/trusttunnel/config.go`, `cmd/configure.go` | The panel's `hostname`, `cert_type`, `acme_email`, `cert_chain_path` and `cert_key_path` control the endpoint wizard. TrustTunnel deliberately skips the generic certificate builder. Its hostname is not inferred from the panel's SNI or `Common.Host`. |
| mDNS and Shadowsocks | `api/panel/node.go` | These node types are marked without TLS. The certificate setup branch does not apply to them. |

`conf.CertConfig.ExpandPaths` substitutes `{domain}` and `{email}` before the
cores consume file paths. `node.validCertificatePair` verifies the loaded key
pair, validity period and configured certificate domain. This is shared native
certificate validation, not validation of TrustTunnel's panel-provided files.

Explicit `Core: "trusttunnel"` is cleared by the generic options decoder, but
`core/selector.go` deliberately reparses and pins cores without private options.
This was checked and is not an additional failure in the normal selector path.

## Installer defect corrected

Previously `trusttunnel_cert_prereqs` treated a missing certificate mode and
every unknown mode as self-signed. It could therefore tell the administrator
that the panel selected self-signed when the panel did not. It also continued
configuration with missing required email or paths.

Changes in `install.sh`:

- Accept self-signed only when the panel explicitly returns `self-signed`.
- Reject empty, null, missing and unknown modes without printing the untrusted
  mode, raw response or panel URL/token.
- Reject missing/whitespace-only Let's Encrypt email or provided certificate
  paths before firewall preparation or configuration replacement.
- Propagate failure from the manual configuration wizard, preserving the
  existing configuration and backup.

The existing offline policy is preserved: if the panel cannot be reached, the
manual wizard warns that its certificate prerequisites are unverified. A
nonempty but unreadable provided path still produces a warning so the operator
can copy the files before starting the endpoint. These checks do not validate
the contents of provided certificate/key files or guarantee public port 80
reachability. Endpoint startup remains responsible for loading the files.

The existing dependency-free shell extraction remains a limited JSON probe,
not a complete JSON parser. The Go panel decoder and core perform runtime
validation; installer messages are preliminary guidance.

## Validation performed for this audit

All shell tests below executed extracted real installer functions with mocked
network/service/firewall operations. No live installer, live panel, ACME order
or firewall modification was executed.

- `bash -n install.sh scripts/test-trusttunnel-cert-prereqs.sh`: passed.
- `bash scripts/test-trusttunnel-cert-prereqs.sh`: 17 cases passed, including
  valid modes, offline fallback, invalid/missing required fields, secret
  non-disclosure and preservation of the manual wizard's config and backup.
- `bash scripts/test-config-wizard.sh`: all five existing cases passed.
- Go 1.27.1: `go test ./conf ./api/panel -run
  'Certificate|Cert|Options|TrustTunnel|IRBoard|AnyTlsSecurity' -count=1`: passed
  the matching tests. Because the contract test uses `Irboard` capitalization,
  it was also explicitly run below.
- Go 1.27.1: `go test ./api/panel -run
  'TestIrboardGeneratedContract|TestGetNodeInfo_TrustTunnelHasIPv6|TestAnyTlsSecurityFromPanel'
  -count=1`: passed.
- Go 1.27.1: `go test ./common/tlscert -run
  'TestLiveTLSKeepsLastPairDuringReplacementAndRotatesWithoutRestart|TestDomainRejectsPathsIPsAndInvalidLabels'
  -count=1`: passed. The first test exercises a real local TLS handshake,
  retaining the active certificate during a broken replacement and selecting
  a new pair after rotation.
- `go test ./common/tlscert -count=1`: **failed on Windows** in
  `TestLoaderConcurrentSelectionAndRotation`: replacing the certificate by
  `os.Rename` while concurrent readers held it open returned `Access is denied`.
  This audit did not change the loader or atomic writer. The full package is
  not recorded as passing on Windows.
- A coordinated broad `go test -race ./core/hy2` run failed in
  `TestHy2_DefaultCoverOwnsTCPAndRetiresWithUDP` and
  `TestHy2_CoverTCPCanBeDisabled`. Inspection established an inherited test
  port-selection limitation: `freeUDPPort` checks UDP availability only, while
  these tests also need the same TCP port. `Get-NetTCPConnection` showed
  pre-existing TCP listeners on `0.0.0.0`/`::` port 49670 (PID 1316) and 49671
  (PID 4332), exactly the ports selected by the failed tests. The first probe
  reached the existing non-TLS service; the second TCP bind was denied. Neither
  port was in the Windows TCP excluded range (50000–50059). A focused rerun of
  both tests with `-race -count=1 -v` passed using newly allocated ports. No
  Hysteria2 production code was changed; the original broad failure is not
  described as a passing run.
- The first Go attempt with the default Go 1.25.12 executable failed before
  tests ran because `go.mod` requires Go 1.27.0. Successful checks used the
  existing Go 1.27.1 SDK directly with its `GOROOT` and `GOTOOLCHAIN=local`.

## Remaining findings and limits

1. **Provided TrustTunnel certificate selection was corrected in the
   coordinated Go change; native runtime validation remains pending.**
   In the inspected TrustTunnel source, `tools/setup_wizard/tls_hosts_settings.rs`
   `parse_cert` derives `Cert.common_name` from the entire subject string,
   stripping an initial `CN=`. `build_settings_from_cert` uses that string as
   `hosts.toml`'s main hostname. The noninteractive provided branch does not
   select the CLI `-n` hostname, and `ask_for_alternative_snis` returns an empty
   list. SANs are collected but do not populate accepted names. In
   `lib/src/tls_demultiplexer.rs`, selection uses the main-host key or explicit
   `allowed_sni`. This is a source-established compatibility risk for SAN-only,
   multi-name and multiattribute-subject certificates. The coordinated
   `core/trusttunnel/config.go` change now checks the provided certificate/key
   pair and leaf SAN against the panel hostname before invoking the wizard,
   then parses generated `hosts.toml` and replaces its single main hostname
   with that requested name while preserving other settings. The config agent
   reports `TestGenerateConfig_ProvidedSANSelectsPanelHostname` passing for
   SAN-only and differing-CN fixtures, including preservation of relative
   native paths, alternate SNI and extra tables/fields;
   `TestGenerateConfig_ProvidedRejectsWrongCertificateBeforeWizard` passing for
   wrong SAN despite matching CN, mismatched key, missing file and invalid PEM;
   and `TestSetProvidedHostname_RejectsUnexpectedNativeShape` passing.
   These use the wizard test helper. A real native wizard and endpoint test
   must still establish behavior for the shipped binary before calling this
   path fully verified. The installer edit alone does not implement this fix.
2. **Generic `CertConfig` is not TrustTunnel's certificate API.** A manually
   supplied generic HTTP/DNS/file configuration can still trigger the
   controller's generic certificate handling because TrustTunnel is marked
   TLS. The endpoint's wizard continues to use its separate panel settings.
   The standard wizard avoids creating this contradictory configuration.
   No global certificate architecture change was made in this audit.
3. Public Let's Encrypt issuance/renewal, real DNS validation, all authenticated
   protocol handshakes, external reachability, Linux file ownership and the
   downloaded endpoint release's full certificate lifecycle were not validated
   by the checks listed above. The coordinated TrustTunnel runtime/startup
   changes and their tests are recorded separately in `AI_HANDOFF.md`.

Files changed by this audit: `install.sh`,
`scripts/test-trusttunnel-cert-prereqs.sh`, and this report. Other concurrent
TrustTunnel code edits belong to the coordinated agents and are not claimed
as part of this installer change.
