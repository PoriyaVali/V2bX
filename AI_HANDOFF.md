# AI work log and handoff

## Active handoff - 2026-10-24 - Codex - CLI restart readiness fixture repair; v1.9.3 still unpublished

Port fixture repair committed/pushed cb223d8. Run40075536034 FAILED at CLI
TestServerRejectedCoreReloadKeepsDNSNode line127, final probe AFTER valid
restart. Startup and rejected-config immediate probe passed. Source of pinned
MasterDnsVPN server/server.go107 explicitly documents Start returns at once,
starts inner.Run in goroutine; node/server logs can precede UDP bind. This
test already passed prior7246735 Linux run; evidence now demonstrates missing
readiness synchronization, not certificate reload failure. Full failed job log
saved in shared ignored .dart_tool/v2bx-release-1.9.3/failed-test-run-
40075536034.log. Gate skipped draft/build/publish again; no version shipped.

Material paths: cmd/server_reload_integration_test.go awaits actual DNS reply
within5s ONLY after initial start and valid restart, keeps immediate probe
after rejected config, dumps server log on DNS failure. .github/workflows/
test.yml repeats this actual binary test3times under Race (2m bound).
AI_HANDOFF.md records rationale/status. No production-code change. Local
cmd Race checks PASS1.982s (actual-binary integration skipped locally; host
binary unset), workflow YAML parse/gofmt/diffcheckPASS. Hosted Linux actual-
binary repeated validation pending; do not claim skipped local integration
passed. These3paths UNCOMMITTED at entry.

## Active handoff - 2026-10-24 - Codex - Linux CI caught shared-port fixture collision; release still blocked

Run40074451673 at committed/pushed72467355d7a1bbc3a47740042e1beaaf731d2bb4
proved Linux preparation repair (10Python tests + real patch application),
installer tests, whole/release-tag builds, command reload, vet, update, AnyTLS/
QUIC authentication/retirement, cached-connection and whole Race suite PASS.
Explicit12packageRace+QUIC step FAILED only core/sing's existing
TestSing_Hysteria2ProberSeesDecoySite: freeUDPPort selected a TCP-busy port;
cover bind EADDRINUSE followed by TCP connect refused. Other11packages PASS.
No data race/certificate-rotation failure reported. Native/public limits still
apply. Release gate correctly skipped draft/build/publish; v1.9.3 unpublished.
Raw failed Linux job log saved in shared ignored release evidence directory.

Material edit core/sing/decoy_hy2_test.go: cover tests now select shared TCP/UDP
port, reserving TCP while checking UDP. Keep actual HTTPS/HTTP3/retirement
assertions. UDP-only certificate probe helper unchanged. No production-code
edit. Both cover tests repeated30times with Race+QUIC PASS2.921s; whole Sing
Race+QUIC PASS18.271s; gofmt/diffcheckPASS. Hosted full retry pending. This
test repair UNCOMMITTED at entry; prior7246735 remains remote head.

## Active handoff - 2026-10-24 - Codex - v1.9.3 cancelled; repair Linux preparation and require tests

Owner cancelled run and explicitly replaced no-test preference with WITH TESTS.
Earlier commit441cb14052f1bbdf0845ea02604039dcc49f9f94 remains published on
dev_new; run40073960927 CANCELLED with multiple preparation failures. Draft
v1.9.3 has zero assets and is NOT published. Attempted cancellation after
status changed returned already completed; no extra mutation. Logs of Windows
amd64 and LinuxMIPS targets show identical Linuxrunner Permission denied at
git apply, before Go build. Root cause: shutil.copytree retains read-only Go
cache DIRECTORY modes; script only made files writable. Earlier Windows-only
preparation tests missed actual POSIX directory permissions.

Material repair paths:
- scripts/prepare_tls_dependencies.py: make_staging_writable changes owner
  write/search bits on copied directories and files only, rejects links;
  original cache remains untouched and hash checks remain enforced.
- scripts/test_prepare_tls_dependencies.py: real Git patch of nested read-only
  copied tree, including empty directory, checks original cache bytes/modes.
- .github/workflows/test.yml: callable workflow; explicit all12certificate
  packages with Race+QUIC, in addition to full existing checks.
- .github/workflows/release.yml: publishing invokes Test first; draft and all
  builds depend on validation. Resume existing draft without replacing any
  published release; do not build after cancelled/failed prerequisites.
- docs/releases/v1.9.3.md: owner now requires tests; document gate/permissions.
- AI_HANDOFF.md: this record. Root shared handoff also updated.

Validation update before commit: all10script safety tests PASS, including new
readonly-directory regression on Windows; fresh independent full dependency
preparation/hash/modfile checks PASS; all3workflow YAML parse PASS; diffcheck
PASS. Twelve-package local Race+QUIC running, not yet claimed passed. These
six paths are UNCOMMITTED at this entry; hosted Linux Test gate will precede
any release builds. No claim that earlier local checks
proved Linux permission correctness. NativeTT/publicACME/DNS/OCSP limits
still apply. Prior audit deliveries/source checkout preserved. No server work.

## Active handoff - 2026-10-24 - Codex - v1.9.3 publication authorized; no repeated tests

Owner explicitly requested push to GitHub and quick v1.9.3 build/release,
without rerunning tests already completed. Target PoriyaVali/V2bX dev_new
freshly read at bb5ccfca6b9d56c0269d6bafe9bdc639a6db0191; v1.9.3 absent.
Verified all 59 reviewed candidate path hashes and exact packaged diff before
release edits. Prior audit delivery remains unchanged. Historical local-only
entries below describe their state at that time, not current authorization.

Release preparation material changes beyond the reviewed 59-path candidate:
- Dockerfile: install git/Python in builder, prepare same verified TLS module
  graph as release binaries, build readonly through audit_mod, inject VERSION.
- .github/workflows/Publish Docker image.yml: pass ref version to Docker build
  and explicit contents-read/packages-write permissions for image publication.
- README.md: link current v1.9.3 notes.
- docs/releases/v1.9.3.md: fixes, upgrade, required source build preparation,
  completed earlier validation and explicit native/public verification limits.
- AI_HANDOFF.md: this release record (already among original candidate paths).

Decision: commit reviewed fixes plus release wiring with [skip ci] so push
does not rerun tests or duplicate builds, then manually dispatch existing
release.yml with tag v1.9.3 and notes. Its draft remains unpublished until
all platform binaries upload; then existing workflow dispatches Docker build.
No production source changes to shared hiddify-app checkout. No server action.

Validation: original source/artifact binding PASS; repository/branch/tag and
authenticated CLI write access read; release/Docker workflows inspected.
No tests/vet rerun. New Docker wiring will be validated by actual build only;
native TT execution and public HTTP01/DNS01/OCSP remain unverified. GitHub
connector lacks release/dispatch writes (workflow collection read rejected);
authenticated gh CLI and normal non-force Git push used for missing actions.
Status at entry: release edits UNCOMMITTED; commit/push/build still pending.

## Active handoff - 2026-10-24 - Codex - ALL-core local candidate validated; native/public runtime UNVERIFIED

Final packaging check: raw dependency patch context indentation triggered
whitespace warnings after intent-to-add. A raw-patch-only .gitattributes
exemption preserves LF/SHA data; repaired Go sources still use gofmt and
complete source-hash verification. Final diffcheck passed. An initial handoff
note insertion used a mismatched text anchor and made no changes; corrected.

OWNER OBJECTIVE: verify certificate recognition and renewal in every V2bX
core; user explicitly said continue. Fresh connected GitHub reads today still
pin dev_new and Latest v1.9.2 to bb5ccfca6b9d56c0269d6bafe9bdc639a6db0191.
Root and scoped Codex agents own these local repairs; original published base
was Ahmad Charghani's work. No commit/push/PR/tag/release/live-node/firewall/
certificate-authority operation. Original clean7199d4b checkout and previous
out/v2bx-trusttunnel-20261023 delivery verified preserved. Shared app production
source/build unchanged; only shared root AI_HANDOFF tracked edit.

STATUS: complete local audit/repair candidate, UNCOMMITTED, NOT production-
validated. Remaining real nativeTT/Linux and publicACME/DNS/OCSP tests are
explicitly unperformed. Full report docs/certificate-lifecycle-audit-2026-10-24.md
supersedes historical October23 certificate architecture. Review delivery
C:/Users/dr mobile/hiddify-app/out/v2bx-certificate-audit-20261024 contains
fix.patch, audit.md, README.fa.md and verification.json. No binary shipped.

Decisions/findings:
- Shared common/certmanager, retained node public aliases. Validate keypair,
  domain/SAN/time/serverAuth or Any or unrestrictedEKU; client-only/unknown-only
  usages fail. ACME accounts persist. Managedselfsigned does not satisfyhttp/dns.
  Renew configured domain30days early, check6h; explicitDNS wildcard supported,
  HTTPwildcard rejected. Self IP SAN and combinedPEM including Windowscase
  aliases repaired. Shared operation lock plus rollback protects installation.
- Renewal follows mode/security transitions; cert preparation precedes listener
  retirement. Failed prep preserves published coreinfo, still enforces user
  revocations. Config rejects conflicting managed domain/path ownership.
- TT now sharedmanager self/http with persisted account and healthy reuse,
  nativewizard provided-only immutable snapshots. Managedchecks6h/failretry1h;
  externalfilechanges5s validated, atomic hosts commit+queued process-safeHUP.
  Partial/bad replacements preserve native snapshot; no oldloop commit after
  shutdown. Source fingerprint separates modes/hostnames. No snapshot pruning.
- Actual SingTLS cert/config races fixed with synchronization, coherent pair
  loading, relativepath anchoring and bounded polling fallback. Initial QUIC
  frozenconfig suspicion DISPROVED; real originalQUIC reload worked.
- Actual Xray permanent reloadstop on readerror, expiredcandidate publication
  and unsafepointer fixed using immutable retryable sources. Configured domain
  permits obsoleteSAN removal; generic sources preserve original identities.
  Async OCSP uses bounded client. Corepreflight validates enabled modes.
- HY2 strict modes and cloned expandedpaths cover actual QUIC+automaticTCP+
  configured HTTPSmasquerade. Loader/covers retain valid configured identity.
- Windows atomicreplace bounded retry tested with actual deny-delete handle;
  permanent failure preserves file. Original Windows rename failure recorded.
- Dependency source repairs are tracked minimal patches+JSON hashes/provenance,
  not1042+990vendored files. Script verifies full Go moduleh1, all files,
  patch before/after hashes, immutable preparedtrees/reversechecks and actual
  Go-selected replacements. Normal go.mod/sum remain unchanged. Test/release
  workflow SOURCE explicitly prepares/uses modfile, report output ignored.
  Plain Go without preparation still selects original unpatched dependencies.

Actual FINAL validation on Go1.27.1/jsonv2/Windowsamd64:
- Latest combined -race -tagswith_quic:12packagesPASS,575pass events incl
  subtests/4skip/0fail. Skips2publicACME,1Linuxsocket,1cmd requireshostbinary.
  Removed obsolete two Xraycert-race skips; both pass in final combined run
  and standalone. Sing19.303s, Xray58.065s, HY2 9.297s, TT22.938s.
- Actual CA+hostname-verified TLS/QUIC serial changes: Sing4TCP/3QUIC;
  Xray3TCP; HY2 QUIC+cover+customHTTPS. Invalid/missing/mismatch/expired/
  future/wrongSAN/EKU candidates keep old certificate and recover to new.
  Shared fakeissuer tests actual TLS with correct request/domain/environment/
  due windows/accounts/retry/recovery/combinedpaths; no public challenge proof.
- Scoped vet on same12packagesPASS after final strengthening. All-release-tags
  Linuxamd64 crossbuildPASS. Both real TT native integration tests compiled
  forLinux, NOT executed. Explicit local Xraydependency TLS tests passed under
  race before lastunknownEKU strengthening; final whole-core tests exercise
  current dependency including unknownEKU rejection. No full upstream claim.
- Python9 safetytestsPASS; final dependency prep + idempotentcheckPASS.
  Independent final second preparedtree reproduced byte-identical complete
  source manifests (Xray1042files,Sing990files). Modified workflow YAML parse
  PASS; hostedCI NOT run. ChangedGo gofmt clean and diffcheckPASS.
- Prior87isolated installer cases preserved with unchanged installer sources;
  not falsely claimed rerun during latest certificate pass.

Failures/limits preserved: earlier originalSingTCP race red4protocols;
generic candidate/IP/combinedPEM/HY2literalpaths/unknownmode redtests corrected.
Earlier full upstreamXray TLS test ran inherited externalECH test and FAILED/
panicked; only subsequent explicitlocal tests passed. Preparation initially
rejected stale patchSHA; Windowsautocrlf fixture mismatch corrected. First
combined final PowerShell unquoted modfile argument failed BEFORE tests,
corrected quoted command. Documentation context mismatch corrected. Original
failed logs/staging retained; previous handoffs retain earlier SDK/test fixture
failures. Last serverAuth audit also closed unknown-onlyEKU hotload gap in
all four consumers, regenerated dependency metadata and reran final12packages.
No publicACME/HTTP01/DNS01/OCSP, nativeTT runtime, everycustomOriginalPath/
transport/ECH/authorityissuance configuration or hostedCI evidence.
In-flight Lego/DNS requests are not cancelled by periodicTask.Close and may
delay shutdown until provider timeouts. File/provided renewal external-owned.
Do not say all production renewals are proven or publish this candidate as
fully validated merely because local checks passed.

Exact changed target paths (including prior patch and two moved test files):
- .gitattributes
- .github/workflows/release.yml
- .github/workflows/test.yml
- .gitignore
- AI_HANDOFF.md
- common/certmanager/cert.go
- common/certmanager/cert_automation_test.go
- common/certmanager/cert_lifecycle_test.go
- common/certmanager/lego.go
- common/certmanager/lego_files_test.go
- common/decoy/decoy.go
- common/file/atomic.go
- common/file/atomic_windows_test.go
- common/tlscert/hostname_test.go
- common/tlscert/loader.go
- conf/certificate_paths.go
- conf/certificate_paths_test.go
- conf/conf.go
- core/hy2/certificate_lifecycle_test.go
- core/hy2/config.go
- core/hy2/node.go
- core/sing/certificate_lifecycle_test.go
- core/sing/certificate_quic_test.go
- core/sing/node.go
- core/trusttunnel/certificate.go
- core/trusttunnel/certificate_test.go
- core/trusttunnel/certificate_usage_test.go
- core/trusttunnel/config.go
- core/trusttunnel/config_generation_test.go
- core/trusttunnel/native_integration_test.go
- core/trusttunnel/node.go
- core/trusttunnel/startup_test.go
- core/trusttunnel/supervise_test.go
- core/trusttunnel/trusttunnel.go
- core/trusttunnel/user.go
- core/xray/certificate_lifecycle_test.go
- core/xray/decoy_e2e_test.go
- core/xray/inbound.go
- docs/certificate-lifecycle-audit-2026-10-24.md
- docs/trusttunnel-certificate-audit-2026-10-23.md
- install.sh
- internal/certtest/certtest.go
- node/cert.go
- node/cert_automation_test.go
- node/certificate_tasks_test.go
- node/controller.go
- node/lego.go
- node/lego_files_test.go
- node/node.go
- node/task.go
- patches/sing-box-tls-lifecycle.json
- patches/sing-box-tls-lifecycle.md
- patches/sing-box-tls-lifecycle.patch
- patches/xray-tls-lifecycle.json
- patches/xray-tls-lifecycle.md
- patches/xray-tls-lifecycle.patch
- scripts/prepare_tls_dependencies.py
- scripts/test-trusttunnel-cert-prereqs.sh
- scripts/test_prepare_tls_dependencies.py

## Active handoff - 2026-10-24 - Codex - ALL-core certificates: combined checks PASS; packaging IN PROGRESS

Resumed at owner's explicit continue. Original published bb5ccfc and prior
12-file patch remain preserved; no commit/push/release/server/ACME issuance.
Own isolated source D:/Drmobjay_apk/V2bX-trusttunnel-20261023. New scoped agents
completed reproducible dependency prep, shared manager review and dedicated
Hysteria2 live TLS tests. Root completed Sing/Xray integration, validated
certificate snapshots, path ownership guards and CI build graph selection.

Actual final combined Go1.27.1/jsonv2 race (with_quic) PASS12packages:
572 pass events including subtests,6skip,0fail. Skips: two explicit publicACME,
one cmd test requiring built host binary, one Linuxsocket test, two historical
XrayTLS race skips. Removed those two obsolete skips and separately reran both
Xraydecoy tests under race PASS1.169s, so they are now exercised.
Shared manager/controller review full racePASS; nine offline preparation tests
PASS; actual prepared full-tree module checks + idempotent checksPASS. Scoped
vetPASS. Full ALLrelease-tags Linuxamd64 crossbuildPASS and native TT tests
crosscompilePASS, NOT run. Normalgo.mod/go.sum unchanged; CI test/release source
now explicitly prepares pinned SHA256-verified patches and uses audit.mod.
Plain Go without preparation still uses unpatched pins. No hostedCI run.

Concrete repaired defects: TT no renewal/no externalfilewatch; Xray reload
permanently stopping on read failure and cert-pointer race; SingTLS race during
rotation; generic wrongSAN/time/client-onlyEKU candidate acceptance; self IP
SAN/combinedPEM/self->ACME reuse; renewal scheduler mode/security transitions;
livecore retained on certificate preparation failure with revocations enforced;
samepath/domain conflicts rejected; HY2 unknown mode and literal placeholders.
Managedhttp/dns reuse account, renew30d early at6h; self regenerate when due.
File/provided issuance remains external; validated hot reload is supported.
TT immutable snapshots and queued SIGHUP keep failed replacements from active
native config. Snapshot history not automatically pruned.

Earlier SingQUIC stale-pointer hypothesis DISPROVED by actual three-protocol
rotation tests; actual constructor already uses dynamicGetConfigForClient.
Baseline original SingTCP rotation race reproduced in four protocols. Actual
Xray missing->restored still stale and expired replacement reproduced before
repair. Initial generic-manager red tests and HY2 path/mode failures corrected.
Initial full upstream XrayTLS test encountered inherited external ECH test
and FAILED/panicked; only explicit local dependency tests subsequently passed.
No claim full upstreamTLS package passed. Earlier Windows concurrent rename
failure now addressed by bounded transient Windows atomic-replace retry with
real handle-sharing testsPASS; current full loader racePASS.
Preparation initially rejected stale patch hashes; corrected metadata and
Git CRLF handling. First combined final command passed literal -modfile=$mod;
failed BEFORE tests. Quoted argument corrected; successful run above. Failed
logs/staging preserved. Public ACME/DNS/OCSP and real TT runtime remain untested;
in-flight Lego/DNS work may delay shutdown until provider timeouts. Current
source is local candidate, not a production-validated stable release.

Exact current changed target paths (including prior patch and moved tests):
- .gitattributes
- .github/workflows/release.yml
- .github/workflows/test.yml
- .gitignore
- AI_HANDOFF.md
- common/certmanager/cert.go
- common/certmanager/cert_automation_test.go
- common/certmanager/cert_lifecycle_test.go
- common/certmanager/lego.go
- common/certmanager/lego_files_test.go
- common/decoy/decoy.go
- common/file/atomic.go
- common/file/atomic_windows_test.go
- common/tlscert/hostname_test.go
- common/tlscert/loader.go
- conf/certificate_paths.go
- conf/certificate_paths_test.go
- conf/conf.go
- core/hy2/certificate_lifecycle_test.go
- core/hy2/config.go
- core/hy2/node.go
- core/sing/certificate_lifecycle_test.go
- core/sing/certificate_quic_test.go
- core/sing/node.go
- core/trusttunnel/certificate.go
- core/trusttunnel/certificate_test.go
- core/trusttunnel/config.go
- core/trusttunnel/config_generation_test.go
- core/trusttunnel/native_integration_test.go
- core/trusttunnel/node.go
- core/trusttunnel/startup_test.go
- core/trusttunnel/supervise_test.go
- core/trusttunnel/trusttunnel.go
- core/trusttunnel/user.go
- core/xray/certificate_lifecycle_test.go
- core/xray/decoy_e2e_test.go
- core/xray/inbound.go
- docs/trusttunnel-certificate-audit-2026-10-23.md
- install.sh
- internal/certtest/certtest.go
- node/cert.go
- node/cert_automation_test.go
- node/certificate_tasks_test.go
- node/controller.go
- node/lego.go
- node/lego_files_test.go
- node/node.go
- node/task.go
- patches/sing-box-tls-lifecycle.json
- patches/sing-box-tls-lifecycle.md
- patches/sing-box-tls-lifecycle.patch
- patches/xray-tls-lifecycle.json
- patches/xray-tls-lifecycle.md
- patches/xray-tls-lifecycle.patch
- scripts/prepare_tls_dependencies.py
- scripts/test-trusttunnel-cert-prereqs.sh
- scripts/test_prepare_tls_dependencies.py

## Active handoff - 2026-10-23 - Codex - LOCAL PATCH VALIDATED; native runtime pending

Objective: deeply audit and repair TrustTunnel configuration, bootstrap users
and initial reload on V2bX v1.9.2. Base is exact dev_new/Latest
bb5ccfca6b9d56c0269d6bafe9bdc639a6db0191, authored by Ahmad Charghani.
Original D:/Drmobjay_apk/V2bX at 7199d4b and all shared app work preserved.
This isolated branch is fix/trusttunnel-startup-20261023. Codex/root and scoped
Codex agents own this patch; prior agent work is not claimed as ours.

STATUS: uncommitted local source only, no push/PR/tag/release/server deployment.
Linux runtime authentication and public ACME remain UNVERIFIED. Do not treat
the locally cross-built V2bX executable as an approved production release.

Exact changed files (12):
- AI_HANDOFF.md
- .github/workflows/test.yml
- core/trusttunnel/config.go (new)
- core/trusttunnel/config_generation_test.go (new)
- core/trusttunnel/native_integration_test.go (new)
- core/trusttunnel/node.go
- core/trusttunnel/startup_test.go (new)
- core/trusttunnel/supervise_test.go
- core/trusttunnel/user.go
- docs/trusttunnel-certificate-audit-2026-10-23.md (new)
- install.sh
- scripts/test-trusttunnel-cert-prereqs.sh (new)

Decisions:
- Honor numeric Options.ListenIP; :: default matches conf; bracket IPv6.
- Require explicit self-signed/letsencrypt/provided and required fields; bound
  wizard to five minutes and do not log potentially secret stdout/stderr.
- TrustTunnel still uses panel hostname/cert settings. Generic CertConfig is
  not silently translated. Provided cert/key must match and cover hostname SAN;
  correct the native wizard's CN-derived main hostname, preserving TOML keys.
- A fresh unadvertised 256-bit bootstrap password is written before EVERY
  endpoint launch and for zero panel users. Empty credentials are rejected by
  native parsing and would retain removed users on failed reload; do not blank.
- Serialize snapshot/replacement/signal/launch. Queue updates until readiness
  for the exact process, replay once ready, clear stale readiness after exit.
- Reject UUIDs requiring escaping/trimming before state changes. Use private
  unique same-directory temporary credentials and atomic replacement.
- Installer rejects invalid certificate modes/missing parameters before saving
  config; intentional offline warning policy and unreadable-path warning remain.

Validation actually performed with cached Go1.27.1 and correct GOROOT:
- Baseline and modified TrustTunnel suites PASS.
- Final race: trusttunnel 74, panel95, conf24 PASS events including subtests;
  no fail/skip events in these packages. TrustTunnel duration19.345s.
- Broad race node/cmd/sing/xray PASS. First command accidentally named missing
  core/hysteria2; corrected path is core/hy2, so initial aggregate exit1 was
  NOT a full pass. Separate final hy2 full race rerun PASS1.499s.
- go vet trusttunnel/node/cmd/panel/conf PASS exit0.
- New installer prerequisites17 + existing wizard5 + release-version20 +
  install/update/PID45 =87 isolated shell scenarios PASS. Syntax checks PASS.
  Git Bash and existing 7-Zip fixture shim were used, with space-free TMPDIR;
  no real installer/network/firewall/service operations were executed.
- Native integration test cross-compiled for Linux amd64 PASS; real endpoint
  NOT executed. Full Linux amd64 V2bX with ALL release tags cross-built PASS,
  CGO0/jsonv2, exact bb5ccfc vcs.modified=true. No go.mod/go.sum change.
- Provided SAN-only/different-CN/name mismatch/key mismatch/missing/invalid PEM,
  preserved TOML settings, ListenIP, mode/input, startup/deferred replay,
  obsolete readiness, empty-user replacement and credential validation covered.
- Focused certificate setup/panel contract tests and actual local TLS loader
  handshake/rotation/domain tests PASS. Per-protocol live auth not all tested.
- Changed Go files gofmt clean; git diff --check PASS. Untouched older files
  in this package have formatting differences and were preserved.

Failed/limited validation:
- Full common/tlscert FAILED TestLoaderConcurrentSelectionAndRotation on
  Windows concurrent file replacement (Access denied). Loader/file sources
  unchanged. Full package NOT claimed passing.
- Initial hy2 two cover tests FAILED because UDP-selected ports49670/49671
  were already occupied by existing system TCP listeners. Read-only socket
  evidence identified this; no existing process was stopped. Focused rerun and
  final whole hy2 race rerun PASS on newly selected ports.
- An agent's first Go attempt used default1.25.12 and failed before tests; fixed
  SDK path. Iterative config test initially wrongly required random username;
  corrected to assert random 256-bit password. A transient unused import during
  editing was corrected before final checks. Audit JSON counter initially
  assumed UTF8; PowerShell Tee writes UTF16; BOM-aware reader corrected it.
- No working Linux runtime/native binary here: WSL disabled, cargo/Docker not
  on PATH. Existing source comments about old live validation are historical,
  not new runtime evidence. Opt-in native test command is in the audit report.
- Public issuance/renewal, DNS challenges and remote production configuration
  remain untested. Explicit generic CertConfig for a manually configured
  TrustTunnel node can still trigger generic controller cert work; normal
  configure wizard avoids that contradictory configuration. Documented boundary.

Audit logs and local cross-builds are in the shared app workspace's ignored
.dart_tool/v2bx-trusttunnel-20261023/audit. Shared durable record also updated:
C:/Users/dr mobile/hiddify-app/AI_HANDOFF.md. Reviewable patch/report delivery:
C:/Users/dr mobile/hiddify-app/out/v2bx-trusttunnel-20261023.
