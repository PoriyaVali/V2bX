# Protocol audit — 14 October 2026

Base: V2bX v1.7.4, commit `a9d3d2b4bdc011b30737367cbbad4bb526d65644`.
Codex and scoped audit/review agents reproduced the defects below and prepared
repairs for v1.7.5. No production server was changed during this audit.
The serious follow-ups from the initial review are included below; remaining
issues and the limits of local validation are listed separately.

## Reproduced defects and repairs

| Area | Trigger and previous result | Result after repair |
| --- | --- | --- |
| AnyTLS authentication | User updates run alongside actual TLS authentication; the race detector reported the shared password map | Publish immutable authentication tables atomically |
| SS2022 authentication | Encrypted TCP handshakes and persistent UDP traffic continue during user updates; key/hash/cipher maps raced | Publish all three maps in one immutable generation; retain existing UDP sessions and response cipher generation |
| Xray SS2022 identity | Removing a user during an actual encrypted handshake changed its authenticated slice index, causing wrong-account admission or an out-of-range panic | Authenticate with stable user pointers, reject retired generations and apply credential/membership updates transactionally; retain persistent UDP sessions |
| TUIC authentication | Concurrent updates could pair a user from one generation with a password from another; concurrent authentication streams could both close the session signal | Publish one immutable user/password table and reserve authentication once per session |
| TUIC UDP deletion | Removing a user asserted `net.Conn` on a packet-only connection and could panic | Track `io.Closer` connections by immutable user generation and close them outside the membership lock |
| AnyTLS pooled sessions | Idle authenticated and pending-authentication physical sessions could survive user removal or inbound close | Track pending physical sockets and authenticated user generations; close captured sockets outside locks and reject late old-generation authentication |
| Sing admission | A stream authenticates before its user is removed but reaches tracking afterward; removed TCP/UDP streams remained open | Check current membership under a short shared registration lock |
| Sing deletion | Closing a slow AnyTLS stream while holding the membership write lock blocked another node's admission | Detach/tombstone the old connection generation under the membership lock, close it after releasing locks; a re-added generation stays intact |
| Sing and Xray SS2022 credentials | Short panel credentials caused `[:16]` / `[:32]` slicing panics | Validate key lengths before conversion; valid credentials retain their previous derivation |
| Sing TUIC user updates | One malformed UUID poisoned the dependency's user list and subsequent valid additions failed | Validate the entire batch before updating the inbound |
| Rate limiting | TCP, UDP and Xray operations stayed inside a token wait after closing the connection | Cancel waiting on close/interrupt; retain the shared bucket, counters and buffer ownership |
| Dynamic speed limits | Expiration of an old limit erased a newly renewed limit | Serialize renewal and the expired-window recheck per user, outside the ordinary nonexpired lookup path |
| Hysteria2 | Custom stream window was written to the wrong field; the configured MTU discovery flag was ignored | Apply the stream window and MTU setting to their intended QUIC fields |
| Xray read/sniff path | A reader returned valid payload together with EOF; the payload was discarded | Preserve the final payload, traffic accounting and sniff cache before propagating EOF |
| User attribution | A failed inbound update left a UID row for a user that was not successfully installed | Publish accepted UID mappings after installation; Xray prevalidates the entire conversion batch |
| TrustTunnel metrics | Six polls opened six abandoned keep-alive transports/connections | Reuse one bounded proxy-free loopback client per node and close idle connections on shutdown |
| TrustTunnel credentials | Concurrent snapshots wrote and renamed the same temporary file, producing errors or stale overwrites | Serialize the snapshot and atomic file replacement; perform file I/O outside the node state lock |
| MDNS listeners | A node configured for a particular listen address still bound all interfaces | Pass `ListenIP` into the underlying UDP/TCP host option; a real DNS socket test verifies it |
| Panel user-list decoding | Invalid JSON or preferred-format MessagePack could be cached as an empty user list, revoking all access | Require a complete top-level users array, reject duplicate/trailing values, and advance ETag only after successful validation |
| Sing node retirement | Deleted nodes retained tracked streams and UIDs; final read/write callbacks could lose bytes or attribute them to a re-added UID | Revoke listener generations, close tracked streams, join counted I/O and retain final bytes under the original UID until consumed; exact node ownership protects names containing delimiters |
| Retirement reporting | Selector deleted the core mapping before final samples were available; a replacement node could fail to start before reporting | Collect after completed Sing teardown, transfer samples through a separate synchronized queue and report them even while the replacement is down |
| Shutdown reporting | No scheduled poll had collected the latest reportable bytes when the controller stopped | Close and drain Sing I/O, collect the final sample and flush saved below-threshold report bytes; other cores retain their existing pre-delete snapshot behavior |
| Windows ACME files | `path.Dir` did not recognize Windows separators, so the account's parent directory was not created | Use `filepath`; retain Unix permission checks on systems supporting them |
| Sing port conversion | An out-of-range port narrowed to an unrelated `uint16` port | Reject negative/overflow values; retain intentional ephemeral port 0 |

The authentication sources are exact pinned local copies, without protocol-version
upgrades. See [third-party provenance](../third_party/README.md) and
[file hashes](../third_party/upstream-manifest.json). Only three declared
upstream source files differ among 133 original files, one added TUIC regression
is recorded separately, and licenses are retained. The existing downstream
sing-box and Xray forks are pinned to `v1.13.21-v2bx.2` and `v1.260909.1`.

## Verification performed

All runtime tests here run on Windows/amd64, Go 1.27.1 with `GOEXPERIMENT=jsonv2`.
Race checks use GCC. The protocol exchanges use loopback endpoints.

- Release follow-up tests use the final root module graph, including patched
  sing-box and Xray pins: AnyTLS physical-session retirement, TUIC user deletion,
  TUIC paired authentication snapshots and Xray SS2022 passed three race runs.
  The Xray fork additionally passed ten race runs using 100 encrypted TCP
  handshakes and 201 persistent UDP exchanges per run.
- Sing's normal suite passed. Tagged AnyTLS reuse/authentication and slow-close
  regressions passed three race runs. The real AnyTLS same-tag retirement/rebuild
  regression passed three runs with exact final billing retained under the old
  UID and new traffic attributed to the new UID. Focused retirement tests cover
  concurrent final read/write callbacks, missing/old listener tokens, exact node
  ownership, 64 compacted generations, unwrapping barriers and close-error retry.
  A real UDP read/write regression pauses after successful packet transport and
  verifies retirement joins the final counter callbacks; three race runs passed.
  Per-device cleanup uses one scan per removal batch rather than one per user.
- Bash syntax and all 65 isolated release/updater regression cases passed.
  Installed 7-Zip supplied test fixture ZIPs because Git Bash lacks `zip`.

Initial audit validation, retained for comparison:

- Root ran the normal broad race suite over `api`, `node`, `conf`, `common`,
  `limiter` and every `core` package: passed. The final additional Sing lock
  correction was subsequently checked with the full Sing race suite and the
  targeted admission/authentication tests.
- Actual TLS AnyTLS authentication during user changes, the existing reused-session
  handshake regression, and TUIC malformed-UUID validation passed three race runs.
- SS2022 encrypted TCP plus a persistent UDP session during updates passed three
  race runs: 6,253 TCP echo sessions and 21,400 UDP exchanges in aggregate.
- Slow user-close/re-add and admission regressions passed three race runs. They
  verify that closing an old generation does not close its replacement.
- Live limiter cancellation and accounting/cache tests passed three race runs.
  The dynamic-limit test passed 100,000 renewal/expiration iterations per run,
  three times.
- New other-core regressions passed three race runs; existing Hysteria2, Xray,
  TrustTunnel and MDNS tests also passed. The original nested Shadowsocks module
  tests passed; the original AnyTLS module contains no tests.
- Broad targeted `go vet` passed. A Linux/amd64 build with all normal release core
  tags and `-mod=readonly`, CGO disabled, passed. This is compilation, not native
  Linux execution or a published binary.

Initial failures and corrections were retained in the shared handoff: Windows
POSIX-mode assertions and unescaped test paths; a test choosing a TCP-free port
for a UDP server; insufficient encrypted-header space in the UDP test buffer;
and a snapshot test stub repeating traffic despite `reset=true`. These were
identified separately from actual protocol defects. No failed test is counted
as a passing run.

Native Linux CI was not executed. GitHub Actions rejected dispatch in the prior
session with `Actions has been disabled for this repository`; this audit makes
no CI-pass claim. No production node, live WAN packet-loss measurement or Docker
image was changed. Public build provenance belongs to the v1.7.5 release record.

## Measured panel polling improvement

The same benchmark runs the real HTTP/decode path against a fixed JSON bulk
response on loopback. Three one-second runs per size were compared with the
unchanged v1.7.4 source. Values below are medians on the same Windows host.

| Users | Old time/poll | New time/poll | Old/new allocation count | Old/new allocated bytes |
| --- | --- | --- | --- | --- |
| 1,000 | 666,601 ns | 442,735 ns | 2,150 / 1,127 | 207,365 / 150,322 |
| 10,000 | 6,629,970 ns | 4,532,606 ns | 20,189 / 10,167 | 2,844,604 / 2,353,912 |

This represents approximately 32–34% less time and 48–50% fewer allocations
for JSON user-list polling. MessagePack remains the requested preferred format.
This benchmark does not measure VPN throughput, WAN latency or packet loss;
machine load and network conditions can change runtime timing.

## Remaining issues and limits

| Priority | Finding | Evidence and next work |
| --- | --- | --- |
| Medium | MasterDNS asynchronous bind failures | Its public `Start` discards the asynchronous `Run` error; a failed listener can appear started. The ListenIP repair does not solve this lifecycle issue |
| Investigated only | TrustTunnel startup readiness and user-file changes | A possible missed-reload window was identified by source review but not reproduced; no repair is claimed |
| Existing behavior | Socket deadlines during throttling | Socket deadlines are forwarded; only connection close/interrupt cancels the limiter wait. Custom waiters lacking cancellation cannot be interrupted internally |

No general speed improvement is claimed for protocols whose WAN performance was
not measured. Private-network access rules, subscriber billing and device limits
were not weakened to increase benchmark numbers.
