# Protocol audit — 14 October 2026

Base: V2bX v1.7.4, commit `a9d3d2b4bdc011b30737367cbbad4bb526d65644`.
Codex and three scoped audit agents reproduced the defects below and prepared
local repairs. These changes have not been released or installed on production.

**Known serious dependency issues remain. This report does not certify every
protocol as safe; Xray SS2022 identity handling, TUIC UDP user deletion and Sing
node retirement require follow-up before claiming a complete protocol repair.**

## Reproduced defects and repairs

| Area | Trigger and previous result | Result after repair |
| --- | --- | --- |
| AnyTLS authentication | User updates run alongside actual TLS authentication; the race detector reported the shared password map | Publish immutable authentication tables atomically |
| SS2022 authentication | Encrypted TCP handshakes and persistent UDP traffic continue during user updates; key/hash/cipher maps raced | Publish all three maps in one immutable generation; retain existing UDP sessions and response cipher generation |
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
| Shutdown reporting | No scheduled poll had collected the latest reportable bytes when the controller stopped | Collect the final available sample and flush saved below-threshold report bytes before core teardown |
| Windows ACME files | `path.Dir` did not recognize Windows separators, so the account's parent directory was not created | Use `filepath`; retain Unix permission checks on systems supporting them |
| Sing port conversion | An out-of-range port narrowed to an unrelated `uint16` port | Reject negative/overflow values; retain intentional ephemeral port 0 |

The authentication sources are exact pinned local copies, without protocol-version
upgrades. See [third-party provenance](../third_party/README.md) and
[file hashes](../third_party/upstream-manifest.json). Only the two declared
upstream source files differ from the original modules, and licenses are retained.

## Verification performed

All runtime tests here run on Windows/amd64, Go 1.27.1 with `GOEXPERIMENT=jsonv2`.
Race checks use GCC. The protocol exchanges use loopback endpoints.

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
no CI-pass claim. No production node, live WAN packet-loss measurement, Docker
image or public release was changed.

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
| High | Xray multi-user SS2022 maps authenticated indices onto a mutable users slice | Source-confirmed: concurrent deletion swaps/truncates the slice; TCP/UDP callbacks index it without synchronization. Possible incorrect identity/billing or panic. Not repaired or runtime-reproduced here; requires stable identity handling in the pinned Xray dependency |
| High | TUIC UDP user deletion asserts `net.Conn` on stored packet connections | Source-confirmed through the concrete packet wrapper types. A UDP connection does not satisfy that interface. No live deletion-panic test or dependency repair was performed |
| High | Sing node retirement and billing generation | `DelNode` does not retire all tracked identities/sessions. Safely retiring counters needs a bounded ledger and proof in-flight accounting completed; immediate deletion can lose bytes. No speculative cleanup was added |
| Medium | MasterDNS asynchronous bind failures | Its public `Start` discards the asynchronous `Run` error; a failed listener can appear started. The ListenIP repair does not solve this lifecycle issue |
| Medium | AnyTLS physical pooled-session deletion | The pinned inbound records physical sessions before authenticated user metadata is available. The repaired hook rejects removed users' new routed streams, but does not immediately destroy every old physical session |
| Investigated only | TrustTunnel startup readiness and user-file changes | A possible missed-reload window was identified by source review but not reproduced; no repair is claimed |
| Existing behavior | Socket deadlines during throttling | Socket deadlines are forwarded; only connection close/interrupt cancels the limiter wait. Custom waiters lacking cancellation cannot be interrupted internally |

No general speed improvement is claimed for protocols whose WAN performance was
not measured. Private-network access rules, subscriber billing and device limits
were not weakened to increase benchmark numbers.
