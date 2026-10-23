# Panel coordination and runtime stability

This change targets the V2bX control plane: malformed panel responses, report
receipts, online-device lifecycle and config reloads. It preserves the existing
MDNS wire protocol and encryption.

## Behavior

- A traffic, online-device or status report needs Irboard's JSON
  `{"data":true}` receipt. HTTP 200 containing a login page, `false`, an empty
  object or invalid JSON is an error. Unacknowledged traffic stays in the
  existing bounded in-memory retry queue under its original report ID.
- Traffic for repeated samples of one UID is summed. Payload construction uses
  fixed two-element arrays instead of one allocated slice per UID, while
  keeping Irboard's JSON `[upload,download]` format.
- Panel replies have a 64 MiB uncompressed body budget, including streamed user
  lists. MessagePack user slices grow as records arrive; a tiny array header
  claiming millions of absent users no longer causes that initial allocation.
  Invalid identities, incomplete alive lists and negative device counts are
  rejected before replacing cached state or advancing user ETags.
- For cores with complete connection snapshots (currently sing and MDNS),
  a departed user's addresses are explicitly cleared with `uid:[]`. Missing
  keys do not clear Irboard's stored addresses. Failed/ambiguous receipts are
  retried, including when nobody remains online and at orderly shutdown.
  An unavailable snapshot never establishes that everybody disconnected.
  Cores with only admission events retain Irboard's existing expiry behavior;
  an idle established connection must not be cleared from lack of handshakes.
- Xray DNS/routing/inbound/outbound read, decode and build errors return errors
  instead of panicking. Explicitly configured broken DNS files are rejected
  rather than silently falling back to defaults.
- The config watcher passes a candidate to the reload callback and commits it
  only after success. Replacement cores are constructed before retiring live
  nodes. Constructor rejection preserves the live runtime and config, and a
  later corrected save can apply normally. Partially constructed selectors
  close their cores in reverse order and retain cleanup errors.

## Verification

Validated locally on Linux amd64, Go 1.27.1 with `GOEXPERIMENT=jsonv2`:

- Whole-module build, release build with all five core registrations, vet,
  and race tests for limiter, node, conf, common, api, core and cmd packages.
- A real release-tagged subprocess serves an MDNS UDP node, rejects an Xray
  routing-file edit while that node keeps answering, then applies a corrected
  save and shuts down cleanly. This regression runs in GitHub's Test workflow.
- Installer/update and release-version regression scripts passed.
- Actual Irboard HTTP/schema tests: 3 tests, 104 assertions. Generated responses
  are consumed by V2bX's ordinary contract tests for all ten protocol configs
  plus the legacy `v2ray` alias, JSON/MessagePack, empty lists, ETags and receipts.
  See [fixture regeneration](../api/panel/testdata/irboard/README.md).
- Irboard's broader suite passed 198 tests / 1552 assertions with
  `--filter '^(?!.*GoogleAuthTest)'`. The five existing GoogleAuth tests are
  excluded because their migration setup does not build the install.sql schema;
  no authentication implementation was changed here.

The payload benchmark includes map construction and the HTTP library's JSON
serialization API, for 10,000 distinct UIDs. Three runs on an AMD EPYC 9V74,
GOMAXPROCS=4 gave these medians:

| Payload | Time/report | Bytes allocated/report | Allocations/report |
| --- | ---: | ---: | ---: |
| Previous slices | 5.238 ms | 2,367,359 | 20,040 |
| Fixed arrays | 5.154 ms | 1,855,416 | 10,039 |

This is about 22% fewer allocated bytes and 50% fewer allocations in this
specific operation. Timing is similar; these results do not establish a whole
daemon CPU, throughput, resident-memory or subscriber-speed improvement.

```sh
GOEXPERIMENT=jsonv2 go test ./api/panel -run '^$' \
  -bench BenchmarkTrafficReportPayload -benchmem -count=3
V2BX_TEST_BINARY=/path/to/release-tagged/V2bX GOEXPERIMENT=jsonv2 \
  go test -race ./cmd -run '^TestServerRejectedCoreReloadKeepsDNSNode$' -count=1
```

## Limits

Contract coverage is not an unconditional 100% compatibility guarantee across
every optional setting, core, client and Internet path. Test deployment remains
necessary. Irboard's fleet-wide alive cache may lag by up to 60 seconds, and
admission-only cores still use the panel's existing expiry windows.

Core construction is checked before teardown; failures during subsequent
listener startup still use the existing controlled process exit/restart path.
The traffic retry queue remains bounded and in memory: prolonged outages can
exhaust it, and process crashes cannot guarantee delivery. Irboard's sequential
retry deduplication is tested; durable exactly-once accounting under concurrent
requests or partially queued jobs is outside this change.
