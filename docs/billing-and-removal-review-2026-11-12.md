# Billing, removal and speed limits on every V2bX core — review 2026-11-12

The review of 2026-11-07 checked that every node Irboard serves carries
traffic on every core. This one checks what a panel relies on a node for once
it does: that a user is billed what they used, that a user the panel removes
is cut off, that they get back in when the panel adds them again, and that a
speed limit holds.

## How it was tested

`cmd/irboard_ledger_test.go` runs a node through V2bX's own controller
against a panel that records every traffic report and changes its user list
mid-run. The clients are the ones of the earlier review (mihomo, sing-box,
Xray), each given what Irboard serves it. The targets count the bytes that
reach them.

- `TestIrboardServedNodesLedgerSurvey` (set `LEDGER_SURVEY=1`) runs every
  node on every core that serves it and prints one line each: bytes billed
  against bytes carried, before and after a removal; which clients a removed
  user's connection stayed open for, or let in; which were kept out once the
  user was back; how long 512 KiB took each way at 2 Mbit/s.
- `TestIrboardServedNodesBillCutOffAndLimit` runs in CI: a node of each kind
  a fault was found with, on the core it was found on, and the Mihomo core's
  own protocols. A bill may differ from the traffic by a closing TLS alert.

The Mihomo core's own protocols (HTTP, SOCKS5, Mieru, ShadowQUIC, Sudoku,
Snell) joined Irboard's contract export and all three served-node tests with
this review.

## Bugs found and fixed

### xray core

1. **A removed user kept their VLESS connections** over plain TCP,
   HTTPUpgrade and XHTTP, and under Vision or VLESS encryption, for as long
   as they went on using them.
   - Cause: removal closed the link's writer, and VLESS's writer closes the
     connection only where it writes straight to one.
   - Fix: a VLESS link ends with its user: its context is cancelled and the
     inbound connection closed.
2. **VLESS uploads were not speed limited.** The limit sat on the link's
   writer only. The reader waits on the same bucket now.
3. **Traffic since the last report was dropped when a user was removed.** The
   counter went with the user: up to a report interval was never billed, on
   every protocol. Counters of removed users are kept until reported.
4. **Vision's filter state was written from both directions of a connection
   without a lock** (a data race in xray-core). Locked in our patch.

### hysteria2 core

5. **Traffic since the last report was dropped on removal**, as on xray.
6. **No speed limit applied.** The core's traffic hook waits on the user's
   bucket now.

### sing core

7. **A gRPC connection could not be closed.** Removing its user waited about
   95 seconds, the stream went on carrying traffic meanwhile, and the user,
   added back within that time, was refused. sing-box's gRPC server
   connection closes now (our patch), connections are closed side by side,
   and a removal waits three seconds at most.
8. **A removed user's TUIC or Hysteria QUIC connection stayed up** while
   refusing every stream: a sing-box client kept using it and got nothing
   once the user was back. The connection is closed with the user.
9. **The end of a limited download was delivered and not billed** on AnyTLS
   and gRPC (about 3.5 % of a 512 KiB download). A write that was delivered
   counted as failed when the limiter's wait was interrupted.

### Mihomo core

No fault in billing, removal, re-adding or speed limits on any of its
protocols, shared or its own.

One property of ShadowQUIC came out: it carries UDP in QUIC datagrams unless
the node sets *UDP over streams*, and a datagram holds no UDP packet larger
than about 1200 bytes, so HTTP/3 through such a node loses packets. That is
the protocol, and V2bX accepts both modes; Irboard's form now says so, and
the tests hold the stream mode to carrying a QUIC-sized packet.

## Not covered

- Device limits and online-user reports under removal.
- Clients other than mihomo, sing-box and Xray.
