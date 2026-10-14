# Filtering in Iran: techniques and countermeasures — 14 October 2026

What Iranian networks are reported to do to proxy traffic, what V2bX does
about each technique, and what is left to the operator or the client. A node
can only do part of the job: much of what a censor sees is the client's own
handshake, and an address that has been blocked stays blocked whatever the
node does.

Evidence is cited per row. Reports from one person or one ISP are marked as
such. Conditions differ between ISPs (MCI, MTN Irancell, TCI and others) and
change over months.

## Techniques and what V2bX does

| # | Technique reported | Evidence | V2bX now | Left to the operator / client |
| --- | --- | --- | --- | --- |
| 1 | **Protocol whitelisting on TCP 53, 80, 443.** A connection lives only if its first two data packets look like DNS, HTTP or TLS. Otherwise the client's traffic is dropped for about 60 s. | Bock et al., FOCI 2020. Seen again during the 2025 shutdown (arXiv 2507.14183). | Warns at node start when Shadowsocks, or VMess/VLESS without TLS on raw TCP, listens on one of those ports (`node/filtering.go`). | Move such nodes to other ports, or use TLS/REALITY. |
| 2 | **Active probing.** Connect, finish the TLS handshake, send an ordinary request, and see whether a web server answers. CPU spikes from probes have been reported on REALITY servers. | XTLS/Xray-core discussion #3269. net4people/bbs #359. | A stranger who finishes the handshake gets the node's own decoy site, served over HTTP/1.1 and h2. This now covers anytls, Hysteria2 on both the sing and hysteria2 cores (as the masquerade, when none is configured), and Xray VLESS/Trojan over TCP+TLS (as the fallback, when none is configured). REALITY already relays strangers to its target. Opt out with `DecoySite: false`. | Avoid self-signed certificates: V2bX warns about them. |
| 3 | **Replaying a captured REALITY ClientHello.** If the replay is authenticated, the prober sees the node's own handshake instead of the target's. | REALITY's `maxTimeDiff` exists for this. | Xray nodes now get the panel's `MaxTimeDiff` in the milliseconds Xray expects. They used to get microseconds, so a window of `90s` became 25 hours. sing nodes were already correct. | Set `MaxTimeDiff` in the panel (for example `90s`). This assumes clients' clocks are roughly right. |
| 4 | **Address reputation driven by traffic volume.** A fresh address works for days to weeks, then gets blocked. Heavier use gets blocked sooner. | #3269 field tests (100–120 GB on Irancell). Alaraj & Wustrow, ASIA CCS '25, as cited in IsaHo/IsaHo#32. | REALITY nodes on Xray hold an unauthenticated relay to 64 KiB/s after its first 4 MiB in each direction. This stops strangers running bulk traffic through the address, a documented abuse (net4people/bbs #359). Configurable with `RealityFallbackAfterKB` / `RealityFallbackKBps`; a negative value turns it off. sing-box's REALITY has no such limit. | Spread users across addresses and keep spare ones. A blocked address is a reason to move, not to retune. |
| 5 | **QUIC and unidentified UDP blocked** on most ISPs since mid-2025. WebRTC/UDP is fully blocked during blackouts. | net4people/bbs #489, #626. IsaHo/IsaHo#32. | Logs a note at start for Hysteria, Hysteria2 and TUIC nodes. TUIC now sends with BBR unless the panel picks an algorithm: sing-box would use CUBIC, which halves its rate on every radio loss. | Keep a TCP node (REALITY or anytls) for those users. |
| 6 | **Throttling and loss.** Foreign upload below 1 Mbit/s and about 100 KB/s are reported, with packet loss on mobile paths. | #489, #626. | Unchanged from 1.7.x: BBR per connection and `TCP_NOTSENT_LOWAT` on both cores, plus the installer's `fq`, `tcp_slow_start_after_idle=0` and `tcp_mtu_probing=1`. New: Xray's handshake allowance went from 4 s to 10 s. On a lossy path with a one-second round trip, a TLS handshake needing two retransmissions used to be killed just before it would have finished. sing allows 60 s. AnyTLS: a client closes a reused session unless a new stream is acknowledged within 3 s, and the node now acknowledges as soon as the stream opens, not after sniffing, DNS and the dial. A control frame's 5 s deadline no longer cuts a slow download or closes the session, and writes over 64 KiB are split into frames instead of corrupting the session (`third_party/README.md`). | Run the installer's network tuning (`v2bx menu`, BBR). |
| 7 | **Silent drops with ICMP blocked.** MCI and TCI block ICMP after a few packets, so path-MTU discovery fails and large packets vanish. | #489. | Unchanged: the installer sets `tcp_mtu_probing=1`. | — |
| 8 | **Vanishing mobile clients and NAT timeouts.** A phone that loses signal or changes network sends no FIN. | Common on mobile networks. | Xray listeners now use TCP keepalive (120 s idle, 20 s interval), the same as sing nodes. Xray had it off. Configurable with `TCPKeepAliveIdle` / `TCPKeepAliveInterval`; negative turns it off. | — |
| 9 | **Plain WebSocket filtered on port 80.** Packets containing "websocket" are dropped from the 7th packet on. | #489 (one report, July 2025). | Warns at start for ws/httpupgrade without TLS on port 80. | Use TLS, or the xhttp transport. |
| 10 | **SNI filtering, SNI whitelists during shutdowns, and an IP/SNI mismatch suspected for REALITY.** For example, a cloud provider's address presenting a big brand's name. | #3269. #626. | At start, each REALITY node (anytls or VLESS) checks its target in the background, the way every handshake uses it. The log says whether the target is unusable (unreachable, or no TLS 1.3 with X25519, so every REALITY handshake fails) or slow (every new connection waits on it). It also says whether the target's certificate fails to cover the server name, which a prober would notice. Xray itself warns about apple, icloud, microsoft and `.ir` targets. | Prefer a REALITY target hosted near the node's own network, or the operator's own domain. |
| 11 | **Fragmented ClientHellos dropped** from about 27 July 2026. | Lantern circumvention corpus and IsaHo/IsaHo#32. Secondary sources; not verified against a primary report. | — (a client-side technique). | Clients that fragment the ClientHello should test with and without it. |
| 12 | **TLS 1.3 to suspected VPS addresses failing on MTN Irancell while TLS 1.2 works.** | #3269 (users' reports, 2026). | TLS nodes already accept TLS 1.2 on both cores. REALITY requires TLS 1.3. | A client on Irancell may try TLS 1.2 on a plain-TLS node. |

## Client compatibility that looked like blocking

**REALITY on Xray refused mihomo and sing-box clients.** xtls/reality
`8cdf7bf9`, shipped with Xray 26.9.8/26.9.9, stopped authenticating ClientHellos
that carry no X25519MLKEM768 key share. Those connections are relayed to the
target site, the client reports "reality verification failed", and the node
logs nothing.

- mihomo sends that share only when a profile sets
  `reality-opts.support-x25519mlkem768: true`.
- sing-box clients (Hiddify, NekoBox, Karing, sing-box) never send it
  (SagerNet/sing-box#4520).

V2bX pins REALITY one commit earlier, which reverts exactly that check.
`core/xray/reality_compat_test.go` dials a real node with both kinds of hello.
anytls REALITY nodes (sing-box's own implementation) were never affected.

## Not done, and why

- **Trojan decoy on the sing core.** sing-box routes a trojan fallback through
  the router. There, V2bX's private-destination rules refuse `127.0.0.1`, as
  they must, or subscribers could reach the node's own services. This would
  need the sing-box fork to dial the fallback directly, as it already does for
  anytls.
- **REALITY fallback limit on sing nodes.** sing-box's REALITY has no such
  option.
- **Port hopping for Hysteria2.** The client hops; the server needs a
  firewall rule redirecting a port range, which is host configuration rather
  than V2bX's. With UDP blocked on most ISPs (row 5), it would rarely help.

## Sources

- K. Bock et al., "Detecting and Evading Censorship-in-Depth: A Case Study of Iran's Protocol Whitelister", USENIX FOCI 2020 — https://www.usenix.org/conference/foci20/presentation/bock, https://geneva.cs.umd.edu/posts/iran-whitelister/
- A. Aryapour, "Iran's Stealth Internet Blackout: A New Model of Censorship", arXiv 2507.14183 — https://arxiv.org/abs/2507.14183
- net4people/bbs #489, "Iran networks after the shutdowns (since 2025-06-25)" — https://github.com/net4people/bbs/issues/489
- net4people/bbs #626, "Internet analysis in the shutdown in iran" — https://github.com/net4people/bbs/issues/626
- net4people/bbs #359, "REALITY servers in Iran being abused as sort-of SNI proxies" — https://github.com/net4people/bbs/issues/359
- XTLS/Xray-core discussion #3269, "Investigation on Blocking of Reality in IRAN" — https://github.com/XTLS/Xray-core/discussions/3269
- SagerNet/sing-box #4520, REALITY and X25519MLKEM768 — https://github.com/SagerNet/sing-box/issues/4520
- S. Tai et al., "IRBlock", USENIX Security 2025 — https://www.usenix.org/system/files/usenixsecurity25-tai.pdf
- IsaHo/IsaHo #32, anti-filtering research and roadmap — https://github.com/IsaHo/IsaHo/pull/32
- Lantern circumvention corpus, SNI-based blocking — https://corpus.lantern.io/techniques/sni-blocking/
