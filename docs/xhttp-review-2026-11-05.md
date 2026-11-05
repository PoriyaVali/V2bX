# VLESS over XHTTP, with REALITY and TLS — review 2026-11-05

A review of VLESS XHTTP nodes on V2bX's Xray core (Xray 26.9.9, the PoriyaVali
fork v1.260909.1), with the settings Irboard stores and serves, and the
clients Irboard's subscriptions configure.

## How it was tested

`core/xray/xhttp_e2e_test.go` builds the node with this core from the panel's
`network_settings`, as `AddNode` does, and dials it through two client
families:

- an Xray client, with the `xhttpSettings` a share link gives (path, host,
  mode and `extra`), pinning the node's certificate over TLS;
- mihomo, with a Clash Meta profile's `xhttp-opts`, run from
  `core/xray/testdata/mihomoclient` because mihomo's outbounds and xray-core
  cannot share a test binary.

| Test | What it covers |
| --- | --- |
| `TestXHTTPModesOverRealityAndTLS` | `auto`, `packet-up`, `stream-up` and `stream-one`, over REALITY and over TLS, for both clients. All pass. |
| `TestXHTTPSettingsAsPanelsSendThem` | Settings shaped as a PHP panel sends them. Failed before the fix below. |
| `TestXHTTPClientsMustMatchTheNodesExtra` | Padding range, obfuscation, placement and method, uplink method, session, sequence and uplink-data placements, and client-only options. A client without them is refused, and one given them is let in. |

Irboard's real output was also run against a real node of this core, as a
one-off check: the settings `UniProxy` serves, the Clash Meta profile, and the
share link. Five cases passed for both clients: padding with obfuscation over
REALITY, placements over TLS, settings beside path and mode with no `extra`,
the default template saved as JSON, and a download leg over REALITY. The
exported profiles also pass `mihomo -t` with the pinned Mihomo v1.19.33.

## Bugs found and fixed

In V2bX:

1. **An XHTTP node with an empty `extra` never came up.** A PHP panel encodes an
   empty object as `[]`. Irboard's and Xboard's XHTTP template,
   `{"path":"/","mode":"auto","extra":{}}`, reached the node as `"extra":[]`, and
   an emptied `headers` or `xmux` did the same. Xray refuses `[]` where it wants
   an object, so `AddNode` failed with `Failed to unmarshal "extra"`. The core
   now reads an empty `extra` as `{}` and leaves out the other empty objects
   (`xhttpSettings` in `core/xray/xhttp.go`). VLESS or VMess settings that are
   entirely `[]` count as none, whatever the transport.

In Irboard (`app/Utils/Xhttp.php`):

2. **mihomo-based clients were refused by any node whose `extra` set something
   they had to match.** The Clash Meta, Mihomo, Clash Verge and Nyanpasu
   profiles carried only path, host and mode. With, for example,
   `xPaddingBytes` "1200-1500", every such client got HTTP 400. `extra` now maps
   into `xhttp-opts`, `xmux` into `reuse-settings` and `downloadSettings` into
   `download-settings`.
3. **Typed options stored as strings stopped the node.** The admin form posts
   urlencoded, so every value arrives as a string. Only some were converted,
   and for VLESS not `xPaddingObfsMode`. Xray refuses `"true"` for a boolean,
   so `AddNode` failed. Every non-string XHTTP option is now typed on save, and
   again when the node is served, which repairs nodes saved before.
4. **sing-box and Hiddify profiles gave XHTTP nodes as plain VLESS or VMess**,
   which the node refuses. sing-box has no XHTTP transport, so these nodes are
   left out. The same applies to VMess XHTTP in mihomo and Stash profiles.
5. **Stash got XHTTP nodes as plain TCP.** Stash supports VLESS XHTTP, and now
   gets it. A node that needs an option Stash does not document (uplink method,
   session, sequence or uplink-data placement) is left out.
6. **Share links lost settings that sat beside path and mode.** Without `extra`,
   Xray reads them from the top level, but the link only carried `extra`. A link
   now carries whatever the node is configured with beyond path, host and mode,
   and drops an empty `extra=[]` that clients rejected.

## Not covered

- XHTTP over HTTP/3 (QUIC). V2bX listens on TCP only.
- Hiddify's own XHTTP support (Hiddify 4.0.5+) uses a sing-box fork with a
  schema we could not verify, so its profiles leave XHTTP nodes out, as for
  sing-box.
- `allowInsecure` was removed from Xray 26 clients. Share links still carry
  `insecure=1` for nodes set to allow it. A modern Xray client needs a real
  certificate, or `pinnedPeerCertSha256`, instead.
