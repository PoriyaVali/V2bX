#!/usr/bin/env bash
# Turn on real-client-address recovery for a node behind the Iran relay.
#
# Run this ON THE FOREIGN SERVER, after `v2bx update && v2bx restart` has put
# V2bX >= v1.3.9 in place. The Iran relay needs NOTHING: it already prefixes
# every forwarded stream with the client's address unconditionally
# (internal/ingress/hub.go), and `proxy_protocol` exists only in the foreign
# side's config.
#
# Two switches have to agree, which is why doing this by hand goes wrong:
#   - the hedioum egress must WRAP that address in a PROXY v2 header
#   - V2bX's sing inbound must ACCEPT one
# Neither alone changes anything, so a half-done setup looks exactly like an
# untouched one.
#
# Safe to run on a server that also serves direct users: the header is believed
# only from a loopback peer, so a direct connection is passed through untouched.
#
#   ./enable-tunnel-realip.sh            # every sing node on this box
#   ./enable-tunnel-realip.sh --off      # undo
set -euo pipefail

V2BX_CONF=${V2BX_CONF:-/etc/V2bX/config.json}
HED_CONF=${HED_CONF:-/etc/hedioum/hedioum.json}
STAMP=$(date +%Y%m%d_%H%M%S)
WANT=true
[[ ${1:-} == "--off" ]] && WANT=false

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }

need() { command -v "$1" >/dev/null || { red "missing required tool: $1"; exit 1; }; }
need python3

# --- preflight -------------------------------------------------------------
# Refuse rather than half-apply: leaving one side on is the confusing state.
for f in "$V2BX_CONF" "$HED_CONF"; do
    [[ -f $f ]] || { red "not found: $f"; red "run this on the FOREIGN server, after the tunnel has been set up there."; exit 1; }
done

ver=$(V2bX version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
if [[ -n $ver ]]; then
    info "V2bX $ver"
    # v1.3.9 is the first build whose sing-box parses the header at all; before
    # it, switching the option on made the inbound refuse to bind.
    if [[ $(printf '%s\nv1.3.9\n' "$ver" | sort -V | head -1) != "v1.3.9" && $ver != "v1.3.9" ]]; then
        red "V2bX $ver is older than v1.3.9 — run 'v2bx update' first, or the inbound will fail to bind."
        exit 1
    fi
fi

echo "== backing up =="
cp -a "$V2BX_CONF" "${V2BX_CONF}.bak_realip_${STAMP}"
cp -a "$HED_CONF"  "${HED_CONF}.bak_realip_${STAMP}"
info "${V2BX_CONF}.bak_realip_${STAMP}"
info "${HED_CONF}.bak_realip_${STAMP}"

# --- V2bX: SingOptions.ProxyProtocol on every sing node --------------------
echo "== V2bX =="
python3 - "$V2BX_CONF" "$WANT" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2] == "true"
cfg = json.load(open(path, encoding="utf-8"))
touched = []
for node in cfg.get("Nodes", []):
    if str(node.get("Core", "")).lower() != "sing":
        continue
    opts = node.setdefault("SingOptions", {})
    if opts.get("ProxyProtocol") != want:
        opts["ProxyProtocol"] = want
        touched.append(node.get("NodeID"))
if touched:
    json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"  ProxyProtocol={want} on node(s): {', '.join(map(str, touched))}")
else:
    print(f"  already ProxyProtocol={want} — nothing to change")
PY

# --- hedioum: proxy_protocol ----------------------------------------------
echo "== hedioum =="
python3 - "$HED_CONF" "$WANT" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2] == "true"
cfg = json.load(open(path, encoding="utf-8"))
if cfg.get("proxy_protocol") == want:
    print(f"  already proxy_protocol={want} — nothing to change")
else:
    cfg["proxy_protocol"] = want
    json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"  proxy_protocol={want}")
PY

# --- restart both, in the order that keeps the gap shortest ---------------
echo "== restarting =="
hed_unit=$(systemctl list-units --type=service --all --plain --no-legend 2>/dev/null \
           | awk '{print $1}' | grep -i hedioum | head -1 || true)
if [[ -n $hed_unit ]]; then
    systemctl restart "$hed_unit" && info "restarted $hed_unit"
else
    red "  could not find the hedioum service — restart it yourself, or the header is still not sent"
fi
V2bX restart >/dev/null 2>&1 && info "restarted V2bX" || red "  V2bX restart failed"

# --- verify ---------------------------------------------------------------
# `V2bX log` follows the journal and never returns, which hung the script right
# after it had already made every change - the worst place to stop, because it
# looks like the change failed when it had actually finished. Read a bounded
# snapshot instead.
echo "== check =="
sleep 3
snapshot=$(journalctl -u V2bX --no-pager -n 60 --since '-1min' 2>/dev/null || true)
if [[ -z $snapshot ]]; then
    info "no journal available — check manually with: V2bX log"
elif grep -qiE 'failed to (start|bind)|address already in use|proxy protocol' <<<"$snapshot"; then
    red "  the log reports a problem:"
    grep -iE 'failed to (start|bind)|address already in use|proxy protocol' <<<"$snapshot" | tail -3 | sed 's/^/    /'
    red "  roll back with:  $0 --off"
else
    grn "  inbounds came up clean"
fi

# A tunnelled inbound that cannot complete TLS is the failure this change can
# cause, and it is invisible from the node's own log - so prove the handshake
# still works rather than assuming it.
if [[ $WANT == true ]]; then
    port=$(python3 - "$V2BX_CONF" <<'PY' 2>/dev/null || true
import json,sys
cfg=json.load(open(sys.argv[1],encoding="utf-8"))
for n in cfg.get("Nodes",[]):
    p=(n.get("SingOptions") or {}).get("ListenPort") or n.get("ListenPort")
    if p: print(p); break
PY
)
    if [[ -n ${port:-} ]] && command -v openssl >/dev/null; then
        if echo | timeout 15 openssl s_client -connect "127.0.0.1:${port}" 2>/dev/null | grep -q "^subject="; then
            grn "  local TLS on :${port} still completes"
        else
            red "  local TLS on :${port} did NOT complete — users may be cut off."
            red "  roll back now:  $0 --off"
        fi
    fi
fi
if [[ $WANT == true ]]; then
cat <<'EOT'

Now watch the panel: this node should start reporting online users within about
a minute, where before it reported none. If it still reports none, the header is
not arriving - check that the hedioum service really restarted, and that this
node's traffic actually comes through the relay rather than direct.
EOT
else
cat <<'EOT'

Real-address recovery is off. Tunnelled users are back to arriving as 127.0.0.1,
so this node reports no online users and enforces no device limit - the state it
was in before. Their connections are unaffected.
EOT
fi
