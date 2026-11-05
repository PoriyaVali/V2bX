#!/usr/bin/env bash
# Real ACME issuance and renewal for the TrustTunnel core.
#
#   sudo scripts/e2e/trusttunnel-acme/run.sh /path/to/endpoint-and-wizard
#
# Starts two local Pebble CAs - one issuing 31-day certificates (not due for
# renewal), one issuing 29-day certificates (due at once) - and a mock DNS that
# resolves every name to 127.0.0.1, then runs core/trusttunnel's acme_e2e tests
# against the given trusttunnel_endpoint and setup_wizard. Needs Linux, Go and
# root: HTTP-01 is answered on port 80, as on a node. Nothing leaves the host.
set -euo pipefail

bin="$(cd "${1:?usage: run.sh DIR_WITH_trusttunnel_endpoint_AND_setup_wizard}" && pwd)"
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
pebble_version=v2.10.0
work="$(mktemp -d)"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$work"
}
trap cleanup EXIT

echo "== building Pebble $pebble_version"
GOBIN="$work/bin" GOFLAGS= go install \
    "github.com/letsencrypt/pebble/v2/cmd/pebble@$pebble_version" \
    "github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@$pebble_version"
src="$(GOFLAGS= go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@$pebble_version"

# Pebble validates challenges itself; a proxy in the environment would send its
# requests for the test hostnames somewhere that cannot answer them.
noproxy=(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY -u all_proxy)

"${noproxy[@]}" "$work/bin/pebble-challtestsrv" -defaultIPv4 127.0.0.1 -defaultIPv6 "" \
    -dnsserver 127.0.0.1:8053 -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -management 127.0.0.1:8055 >"$work/dns.log" 2>&1 &
pids+=($!)

start_ca() { # NAME PORT MGMT_PORT VALIDITY_DAYS
    cat >"$work/$1.json" <<JSON
{"pebble": {
  "listenAddress": "127.0.0.1:$2", "managementListenAddress": "127.0.0.1:$3",
  "certificate": "$src/test/certs/localhost/cert.pem",
  "privateKey": "$src/test/certs/localhost/key.pem",
  "httpPort": 80, "tlsPort": 5001, "ocspResponderURL": "",
  "externalAccountBindingRequired": false, "retryAfter": {"authz": 1, "order": 1},
  "profiles": {"default": {"description": "$4 days", "validityPeriod": $(($4 * 86400))}}
}}
JSON
    "${noproxy[@]}" PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=0 \
        "$work/bin/pebble" -config "$work/$1.json" -dnsserver 127.0.0.1:8053 >"$work/$1.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 1 100); do
        curl -fsk "https://localhost:$2/dir" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    echo "the $1 CA did not start:"; cat "$work/$1.log"; return 1
}
start_ca long 14000 15000 31
start_ca due 14001 15001 29

cd "$repo"
V2BX_TEST_TRUSTTUNNEL_BIN="$bin" \
V2BX_TEST_ACME_LONG=https://localhost:14000 V2BX_TEST_ACME_LONG_MGMT=https://localhost:15000 \
V2BX_TEST_ACME_DUE=https://localhost:14001 V2BX_TEST_ACME_DUE_MGMT=https://localhost:15001 \
LEGO_CA_CERTIFICATES="$src/test/certs/pebble.minica.pem" \
    go test -tags acme_e2e -count=1 -v -run '^TestACME_' ./core/trusttunnel/
