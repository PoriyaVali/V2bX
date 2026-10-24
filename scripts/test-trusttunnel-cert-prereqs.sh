#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_parent=$(cd -- "${TMPDIR:-/tmp}" && pwd)
test_root=$(mktemp -d)
test_root=$(cd -- "$test_root" && pwd)
trap 'status=$?; case "$test_root" in "$test_parent"/*) rm -rf -- "$test_root";;
    *) printf "Unsafe test cleanup path: %s\n" "$test_root" >&2; status=1;; esac; exit "$status"' EXIT

run_case() (
    local scenario=$1 panel_body=$2 expected=$3 curl_result=${4:-0}
    local API_HOST=https://panel.example.test API_KEY=fictional-private-api-key
    local red='' green='' yellow='' plain='' result=0
    local output="$test_root/$scenario.output" trace="$test_root/$scenario.trace"
    : > "$trace"
    # Extract only the real prerequisite function, skipping all installer
    # startup logic. Every network/firewall operation is replaced below.
    source <(sed -n '/^trusttunnel_cert_prereqs() {/,/^# The trusttunnel core/p' "$repo_root/install.sh" | sed '$d')
    curl() { printf '%s' "$panel_body"; return "$curl_result"; }
    ufw() { printf 'ufw:%s\n' "$*" >> "$trace"; printf 'Status: inactive\n'; }
    firewall-cmd() { printf 'firewalld:%s\n' "$*" >> "$trace"; return 1; }
    ss() { printf 'ss:%s\n' "$*" >> "$trace"; }
    trusttunnel_cert_prereqs 1 > "$output" 2>&1 || result=$?
    if [[ "$expected" == fail ]]; then
        [[ "$result" != 0 ]] || { cat "$output"; return 1; }
        # Rejecting panel data must not expose the API key, raw response or an
        # untrusted mode, nor change any firewall rules before rejecting it.
        ! grep -qE 'fictional-private-api-key|fictional-private-response|Panel says: self-signed' "$output"
        [[ ! -s "$trace" ]]
    else
        [[ "$result" == 0 ]] || { cat "$output"; return 1; }
    fi
    printf 'PASS trusttunnel_cert_%s\n' "$scenario"
)

run_case self_signed '{"cert_type":"self-signed"}' pass
run_case letsencrypt '{"cert_type":"letsencrypt","acme_email":"admin@example.test"}' pass
run_case provided '{"cert_type":"provided","cert_chain_path":"/future/fullchain.pem","cert_key_path":"/future/private.key"}' pass
run_case offline '' pass 28
run_case unknown '{"cert_type":"fictional-private-response","api_key":"fictional-private-api-key"}' fail
run_case missing '{"api_key":"fictional-private-api-key"}' fail
run_case empty '{"cert_type":""}' fail
run_case null '{"cert_type":null}' fail
run_case malformed 'fictional-private-response' fail
run_case missing_email '{"cert_type":"letsencrypt"}' fail
run_case empty_email '{"cert_type":"letsencrypt","acme_email":""}' fail
run_case whitespace_email '{"cert_type":"letsencrypt","acme_email":"   "}' fail
run_case missing_chain '{"cert_type":"provided","cert_key_path":"/future/private.key"}' fail
run_case missing_key '{"cert_type":"provided","cert_chain_path":"/future/fullchain.pem"}' fail
run_case empty_chain '{"cert_type":"provided","cert_chain_path":"","cert_key_path":"/future/private.key"}' fail
run_case whitespace_key '{"cert_type":"provided","cert_chain_path":"/future/fullchain.pem","cert_key_path":"   "}' fail

(
    case_dir="$test_root/manual_wizard"
    mkdir -p "$case_dir/config"
    printf 'existing operator configuration\n' > "$case_dir/config/config.json"
    printf 'existing operator backup\n' > "$case_dir/config/config.json.bak"
    cp "$case_dir/config/config.json" "$case_dir/original"
    cp "$case_dir/config/config.json.bak" "$case_dir/original.bak"
    source <(sed -n '/^trusttunnel_cert_prereqs() {/,/^# The trusttunnel core/p' "$repo_root/install.sh" | sed '$d')
    source <(sed -n '/^generate_config() {/,/^gen_x25519() {/p' "$repo_root/install.sh" | sed '$d' |
        sed "s|/etc/V2bX|$case_dir/config|g")
    V2BX_MANUAL_WIZARD=1 red='' green='' yellow='' plain=''
    curl() { printf '{"cert_type":"fictional-private-response"}'; }
    install_trusttunnel_bins() { return 0; }
    read() {
        local variable="${!#}" value=''
        case "$variable" in
            API_HOST) value=https://panel.example.test ;;
            API_KEY) value=fictional-private-api-key ;;
            BLOCKED) value=none ;;
            NODE_ID) value=1 ;;
            core_choice) value=5 ;;
            add_more) value=n ;;
        esac
        printf -v "$variable" '%s' "$value"
    }
    result=0
    generate_config > "$case_dir/output" 2>&1 || result=$?
    [[ "$result" != 0 ]]
    cmp "$case_dir/original" "$case_dir/config/config.json"
    cmp "$case_dir/original.bak" "$case_dir/config/config.json.bak"
    ! grep -qE 'fictional-private-api-key|fictional-private-response' "$case_dir/output"
    printf 'PASS trusttunnel_cert_manual_wizard_preserves_config\n'
)
