#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_parent=$(cd -- "${TMPDIR:-/tmp}" && pwd)
test_root=$(mktemp -d)
test_root=$(cd -- "$test_root" && pwd)
trap 'status=$?; case "$test_root" in "$test_parent"/*) rm -rf -- "$test_root";;
    *) printf "Unsafe test cleanup path: %s\n" "$test_root" >&2; status=1;; esac; exit "$status"' EXIT

run_case() (
    local scenario=$1 requested=$2 expected=$3 expected_trace=$4
    local GITHUB_REPO=example/repo last_version=stale-v9
    local red="" green="" plain="" trace="$test_root/$1.trace" result=0
    : > "$trace"
    # Execute the actual resolver and update entry, without OS/root checks or
    # the real installer/service manager. The archive transaction has its own
    # integration suite, including successful downgrade lookups.
    source <(sed -n '/^github_release_tag() {/,/^# Install TrustTunnel endpoint/p' "$repo_root/install.sh" | sed '$d')
    source <(sed -n '/^update_V2bX() {/,/^}/p' "$repo_root/install.sh")
    curl() {
        local path="${!#}" tag reply status=200
        [[ "$path" == "https://api.github.com/repos/example/repo/releases/"* ]] || return 99
        path=${path#https://api.github.com/repos/example/repo/releases/}
        printf '%s\n' "$path" >> "$trace"
        case "$scenario" in
            network_fail|latest_network_fail) return 28 ;;
            forbidden) printf '{}\n403'; return 0 ;;
            server_error) printf '{}\n503'; return 0 ;;
            malformed) printf 'not json\n200'; return 0 ;;
            wrong_tag) printf '{"tag_name":"v9.9.9"}\n200'; return 0 ;;
            unsafe_latest) printf '{"tag_name":"../bad"}\n200'; return 0 ;;
            empty_tag) printf '{"tag_name":""}\n200'; return 0 ;;
            missing) status=404 ;;
        esac
        if [[ "$path" == latest ]]; then
            reply=v1.7.4
        else
            tag=${path#tags/}
            reply=$tag
            case "$scenario" in
                bare|prefixed|compact|prerelease) [[ "$tag" == v* ]] || status=404 ;;
                bare_tag) [[ "$tag" != v* ]] || status=404 ;;
                custom_missing) status=404 ;;
            esac
        fi
        if [[ "$status" == 404 ]]; then
            printf '{"message":"Not Found"}\n404'
        elif [[ "$scenario" == compact ]]; then
            printf '{"other":"value","tag_name":"%s"}\n200' "$reply"
        else
            printf '{\n  "tag_name": "%s",\n  "name": "Release"\n}\n200' "$reply"
        fi
    }
    install_V2bX() { printf 'install:%s\n' "$last_version" >> "$trace"; }
    show_status() { return 0; }
    update_V2bX "$requested" > "$test_root/$scenario.output" 2>&1 || result=$?
    if [[ "$expected" == FAIL ]]; then
        [[ "$result" != 0 && -z "$last_version" ]] || { cat "$test_root/$scenario.output"; return 1; }
        ! grep -q '^install:' "$trace"
    else
        [[ "$result" == 0 && "$last_version" == "$expected" ]] || { cat "$test_root/$scenario.output"; return 1; }
        expected_trace+=$'\n'"install:$expected"
    fi
    [[ "$(cat "$trace")" == "$expected_trace" ]] || { cat "$trace"; return 1; }
    printf 'PASS release_%s\n' "$scenario"
)

run_case bare 1.7.2 v1.7.2 $'tags/1.7.2\ntags/v1.7.2'
run_case prefixed v1.7.2 v1.7.2 'tags/v1.7.2'
run_case bare_tag v1.7.2 1.7.2 $'tags/v1.7.2\ntags/1.7.2'
run_case both_tags 1.7.2 1.7.2 'tags/1.7.2'
run_case custom nightly-202610 nightly-202610 'tags/nightly-202610'
run_case custom_missing nightly-202610 FAIL 'tags/nightly-202610'
run_case prerelease 1.7.4-rc.1 v1.7.4-rc.1 $'tags/1.7.4-rc.1\ntags/v1.7.4-rc.1'
run_case compact 1.7.2 v1.7.2 $'tags/1.7.2\ntags/v1.7.2'
run_case latest '' v1.7.4 latest
run_case missing 1.7.2 FAIL $'tags/1.7.2\ntags/v1.7.2'
run_case forbidden 1.7.2 FAIL 'tags/1.7.2'
run_case server_error 1.7.2 FAIL 'tags/1.7.2'
run_case network_fail 1.7.2 FAIL 'tags/1.7.2'
run_case latest_network_fail '' FAIL latest
run_case malformed 1.7.2 FAIL 'tags/1.7.2'
run_case wrong_tag 1.7.2 FAIL 'tags/1.7.2'
run_case unsafe_latest '' FAIL latest
run_case empty_tag 1.7.2 FAIL 'tags/1.7.2'
run_case invalid_path ../1.7.2 FAIL ''
run_case invalid_shell '1.7.2;echo injected' FAIL ''
