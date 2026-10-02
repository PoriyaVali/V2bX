#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'status=$?; if (( status != 0 )) && [[ -n "${scenario:-}" ]]; then
    printf "FAIL %s\n" "$scenario" >&2
    [[ ! -f "$test_root/$scenario/output" ]] || cat "$test_root/$scenario/output" >&2
    [[ ! -f "$test_root/$scenario/trace" ]] || cat "$test_root/$scenario/trace" >&2
fi; rm -rf -- "$test_root"; exit "$status"' EXIT

mkdir -p "$test_root/fixture" "$test_root/endpoint"
cat > "$test_root/fixture/V2bX" <<'EOF'
#!/usr/bin/env bash
printf 'validate\n' >> "$INSTALL_UPDATE_TRACE"
[[ "$1" == version ]]
EOF
chmod +x "$test_root/fixture/V2bX"
printf '{}\n' > "$test_root/fixture/config.json"
printf 'new database\n' > "$test_root/fixture/geoip.dat"
(cd "$test_root/fixture" && zip -q "$test_root/valid.zip" V2bX config.json geoip.dat)
cat > "$test_root/endpoint/trusttunnel_endpoint" <<'EOF'
#!/usr/bin/env bash
printf 'validate-endpoint\n' >> "$INSTALL_UPDATE_TRACE"
[[ "$1" == --version ]]
EOF
printf '#!/usr/bin/env bash\n# new wizard\n' > "$test_root/endpoint/setup_wizard"
printf '#!/usr/bin/env bash\n# old endpoint\n' > "$test_root/old-endpoint"
printf '#!/usr/bin/env bash\n# old wizard\n' > "$test_root/old-wizard"
chmod +x "$test_root/endpoint/"*
(cd "$test_root/endpoint" && zip -q "$test_root/endpoint.zip" trusttunnel_endpoint setup_wizard)
(cd "$test_root/endpoint" && zip -q "$test_root/missing-wizard.zip" trusttunnel_endpoint)

run_case() (
    local scenario=$1 case_dir="$test_root/$1"
    mkdir -p "$case_dir/usr/local/V2bX" "$case_dir/etc/V2bX" "$case_dir/usr/bin" \
        "$case_dir/etc/systemd/system" "$case_dir/etc/init.d"
    printf 'old executable\n' > "$case_dir/usr/local/V2bX/V2bX"
    printf 'old database\n' > "$case_dir/usr/local/V2bX/geoip.dat"
    printf 'old unit\n' > "$case_dir/etc/systemd/system/V2bX.service"
    printf 'old openrc unit\n' > "$case_dir/etc/init.d/V2bX"
    printf 'active\n' > "$case_dir/service-state"
    if [[ "$scenario" == update_inactive* ]]; then printf 'inactive\n' > "$case_dir/service-state"; fi
    if [[ "$scenario" == update_existing_config ]]; then
        printf 'operator configuration\n' > "$case_dir/etc/V2bX/config.json"
    fi
    if [[ "$scenario" == endpoint_* ]]; then
        cp "$test_root/old-endpoint" "$case_dir/usr/local/V2bX/trusttunnel_endpoint"
        cp "$test_root/old-wizard" "$case_dir/usr/local/V2bX/setup_wizard"
        chmod +x "$case_dir/usr/local/V2bX/trusttunnel_endpoint" "$case_dir/usr/local/V2bX/setup_wizard"
        printf 'tt-v1\n' > "$case_dir/usr/local/V2bX/.trusttunnel_version"
        [[ "$scenario" != endpoint_unchanged ]] || printf 'tt-v2\n' > "$case_dir/usr/local/V2bX/.trusttunnel_version"
        [[ "$scenario" != endpoint_incomplete_lookup ]] || rm -f "$case_dir/usr/local/V2bX/setup_wizard"
    fi
    export INSTALL_UPDATE_TRACE="$case_dir/trace"
    : > "$INSTALL_UPDATE_TRACE"
    local release=debian GITHUB_REPO=example/repo last_version=v1 arch=64
    local red="" green="" yellow="" plain=""

    # No installer entry point, networking or actual service manager is run.
    # Extract production functions; relocate ALL their absolute write paths.
    source <(sed -n '/^stage_trusttunnel_bins() {/,/^setup_systemd() {/p' "$repo_root/install.sh" |
        sed '$d' | sed "s|/usr/local/V2bX|$case_dir/usr/local/V2bX|g; s|/etc/V2bX|$case_dir/etc/V2bX|g; s|/usr/bin/|$case_dir/usr/bin/|g; s|/etc/systemd/system/|$case_dir/etc/systemd/system/|g; s|/etc/init.d/|$case_dir/etc/init.d/|g")
    source <(sed -n '/^update_V2bX() {/,/^}/p' "$repo_root/install.sh")

    service_mock() {
        local operation=$1
        case "$operation" in
            is-active|status) [[ "$(cat "$case_dir/service-state")" == active ]]; return $? ;;
            daemon-reload) return 0 ;;
        esac
        printf '%s\n' "$operation" >> "$INSTALL_UPDATE_TRACE"
        if [[ "$operation" == restart ]]; then return 99; fi
        if [[ "$operation" == stop ]]; then
            if [[ "$scenario" == recovery_stop_fail && -f "$case_dir/new-started" ]]; then return 1; fi
            printf 'inactive\n' > "$case_dir/service-state"
            if [[ "$scenario" == stop_fail && ! -f "$case_dir/stop-attempt" ]]; then
                : > "$case_dir/stop-attempt"; return 1
            fi
        fi
        if [[ "$operation" == start ]]; then
            if [[ "$scenario" == start_fail && ! -f "$case_dir/start-attempt" ]]; then
                : > "$case_dir/start-attempt"; return 1
            fi
            if [[ "$scenario" == recovery_start_fail ]]; then return 1; fi
            : > "$case_dir/new-started"
            printf 'active\n' > "$case_dir/service-state"
        fi
        return 0
    }
    systemctl() { service_mock "$1"; }
    rc-service() { service_mock "$2"; }
    setup_systemd() {
        printf 'new unit\n' > "$case_dir/etc/systemd/system/V2bX.service"
        [[ "$scenario" != setup_fail && "$scenario" != endpoint_setup_fail && "$scenario" != update_inactive_fail ]]
    }
    setup_openrc() { printf 'new openrc unit\n' > "$case_dir/etc/init.d/V2bX"; }
    get_version() { return 0; }
    show_status() { return 0; }
    sleep() { return 0; }

    # The health poll still runs for real; only its service-PID samples are
    # controlled. A command succeeding without a stable process must fail.
    v2bx_service_pid() {
        [[ "$(cat "$case_dir/service-state")" == active ]] || return 1
        compgen -G "$case_dir/usr/local/V2bX/.V2bX.rollback.*" >/dev/null || return 1
        [[ "$scenario" != recovery_health_fail ]] || return 1
        if ! grep -qx 'old executable' "$case_dir/usr/local/V2bX/V2bX"; then
            if [[ "$scenario" == health_fail || "$scenario" == endpoint_health_fail ||
                  "$scenario" == openrc_health_fail || "$scenario" == recovery_stop_fail ]]; then return 1; fi
            if [[ "$scenario" == health_flapping ]]; then
                local attempt=0
                [[ ! -f "$case_dir/health-count" ]] || read -r attempt < "$case_dir/health-count"
                ((attempt += 1))
                printf '%s\n' "$attempt" > "$case_dir/health-count"
                printf '%s\n' "$((4000 + attempt))"; return 0
            fi
        fi
        printf '4242\n'
    }
    curl() {
        [[ "$scenario" != endpoint_lookup_fail && "$scenario" != endpoint_incomplete_lookup ]] || return 1
        printf '{"tag_name":"tt-v2"}\n'
    }
    wget() {
        local output="" url="${!#}"
        printf 'download\n' >> "$INSTALL_UPDATE_TRACE"
        [[ "$scenario" != download_fail && "$scenario" != update_fail ]] || return 1
        while (( $# > 0 )); do
            if [[ "$1" == -O ]]; then output=$2; shift 2; else shift; fi
        done
        if [[ "$url" == *TrustTunnel-* ]]; then
            [[ "$scenario" != endpoint_download_fail ]] || return 1
            if [[ "$scenario" == endpoint_archive_fail ]]; then printf 'bad zip\n' > "$output"
            elif [[ "$scenario" == endpoint_missing_wizard ]]; then cp "$test_root/missing-wizard.zip" "$output"
            elif [[ "$scenario" == endpoint_binary_fail ]]; then
                mkdir -p "$case_dir/bad-endpoint"
                printf '#!/usr/bin/env bash\nexit 1\n' > "$case_dir/bad-endpoint/trusttunnel_endpoint"
                cp "$test_root/endpoint/setup_wizard" "$case_dir/bad-endpoint/setup_wizard"
                (cd "$case_dir/bad-endpoint" && zip -q "$output" trusttunnel_endpoint setup_wizard)
            else cp "$test_root/endpoint.zip" "$output"; fi
        elif [[ "$scenario" == archive_fail ]]; then printf 'not a zip\n' > "$output"
        elif [[ "$scenario" == binary_fail ]]; then
            mkdir -p "$case_dir/bad"
            printf '#!/usr/bin/env bash\nexit 1\n' > "$case_dir/bad/V2bX"
            (cd "$case_dir/bad" && zip -q "$output" V2bX)
        else cp "$test_root/valid.zip" "$output"; fi
    }
    mv() {
        if [[ "$scenario" == replace_fail && "$*" == *".V2bX.new."* ]]; then return 1; fi
        if [[ "$scenario" == support_replace_fail && "$*" == *".V2bX.new."* && "${!#}" == *geoip.dat ]]; then return 1; fi
        if [[ "$scenario" == endpoint_replace_fail && "$*" == *".V2bX.new."* && "${!#}" == *setup_wizard ]]; then return 1; fi
        if [[ "$scenario" == recovery_restore_fail && "$*" == *".restore."* ]]; then return 1; fi
        command mv "$@"
    }
    if [[ "$scenario" == recovery_restore_fail ]]; then setup_systemd() { return 1; }; fi
    if [[ "$scenario" == openrc* ]]; then release=alpine; fi

    local result=0
    if [[ "$scenario" == update_* || "$scenario" == endpoint_* || "$scenario" == openrc_update ]]; then
        update_V2bX v1 > "$case_dir/output" 2>&1 || result=$?
    else
        install_V2bX > "$case_dir/output" 2>&1 || result=$?
    fi
    local operations
    operations=$(grep -E '^(stop|start|restart)$' "$INSTALL_UPDATE_TRACE" || true)
    case "$scenario" in
        success|openrc|update_success|openrc_update|update_existing_config|endpoint_changed|endpoint_unchanged|endpoint_lookup_fail)
            [[ "$result" == 0 ]] || { cat "$case_dir/output"; return 1; }
            [[ "$operations" == $'stop\nstart' ]]
            cmp "$test_root/fixture/V2bX" "$case_dir/usr/local/V2bX/V2bX"
            cmp "$test_root/fixture/geoip.dat" "$case_dir/usr/local/V2bX/geoip.dat"
            [[ -f "$case_dir/etc/V2bX/config.json" ]]
            [[ -x "$case_dir/usr/local/V2bX/V2bX" ]]
            if [[ "$scenario" == update_existing_config ]]; then
                [[ "$(cat "$case_dir/etc/V2bX/config.json")" == 'operator configuration' ]]
            fi
            ;;
        update_inactive)
            [[ "$result" == 0 && -z "$operations" ]]
            [[ "$(cat "$case_dir/service-state")" == inactive ]]
            ;;
        download_fail|archive_fail|binary_fail|update_fail|endpoint_download_fail|endpoint_archive_fail|endpoint_binary_fail|endpoint_missing_wizard|endpoint_incomplete_lookup)
            [[ "$result" != 0 && -z "$operations" ]]
            [[ "$(cat "$case_dir/usr/local/V2bX/V2bX")" == 'old executable' ]]
            ;;
        recovery_restore_fail|recovery_start_fail|recovery_health_fail|recovery_stop_fail)
            [[ "$result" != 0 ]]
            compgen -G "$case_dir/usr/local/V2bX/.V2bX.rollback.*" >/dev/null
            grep -q 'Recovery failed; backups retained' "$case_dir/output"
            if [[ "$scenario" == recovery_stop_fail ]]; then
                cmp "$test_root/fixture/V2bX" "$case_dir/usr/local/V2bX/V2bX"
                [[ "$(tail -n 1 <<< "$operations")" == stop ]]
            fi
            ;;
        replace_fail|support_replace_fail|setup_fail|start_fail|stop_fail|health_fail|health_flapping|endpoint_health_fail|endpoint_replace_fail|endpoint_setup_fail|openrc_health_fail|update_inactive_fail)
            [[ "$result" != 0 ]]
            if [[ "$scenario" == update_inactive_fail ]]; then
                [[ -z "$operations" && "$(cat "$case_dir/service-state")" == inactive ]]
            else
                [[ "$(tail -n 1 <<< "$operations")" == start ]]
                [[ "$(cat "$case_dir/service-state")" == active ]]
            fi
            [[ "$(cat "$case_dir/usr/local/V2bX/V2bX")" == 'old executable' ]]
            [[ "$(cat "$case_dir/usr/local/V2bX/geoip.dat")" == 'old database' ]]
            [[ "$(cat "$case_dir/etc/systemd/system/V2bX.service")" == 'old unit' ]]
            [[ "$(cat "$case_dir/etc/init.d/V2bX")" == 'old openrc unit' ]]
            [[ ! -e "$case_dir/etc/V2bX/config.json" ]]
            ;;
    esac
    if [[ "$scenario" == endpoint_changed ]]; then
        cmp "$test_root/endpoint/trusttunnel_endpoint" "$case_dir/usr/local/V2bX/trusttunnel_endpoint"
        cmp "$test_root/endpoint/setup_wizard" "$case_dir/usr/local/V2bX/setup_wizard"
        [[ "$(cat "$case_dir/usr/local/V2bX/.trusttunnel_version")" == tt-v2 ]]
        [[ "$(cat "$INSTALL_UPDATE_TRACE")" == $'download\nvalidate\ndownload\nvalidate-endpoint\nstop\nstart' ]]
    elif [[ "$scenario" == endpoint_* ]]; then
        cmp "$test_root/old-endpoint" "$case_dir/usr/local/V2bX/trusttunnel_endpoint"
        if [[ "$scenario" != endpoint_incomplete_lookup ]]; then
            cmp "$test_root/old-wizard" "$case_dir/usr/local/V2bX/setup_wizard"
        fi
        [[ "$scenario" == endpoint_unchanged || "$(cat "$case_dir/usr/local/V2bX/.trusttunnel_version")" == tt-v1 ]]
    fi
    if [[ "$scenario" != recovery_* ]]; then
        ! compgen -G "$case_dir/usr/local/V2bX/.V2bX.*" >/dev/null
    fi
    printf 'PASS %s\n' "$scenario"
)

for scenario in download_fail archive_fail binary_fail update_fail replace_fail setup_fail start_fail success openrc \
    update_success openrc_update update_inactive update_existing_config stop_fail support_replace_fail health_fail health_flapping \
    endpoint_changed endpoint_unchanged endpoint_lookup_fail endpoint_incomplete_lookup endpoint_download_fail \
    endpoint_archive_fail endpoint_binary_fail endpoint_missing_wizard endpoint_health_fail \
    endpoint_replace_fail endpoint_setup_fail openrc_health_fail update_inactive_fail \
    recovery_restore_fail recovery_start_fail recovery_health_fail recovery_stop_fail; do
    run_case "$scenario"
done

# Exercise the actual service-PID reader separately from the transaction's
# controlled stability samples. Neither real processes nor services are touched.
run_pid_case() (
    local scenario=$1 case_dir="$test_root/$1" release=debian actual result=0
    mkdir -p "$case_dir/run"
    source <(sed -n '/^v2bx_service_pid() {/,/^# A successful Type=simple/p' "$repo_root/install.sh" |
        sed '$d' | sed "s|/run/V2bX.pid|$case_dir/run/V2bX.pid|g")
    systemctl() {
        if [[ "$1" == is-active ]]; then [[ "$scenario" != pid_inactive ]]; return $?; fi
        [[ "$1" == show && "$2" == -p && "$3" == MainPID && "$4" == V2bX ]] || return 1
        case "$scenario" in
            pid_zero) printf 'MainPID=0\n' ;;
            pid_malformed) printf 'MainPID=12 nope\n' ;;
            pid_show_fail) return 1 ;;
            *) printf 'MainPID=4242\n' ;;
        esac
    }
    rc-service() { [[ "$1" == V2bX && "$2" == status ]]; }
    kill() { [[ "$1" == -0 && "$2" == 4242 && "$scenario" != pid_dead ]]; }
    if [[ "$scenario" == pid_openrc* ]]; then
        release=alpine
        if [[ "$scenario" == pid_openrc_bad ]]; then
            printf 'garbage\n' > "$case_dir/run/V2bX.pid"
        elif [[ "$scenario" != pid_openrc_missing ]]; then
            printf '4242\n' > "$case_dir/run/V2bX.pid"
        fi
    fi
    actual=$(v2bx_service_pid) || result=$?
    if [[ "$scenario" == pid_live || "$scenario" == pid_openrc_live ]]; then
        [[ "$result" == 0 && "$actual" == 4242 ]]
    else
        [[ "$result" != 0 && -z "$actual" ]]
    fi
    printf 'PASS %s\n' "$scenario"
)
for scenario in pid_live pid_zero pid_malformed pid_show_fail pid_inactive pid_dead \
    pid_openrc_live pid_openrc_bad pid_openrc_missing; do
    run_pid_case "$scenario"
done
