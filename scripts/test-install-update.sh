#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

mkdir -p "$test_root/fixture"
cat > "$test_root/fixture/V2bX" <<'EOF'
#!/usr/bin/env bash
printf 'validate\n' >> "$INSTALL_UPDATE_TRACE"
[[ "$1" == version ]]
EOF
chmod +x "$test_root/fixture/V2bX"
printf '{}\n' > "$test_root/fixture/config.json"
(cd "$test_root/fixture" && zip -q "$test_root/valid.zip" V2bX config.json)

run_case() (
    local scenario=$1
    local case_dir="$test_root/$scenario"
    mkdir -p "$case_dir/usr/local/V2bX" "$case_dir/etc/V2bX" "$case_dir/usr/bin"
    printf 'old executable\n' > "$case_dir/usr/local/V2bX/V2bX"
    export INSTALL_UPDATE_TRACE="$case_dir/trace"
    : > "$INSTALL_UPDATE_TRACE"
    local release=debian GITHUB_REPO=example/repo last_version=v1 arch=64
    local red="" green="" yellow="" plain=""

    # Use the production functions with only their absolute install paths moved.
    source <(sed -n '/^v2bx_service() {/,/^setup_systemd() {/p' "$repo_root/install.sh" |
        sed '$d' | sed "s|/usr/local/V2bX|$case_dir/usr/local/V2bX|g; s|/etc/V2bX|$case_dir/etc/V2bX|g; s|/usr/bin/|$case_dir/usr/bin/|g")
    source <(sed -n '/^update_V2bX() {/,/^}/p' "$repo_root/install.sh" |
        sed "s|/usr/local/V2bX|$case_dir/usr/local/V2bX|g")
    systemctl() {
        if [[ "$1" == is-active ]]; then return 0; fi
        printf '%s\n' "$1" >> "$INSTALL_UPDATE_TRACE"
        if [[ "$scenario" == start_fail && "$1" == start && ! -f "$case_dir/start-attempt" ]]; then
            : > "$case_dir/start-attempt"
            return 1
        fi
    }
    rc-service() {
        if [[ "$2" == status ]]; then return 0; fi
        printf '%s\n' "$2" >> "$INSTALL_UPDATE_TRACE"
    }
    setup_systemd() {
        [[ "$scenario" != setup_fail ]]
    }
    setup_openrc() { return 0; }
    get_version() { return 0; }
    show_status() { return 0; }
    wget() {
        printf 'download\n' >> "$INSTALL_UPDATE_TRACE"
        [[ "$scenario" != download_fail && "$scenario" != update_fail ]] || return 1
        local output=""
        while (( $# > 0 )); do
            if [[ "$1" == -O ]]; then output=$2; shift 2; else shift; fi
        done
        if [[ "$scenario" == archive_fail ]]; then
            printf 'not a zip\n' > "$output"
        elif [[ "$scenario" == binary_fail ]]; then
            mkdir -p "$case_dir/bad"
            printf '#!/usr/bin/env bash\nexit 1\n' > "$case_dir/bad/V2bX"
            (cd "$case_dir/bad" && zip -q "$output" V2bX)
        else
            cp "$test_root/valid.zip" "$output"
        fi
    }
    mv() {
        if [[ "$scenario" == replace_fail && "$*" == *".V2bX.new."* ]]; then return 1; fi
        command mv "$@"
    }
    if [[ "$scenario" == openrc ]]; then release=alpine; fi

    local result=0
    if [[ "$scenario" == update_fail ]]; then
        update_V2bX v1 >/dev/null 2>&1 || result=$?
    else
        install_V2bX >/dev/null 2>&1 || result=$?
    fi
    case "$scenario" in
        success|openrc)
            [[ "$result" == 0 ]]
            [[ "$(cat "$INSTALL_UPDATE_TRACE")" == $'download\nvalidate\nstop\nstart' ]]
            cmp "$test_root/fixture/V2bX" "$case_dir/usr/local/V2bX/V2bX"
            [[ -f "$case_dir/etc/V2bX/config.json" ]]
            ;;
        download_fail|archive_fail|binary_fail|update_fail)
            [[ "$result" != 0 ]]
            ! grep -Eq '^(stop|start|restart)$' "$INSTALL_UPDATE_TRACE"
            [[ "$(cat "$case_dir/usr/local/V2bX/V2bX")" == "old executable" ]]
            ;;
        replace_fail|setup_fail|start_fail)
            [[ "$result" != 0 ]]
            [[ "$(tail -n 1 "$INSTALL_UPDATE_TRACE")" == start ]]
            grep -qx stop "$INSTALL_UPDATE_TRACE"
            [[ "$(cat "$case_dir/usr/local/V2bX/V2bX")" == "old executable" ]]
            ;;
    esac
    ! compgen -G "$case_dir/usr/local/V2bX/.V2bX.*" >/dev/null
    printf 'PASS %s\n' "$scenario"
)

for scenario in download_fail archive_fail binary_fail update_fail replace_fail setup_fail start_fail success openrc; do
    run_case "$scenario"
done
