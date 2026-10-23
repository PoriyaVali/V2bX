#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

for scenario in success failure trusttunnel older_binary; do
    case_dir="$test_root/$scenario"
    mkdir -p "$case_dir/bin" "$case_dir/config"
    (
        export WIZARD_TEST_SCENARIO="$scenario" WIZARD_TEST_DIR="$case_dir"
        cat > "$case_dir/bin/V2bX" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == 'configure --help' ]]; then
    [[ "$WIZARD_TEST_SCENARIO" != older_binary ]]; exit $?
fi
[[ "$1" == configure && "$2" == --output ]] || exit 99
if [[ "$WIZARD_TEST_SCENARIO" == failure ]]; then exit 17; fi
printf 'configure\n' > "$WIZARD_TEST_DIR/trace"
if [[ "$WIZARD_TEST_SCENARIO" == trusttunnel ]]; then
    printf '{"Cores":[{"Type":"trusttunnel"}]}\n' > "$3"
else
    printf '{"Cores":[{"Type":"mdns"}]}\n' > "$3"
fi
EOF
        chmod +x "$case_dir/bin/V2bX"
        source <(sed -n '/^generate_config() {/,/^gen_x25519() {/p' "$repo_root/install.sh" | sed '$d' |
            sed "s|/usr/local/V2bX/V2bX|$case_dir/bin/V2bX|g; s|/etc/V2bX|$case_dir/config|g")
        red='' green='' yellow='' plain=''
        install_trusttunnel_bins() { printf 'trusttunnel\n' >> "$case_dir/trace"; }
        read() {
            printf 'manual\n' >> "$case_dir/trace"
            local variable="${!#}" value=''
            case "$variable" in
                API_HOST) value='https://panel.example.test' ;;
                API_KEY) value='fictional-key' ;;
                BLOCKED) value=none ;;
                NODE_ID) value=1 ;;
                core_choice) value=4 ;;
                add_more) value=n ;;
            esac
            printf -v "$variable" '%s' "$value"
        }
        if generate_config > "$case_dir/output" 2>&1; then result=0; else result=$?; fi
        case "$scenario" in
            success) [[ "$result" == 0 && "$(cat "$case_dir/trace")" == configure ]] ;;
            failure) [[ "$result" == 17 && ! -f "$case_dir/config/config.json" ]] ;;
            trusttunnel) [[ "$result" == 0 && "$(cat "$case_dir/trace")" == $'configure\ntrusttunnel' ]] ;;
            older_binary) [[ "$result" == 0 ]] && grep -q '^manual$' "$case_dir/trace" ;;
        esac
    )
    printf 'PASS wizard_%s\n' "$scenario"
done
