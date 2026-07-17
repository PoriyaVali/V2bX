#!/bin/bash

# ================================================================
# V2bX Install Script — DrMobile Fork
# Repo: https://github.com/PoriyaVali/V2bX
# ================================================================

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# Root check | بررسی دسترسی root
[[ $EUID -ne 0 ]] && echo -e "${red}Error | خطا:${plain} This script must be run as root! | این اسکریپت باید با دسترسی root اجرا شود!\n" && exit 1

# OS detection | تشخیص سیستم‌عامل
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -q -E -i "debian"; then
    release="debian"
elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -q -E -i "debian"; then
    release="debian"
elif cat /proc/version | grep -q -E -i "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
elif cat /etc/issue | grep -q -E -i "alpine"; then
    release="alpine"
else
    echo -e "${red}Unsupported OS | سیستم‌عامل پشتیبانی نمی‌شود${plain}" && exit 1
fi

os_version=""
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}CentOS 7+ required | نیاز به CentOS 7 یا بالاتر است${plain}" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}Ubuntu 16+ required | نیاز به Ubuntu 16 یا بالاتر است${plain}" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}Debian 8+ required | نیاز به Debian 8 یا بالاتر است${plain}" && exit 1
    fi
fi

# Architecture detection | تشخیص معماری
arch=$(uname -m)
if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="linux-64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="linux-arm64-v8a"
elif [[ $arch == "s390x" ]]; then
    arch="linux-s390x"
elif [[ $arch == "armv7l" ]]; then
    arch="linux-arm32-v7a"
elif [[ $arch == "armv6l" ]]; then
    arch="linux-arm32-v6"
elif [[ $arch == "armv5l" ]]; then
    arch="linux-arm32-v5"
elif [[ $arch == "riscv64" ]]; then
    arch="linux-riscv64"
else
    arch="linux-64"
    echo -e "${yellow}Architecture not detected, defaulting to amd64 | معماری شناسایی نشد، amd64 انتخاب شد${plain}"
fi

echo -e "Architecture | معماری: ${green}${arch}${plain}"

# ================================================================
# Install dependencies | نصب وابستگی‌ها
# ================================================================
install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install -y wget curl unzip tar socat gzip
    elif [[ x"${release}" == x"alpine" ]]; then
        apk add --no-cache wget curl unzip tar socat gzip
    else
        apt-get install -y wget curl unzip tar socat gzip
    fi
}

# ================================================================
# Get latest version from GitHub | دریافت آخرین نسخه از GitHub
# ================================================================
GITHUB_REPO="PoriyaVali/V2bX"

get_version() {
    if [[ -n "$1" ]]; then
        last_version="$1"
        echo -e "Using version | استفاده از نسخه: ${green}${last_version}${plain}"
    else
        echo -e "Checking latest version | بررسی آخرین نسخه..."
        last_version=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
            | grep '"tag_name":' \
            | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -z "${last_version}" ]]; then
            echo -e "${red}Failed to get version from GitHub | دریافت نسخه از GitHub ناموفق بود${plain}"
            echo -e "Please check: | بررسی کنید: https://github.com/${GITHUB_REPO}/releases"
            exit 1
        fi
        echo -e "Latest version | آخرین نسخه: ${green}${last_version}${plain}"
    fi
}

# ================================================================
# Install V2bX | نصب V2bX
# ================================================================
install_V2bX() {
    echo -e "${green}Installing V2bX | در حال نصب V2bX...${plain}"

    # Stop existing service | توقف سرویس موجود
    if systemctl is-active --quiet V2bX 2>/dev/null; then
        systemctl stop V2bX
    fi

    # Create directories | ایجاد پوشه‌ها
    mkdir -p /etc/V2bX
    mkdir -p /usr/local/V2bX

    # Download | دانلود
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${last_version}/V2bX-${arch}.zip"
    echo -e "Downloading | دانلود: ${DOWNLOAD_URL}"

    wget -nv --show-progress -O /tmp/V2bX.zip "${DOWNLOAD_URL}"
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Download failed | دانلود ناموفق بود${plain}"
        echo -e "Try downloading manually from | به صورت دستی دانلود کنید: https://github.com/${GITHUB_REPO}/releases"
        exit 1
    fi

    # Extract | استخراج
    unzip -o /tmp/V2bX.zip -d /usr/local/V2bX
    rm -f /tmp/V2bX.zip
    chmod +x /usr/local/V2bX/V2bX

    # Symlink | لینک سمبلیک
    ln -sf /usr/local/V2bX/V2bX /usr/bin/V2bX
    ln -sf /usr/local/V2bX/V2bX /usr/bin/v2bx

    # Copy config templates if not exist | کپی فایل‌های نمونه اگر وجود ندارند
    for f in config.json dns.json route.json; do
        if [[ ! -f /etc/V2bX/${f} && -f /usr/local/V2bX/${f} ]]; then
            cp /usr/local/V2bX/${f} /etc/V2bX/${f}
            echo -e "Created config | فایل تنظیمات ایجاد شد: /etc/V2bX/${f}"
        fi
    done

    # Setup systemd service | راه‌اندازی سرویس systemd
    if [[ x"${release}" == x"alpine" ]]; then
        setup_openrc
    else
        setup_systemd
    fi

    echo -e "${green}V2bX ${last_version} installed successfully! | V2bX ${last_version} با موفقیت نصب شد!${plain}"
    echo -e ""
    echo -e "Edit config | ویرایش تنظیمات: ${yellow}nano /etc/V2bX/config.json${plain}"
    echo -e "Start service | راه‌اندازی: ${yellow}V2bX start${plain}"
    echo -e "View logs | مشاهده لاگ: ${yellow}V2bX log${plain}"
}

setup_systemd() {
    cat > /etc/systemd/system/V2bX.service << EOF
[Unit]
Description=V2bX Service
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/usr/local/V2bX
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/V2bX/V2bX server -c /etc/V2bX/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable V2bX
    echo -e "${green}Systemd service configured | سرویس systemd پیکربندی شد${plain}"
}

setup_openrc() {
    cat > /etc/init.d/V2bX << EOF
#!/sbin/openrc-run
name="V2bX"
description="V2bX Service"
command="/usr/local/V2bX/V2bX"
command_args="server -c /etc/V2bX/config.json"
command_background=true
pidfile="/run/V2bX.pid"
EOF
    chmod +x /etc/init.d/V2bX
    rc-update add V2bX default
    echo -e "${green}OpenRC service configured | سرویس OpenRC پیکربندی شد${plain}"
}

# ================================================================
# Update V2bX | به‌روزرسانی V2bX
# ================================================================
update_V2bX() {
    echo -e "${green}Updating V2bX | در حال به‌روزرسانی V2bX...${plain}"
    get_version "$1"
    install_V2bX
    if [[ x"${release}" != x"alpine" ]]; then
        systemctl restart V2bX
    fi
    show_status
}

# ================================================================
# Uninstall V2bX | حذف V2bX
# ================================================================
uninstall_V2bX() {
    echo -e "${yellow}Are you sure you want to uninstall V2bX? | آیا مطمئنید که می‌خواهید V2bX را حذف کنید؟ [y/n]${plain}"
    read -r answer
    if [[ "${answer,,}" != "y" ]]; then
        echo -e "Cancelled | لغو شد"
        return
    fi
    if [[ x"${release}" == x"alpine" ]]; then
        rc-service V2bX stop 2>/dev/null
        rc-update del V2bX 2>/dev/null
        rm -f /etc/init.d/V2bX
    else
        systemctl stop V2bX 2>/dev/null
        systemctl disable V2bX 2>/dev/null
        rm -f /etc/systemd/system/V2bX.service
        systemctl daemon-reload
        systemctl reset-failed
    fi
    rm -rf /usr/local/V2bX
    rm -f /usr/bin/V2bX /usr/bin/v2bx
    echo -e "${green}V2bX uninstalled. Config preserved at /etc/V2bX/ | V2bX حذف شد. تنظیمات در /etc/V2bX/ باقی است${plain}"
}

# ================================================================
# Config wizard | راهنمای ساخت config
# ================================================================
generate_config() {
    echo -e "${green}V2bX Config Wizard | راهنمای ساخت تنظیمات${plain}"
    echo -e "${yellow}Config will be saved to /etc/V2bX/config.json${plain}"
    echo -e "${yellow}Old config backed up to /etc/V2bX/config.json.bak${plain}"
    echo ""

    # NOTE: the core is chosen PER NODE inside the loop below, so one config can
    # mix cores (e.g. a sing anytls node + an mdns node + an xray vless node).
    # Each distinct core is added to the "Cores" array once (deduplicated).

    # ── Panel API (shared for all nodes — same panel, different IDs) ──
    read -rp "Panel URL (e.g. https://panel.example.com): " API_HOST
    read -rp "API Key: " API_KEY

    # ── Blocked countries (core-level, applies to all nodes) ──────
    read -rp "Block countries (comma separated, e.g. ir,cn) [default: ir, 'none' to disable]: " BLOCKED
    BLOCKED="${BLOCKED:-ir}"
    if [[ "${BLOCKED}" == "none" ]]; then
        BLOCKED_JSON=""
    else
        BLOCKED_JSON=$(echo "$BLOCKED" | tr -d ' ' | sed 's/,/","/g')
    fi

    # ── Log level ─────────────────────────────────────────────────
    # LOG_LEVEL controls V2bX's own operational logs (user reports, limits…).
    read -rp "V2bX log level (debug/info/warn/error) [default: info]: " LOG_LEVEL
    LOG_LEVEL="${LOG_LEVEL:-info}"
    # Core (sing/xray) logs every connection at info → floods the journal.
    # Default the core to warn; set it equal to LOG_LEVEL only for debugging.
    read -rp "Core connection-log level [default: warn]: " CORE_LOG_LEVEL
    CORE_LOG_LEVEL="${CORE_LOG_LEVEL:-warn}"

    # ── Multiplexing (smux) — vmess/vless/trojan/shadowsocks only ─
    echo -e "Enable multiplexing (smux)? | فعال کردن مالتی‌پلکس؟"
    echo -e "  ${yellow}Works on: vmess, vless, trojan, shadowsocks${plain}"
    echo -e "  ${yellow}anytls/hysteria2 have built-in mux — not needed${plain}"
    read -rp "Enable? [y/N]: " mux_choice
    if [[ "${mux_choice,,}" == "y" ]]; then
        MULTIPLEX_BLOCK=",
        \"MultiplexConfig\": {
          \"Enable\": true,
          \"Padding\": false,
          \"Brutal\": { \"Enable\": false, \"UpMbps\": 0, \"DownMbps\": 0 }
        }"
    else
        MULTIPLEX_BLOCK=""
    fi

    # ── Core-block builder (sets CB for a given core type) ────────
    build_core_block() {
        case "$1" in
            sing)
                local BLOCKED_FIELD=""
                if [[ -n "${BLOCKED_JSON}" ]]; then
                    BLOCKED_FIELD=",
      \"BlockedCountries\": [\"${BLOCKED_JSON}\"]"
                fi
                CB="{
      \"Type\": \"sing\",
      \"Log\": { \"Level\": \"${CORE_LOG_LEVEL}\", \"Timestamp\": true },
      \"NTP\": { \"Enable\": false, \"Server\": \"time.apple.com\", \"ServerPort\": 0 },
      \"OriginalPath\": \"/etc/V2bX/sing_origin.json\"${BLOCKED_FIELD}
    }" ;;
            xray)
                CB="{
      \"Type\": \"xray\",
      \"Log\": { \"Level\": \"${CORE_LOG_LEVEL}\" }
    }" ;;
            mdns)
                # mdns core takes no core-level config; every param (domain, UDP
                # port, encryption, node secret) is delivered per-node by the panel.
                CB="{
      \"Type\": \"mdns\"
    }" ;;
            *)
                CB="{
      \"Type\": \"hysteria2\"
    }" ;;
        esac
    }

    # ── Node loop — each node picks its own CORE, type, domain & cert ──
    NODES_BLOCK=""
    CORES_BLOCK=""
    CORES_SEEN=" "
    NODE_NUM=0
    while true; do
        NODE_NUM=$((NODE_NUM + 1))
        echo ""
        echo -e "${green}━━━ Node ${NODE_NUM} | نود ${NODE_NUM} ━━━${plain}"

        read -rp "Node ID: " NODE_ID

        # ── Core for THIS node ────────────────────────────────────
        echo -e "Core for this node | هستهٔ این نود:"
        echo -e "  ${green}1.${plain} sing  (recommended | پیشنهادی)"
        echo -e "  ${green}2.${plain} xray"
        echo -e "  ${green}3.${plain} hysteria2"
        echo -e "  ${green}4.${plain} mdns  (DNS-tunnel anti-censorship | تونل DNS ضدسانسور)"
        read -rp "Core [1-4, default=1]: " core_choice
        case "${core_choice}" in
            2) CORE_TYPE="xray" ;;
            3) CORE_TYPE="hysteria2" ;;
            4) CORE_TYPE="mdns" ;;
            *) CORE_TYPE="sing" ;;
        esac

        # Add this core to the "Cores" array once (V2bX keys cores by Type, so a
        # duplicate would collide — one block per distinct core is enough; every
        # node of that core references it by "Core": "<type>").
        if [[ "${CORES_SEEN}" != *" ${CORE_TYPE} "* ]]; then
            build_core_block "${CORE_TYPE}"
            if [[ -n "${CORES_BLOCK}" ]]; then
                CORES_BLOCK="${CORES_BLOCK},
    ${CB}"
            else
                CORES_BLOCK="    ${CB}"
            fi
            CORES_SEEN="${CORES_SEEN}${CORE_TYPE} "
        fi

        # ── Node type — the menu depends on the chosen core ───────
        if [[ "${CORE_TYPE}" == "mdns" ]]; then
            NODE_TYPE="mdns"
            echo -e "Node type | نوع نود: ${yellow}mdns${plain}"
        elif [[ "${CORE_TYPE}" == "hysteria2" ]]; then
            NODE_TYPE="hysteria2"
            echo -e "Node type | نوع نود: ${yellow}hysteria2${plain}"
        elif [[ "${CORE_TYPE}" == "xray" ]]; then
            echo -e "Node type | نوع نود:"
            echo -e "  ${green}1.${plain} vless"
            echo -e "  ${green}2.${plain} vmess"
            echo -e "  ${green}3.${plain} trojan"
            echo -e "  ${green}4.${plain} shadowsocks"
            read -rp "Node type [1-4, default=1]: " node_choice
            case "${node_choice}" in
                2) NODE_TYPE="vmess" ;;
                3) NODE_TYPE="trojan" ;;
                4) NODE_TYPE="shadowsocks" ;;
                *) NODE_TYPE="vless" ;;
            esac
        else
            echo -e "Node type | نوع نود:"
            echo -e "  ${green}1.${plain} anytls"
            echo -e "  ${green}2.${plain} vmess"
            echo -e "  ${green}3.${plain} vless"
            echo -e "  ${green}4.${plain} trojan"
            echo -e "  ${green}5.${plain} shadowsocks"
            echo -e "  ${green}6.${plain} hysteria2"
            read -rp "Node type [1-6, default=1]: " node_choice
            case "${node_choice}" in
                2) NODE_TYPE="vmess" ;;
                3) NODE_TYPE="vless" ;;
                4) NODE_TYPE="trojan" ;;
                5) NODE_TYPE="shadowsocks" ;;
                6) NODE_TYPE="hysteria2" ;;
                *) NODE_TYPE="anytls" ;;
            esac
        fi

        # "::" = dual-stack (IPv4+IPv6). Use 0.0.0.0 to force IPv4-only.
        read -rp "Listen IP [default: :: (IPv4+IPv6), or 0.0.0.0 for IPv4-only]: " LISTEN_IP
        LISTEN_IP="${LISTEN_IP:-::}"

        # TLS cert — each TLS node type (anytls/vmess/vless/trojan, on sing or
        # xray) gets its own domain → own cert files. ss/hysteria2/mdns skip it.
        NODE_CERT_BLOCK=""
        if [[ "${NODE_TYPE}" == "anytls" || "${NODE_TYPE}" == "vmess" || "${NODE_TYPE}" == "vless" || "${NODE_TYPE}" == "trojan" ]]; then
            read -rp "Certificate domain (e.g. ff.example.com): " CERT_DOMAIN
            echo -e "Cert mode | نحوه دریافت سرتیفیکت:"
            echo -e "  ${green}1.${plain} http  (port 80 must be open)"
            echo -e "  ${green}2.${plain} dns   (no port needed — needs DNS API token) | بدون نیاز به پورت"
            echo -e "  ${green}3.${plain} self  (self-signed, test only)"
            echo -e "  ${green}4.${plain} file  (already have cert files)"
            echo -e "  ${green}5.${plain} none  (no TLS)"
            read -rp "Cert mode [1-5, default=1]: " cert_choice
            CERT_EXTRA=""
            case "${cert_choice}" in
                2) CERT_MODE="dns" ;;
                3) CERT_MODE="self" ;;
                4) CERT_MODE="file" ;;
                5) CERT_MODE="none" ;;
                *) CERT_MODE="http" ;;
            esac
            # DNS-01 challenge: no port needed, survives closed/blocked port 80,
            # works behind CDN. Needs the DNS provider's API credentials.
            if [[ "${CERT_MODE}" == "dns" ]]; then
                read -rp "DNS provider [default: cloudflare]: " DNS_PROVIDER
                DNS_PROVIDER="${DNS_PROVIDER:-cloudflare}"
                read -rp "ACME email (e.g. you@example.com): " ACME_EMAIL
                if [[ "${DNS_PROVIDER}" == "cloudflare" ]]; then
                    read -rp "Cloudflare API Token (Zone.DNS: Edit): " CF_TOKEN
                    DNS_ENV_JSON="\"CLOUDFLARE_DNS_API_TOKEN\": \"${CF_TOKEN}\""
                else
                    echo -e "Enter DNS env vars as KEY=VALUE, comma separated (see go-acme/lego docs)"
                    read -rp "DNS env: " DNS_ENV_RAW
                    DNS_ENV_RAW="${DNS_ENV_RAW//, /,}"
                    DNS_ENV_JSON=""
                    IFS=',' read -ra _pairs <<< "${DNS_ENV_RAW}"
                    for _p in "${_pairs[@]}"; do
                        [[ -z "${_p}" ]] && continue
                        _k="${_p%%=*}"; _v="${_p#*=}"
                        [[ -n "${DNS_ENV_JSON}" ]] && DNS_ENV_JSON="${DNS_ENV_JSON}, "
                        DNS_ENV_JSON="${DNS_ENV_JSON}\"${_k}\": \"${_v}\""
                    done
                fi
                CERT_EXTRA=",
          \"Provider\": \"${DNS_PROVIDER}\",
          \"Email\": \"${ACME_EMAIL}\",
          \"DNSEnv\": { ${DNS_ENV_JSON} }"
            fi
            # Cert path includes domain name — avoids conflicts between nodes
            NODE_CERT_BLOCK=",
        \"CertConfig\": {
          \"CertMode\": \"${CERT_MODE}\",
          \"RejectUnknownSni\": false,
          \"CertDomain\": \"${CERT_DOMAIN}\",
          \"CertFile\": \"/etc/V2bX/${CERT_DOMAIN}.cer\",
          \"KeyFile\": \"/etc/V2bX/${CERT_DOMAIN}.key\"${CERT_EXTRA}
        }"
        fi

        # Build this node's JSON
        if [[ "${CORE_TYPE}" == "mdns" ]]; then
            # mdns node: no SingOptions/cert — the DNS-tunnel params (domain,
            # UDP port, encryption, node secret) arrive from the panel.
            ONE_NODE="{
      \"Core\": \"mdns\",
      \"ApiHost\": \"${API_HOST}\",
      \"ApiKey\": \"${API_KEY}\",
      \"NodeID\": ${NODE_ID},
      \"NodeType\": \"mdns\",
      \"Timeout\": 30,
      \"ListenIP\": \"${LISTEN_IP}\",
      \"SendIP\": \"\",
      \"DeviceOnlineMinTraffic\": 200,
      \"MinReportTraffic\": 0
    }"
        else
            ONE_NODE="{
      \"Core\": \"${CORE_TYPE}\",
      \"ApiHost\": \"${API_HOST}\",
      \"ApiKey\": \"${API_KEY}\",
      \"NodeID\": ${NODE_ID},
      \"NodeType\": \"${NODE_TYPE}\",
      \"Timeout\": 30,
      \"ListenIP\": \"${LISTEN_IP}\",
      \"SendIP\": \"\",
      \"DeviceOnlineMinTraffic\": 200,
      \"MinReportTraffic\": 0,
      \"SingOptions\": {
        \"EnableTFO\": false,
        \"EnableSniff\": true,
        \"SniffOverrideDestination\": true,
        \"EnableDNS\": false${MULTIPLEX_BLOCK}
      }${NODE_CERT_BLOCK}
    }"
        fi

        if [[ -n "${NODES_BLOCK}" ]]; then
            NODES_BLOCK="${NODES_BLOCK},
    ${ONE_NODE}"
        else
            NODES_BLOCK="    ${ONE_NODE}"
        fi

        echo ""
        read -rp "Add another node? | نود دیگری اضافه کنید؟ [y/N]: " add_more
        [[ "${add_more,,}" != "y" ]] && break
    done

    # ── Write config ──────────────────────────────────────────────
    mkdir -p /etc/V2bX
    [[ -f /etc/V2bX/config.json ]] && cp /etc/V2bX/config.json /etc/V2bX/config.json.bak

    cat > /etc/V2bX/config.json << CFGEOF
{
  "Log": {
    "Level": "${LOG_LEVEL}",
    "Output": ""
  },
  "Cores": [
${CORES_BLOCK}
  ],
  "Nodes": [
${NODES_BLOCK}
  ]
}
CFGEOF

    echo ""
    echo -e "${green}Config saved | تنظیمات ذخیره شد: /etc/V2bX/config.json${plain}"
    echo -e "Nodes configured | تعداد نودها: ${yellow}${NODE_NUM}${plain}"
    echo -e "Restart to apply | اعمال تغییرات: ${yellow}v2bx restart${plain}"
}

# ================================================================
# X25519 key generation | تولید کلید X25519
# ================================================================
gen_x25519() {
    if ! command -v openssl &>/dev/null; then
        echo -e "${red}openssl not found. Install with: apt install openssl${plain}"
        return
    fi
    echo -e "${green}Generating X25519 key pair | تولید جفت کلید X25519...${plain}"
    # Generate once, derive both keys from same pair
    TMPKEY=$(openssl genpkey -algorithm X25519 2>/dev/null)
    PRIVATE=$(echo "$TMPKEY" | openssl pkey -outform DER 2>/dev/null | tail -c 32 | base64 -w 0)
    PUBLIC=$(echo "$TMPKEY"  | openssl pkey -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w 0)
    echo -e "Private key | کلید خصوصی: ${yellow}${PRIVATE}${plain}"
    echo -e "Public key  | کلید عمومی: ${yellow}${PUBLIC}${plain}"
}

# ================================================================
# Install BBR | نصب BBR
# ================================================================
install_bbr() {
    if [[ x"${release}" == x"alpine" ]]; then
        echo -e "${red}BBR not supported on Alpine | BBR در Alpine پشتیبانی نمی‌شود${plain}"
        return
    fi
    echo -e "${green}Enabling BBR | فعال‌سازی BBR...${plain}"
    modprobe tcp_bbr 2>/dev/null
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        echo -e "${green}BBR enabled successfully | BBR با موفقیت فعال شد${plain}"
    else
        echo -e "${yellow}BBR may require a kernel upgrade. Current kernel: $(uname -r)${plain}"
    fi
}

# ================================================================
# Allow all ports | باز کردن تمام پورت‌ها
# ================================================================
allow_all_ports() {
    echo -e "${green}Opening all ports | باز کردن تمام پورت‌ها...${plain}"
    if command -v ufw &>/dev/null; then
        ufw disable 2>/dev/null
        echo -e "${green}UFW disabled | UFW غیرفعال شد${plain}"
    fi
    if command -v iptables &>/dev/null; then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -F
        echo -e "${green}iptables rules cleared | قوانین iptables پاک شدند${plain}"
    fi
}

# ================================================================
# Show status | نمایش وضعیت
# ================================================================
show_status() {
    if [[ x"${release}" == x"alpine" ]]; then
        if rc-service V2bX status &>/dev/null; then
            echo -e "V2bX status | وضعیت: ${green}Running | در حال اجرا${plain}"
        else
            echo -e "V2bX status | وضعیت: ${red}Stopped | متوقف${plain}"
        fi
    else
        if systemctl is-active --quiet V2bX; then
            echo -e "V2bX status | وضعیت: ${green}Running | در حال اجرا${plain}"
        else
            echo -e "V2bX status | وضعیت: ${red}Stopped | متوقف${plain}"
        fi
    fi
    installed_version=$(/usr/local/V2bX/V2bX version 2>/dev/null || echo "unknown")
    echo -e "Version | نسخه: ${green}${installed_version}${plain}"
}

# ================================================================
# Main menu | منوی اصلی
# ================================================================
setup_tunnel() {
    local HEDIOUM_INSTALL="https://raw.githubusercontent.com/PoriyaVali/Hedioum-Pool-Tunnel/main/install.sh"
    local LOG="/etc/V2bX/tunnel-setup.log"
    local INFO="/etc/V2bX/tunnel-info.txt"
    mkdir -p /etc/V2bX 2>/dev/null

    # tlog: print to screen AND append a clean (color-stripped) timestamped line to $LOG
    tlog() {
        echo -e "$1"
        echo "[$(date '+%F %T')] $(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG"
    }

    echo "===================== tunnel setup $(date '+%F %T') =====================" >> "$LOG"
    tlog "${green}=== Iran Relay Tunnel (Hedioum front) | تونل رله ایران ===${plain}"
    tlog "${yellow}Run on the FOREIGN V2bX node. Everything is logged to ${LOG}${plain}"
    tlog ""

    # 1) Auto-detect the V2bX inbound ports (the ports V2bX is listening on)
    if ! systemctl is-active --quiet V2bX 2>/dev/null; then
        tlog "${yellow}[!] V2bX is not running — start it first so ports can be auto-detected.${plain}"
    fi
    local PORTS
    PORTS=$(ss -tlnpH 2>/dev/null | awk '/V2bX/{n=split($4,a,":"); print a[n]}' | sort -un | paste -sd, -)
    if [ -z "$PORTS" ]; then
        read -rp "Could not auto-detect inbound ports. Enter comma-separated ports: " PORTS
    fi
    [ -z "$PORTS" ] && { tlog "${red}[x] No inbound ports. Aborting.${plain}"; return; }
    tlog "${green}[✓] Detected V2bX inbound ports: ${PORTS}${plain}"

    # 2) Tunnel (border-crossing) port the Iran relay connects to — keep SSH safe
    local TPORT
    read -rp "Tunnel listen port on THIS server (Iran relay connects here) [2222]: " TPORT
    TPORT=${TPORT:-2222}
    tlog "[i] Tunnel (border) port: ${TPORT}"

    # 3) Public IPv4 of this foreign node
    local PUBIP IPIN
    PUBIP=$(curl -s4 --max-time 8 https://api.ipify.org 2>/dev/null || curl -s4 --max-time 8 https://ifconfig.me 2>/dev/null)
    read -rp "Public IPv4 of THIS server [${PUBIP}]: " IPIN
    PUBIP=${IPIN:-$PUBIP}
    [ -z "$PUBIP" ] && { tlog "${red}[x] No public IP. Aborting.${plain}"; return; }
    tlog "[i] Foreign public IP: ${PUBIP}"

    # 4) Shared secret for both ends
    local TOKEN
    TOKEN=$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
    tlog "[i] Shared token generated (stored in ${INFO})"

    # 4b) Multi-foreign relay: if this foreign will sit behind an Iran relay that
    # ALREADY fronts other foreign nodes, the relay command must MERGE (-add) into
    # that relay's config instead of overwriting it. Each foreign then needs a
    # UNIQUE public port on the relay (the relay binds each port once and rejects
    # a clash). A readable alias distinguishes this node in the relay config/logs.
    local ADDFLAG="" ALIAS MULTI
    ALIAS=$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9._-')
    ALIAS=${ALIAS:-fr-${PUBIP//./-}}
    read -rp "Additional foreign behind a relay that already tunnels other nodes? [y/N]: " MULTI
    case "$MULTI" in
        [yY]*)
            ADDFLAG=" -add"
            tlog "${yellow}[i] Multi-foreign: the relay command will use -add (merge). Make sure THIS node's inbound ports (${PORTS}) do NOT clash with the other foreigns already on that relay, or the relay will reject them.${plain}"
            ;;
    esac

    # 5) Install + provision Hedioum (foreign role); tee its full output into the log
    tlog "${green}[*] Installing & provisioning Hedioum (foreign) ...${plain}"
    bash <(curl -s "$HEDIOUM_INSTALL") setup -role foreign -forward-host 127.0.0.1 -listen-port "$TPORT" -token "$TOKEN" 2>&1 | tee -a "$LOG"

    # 6) Build the Iran one-liner (double quotes keep <(...) literal, not executed)
    local IRAN_CMD="bash <(curl -s ${HEDIOUM_INSTALL}) setup -role iran -foreign-ip ${PUBIP} -foreign-port ${TPORT} -token ${TOKEN} -ports ${PORTS} -alias ${ALIAS}${ADDFLAG}"

    # 7) Persist all tunnel info so it can be retrieved later (not just printed once)
    cat > "$INFO" <<INFOEOF
# V2bX <-> Hedioum tunnel   ($(date '+%F %T'))
foreign_public_ip = ${PUBIP}
tunnel_port       = ${TPORT}
inbound_ports     = ${PORTS}
auth_token        = ${TOKEN}
forward           = 127.0.0.1:<port>  (port-preserving, all TCP inbounds)

# Run this on the IRAN relay:
${IRAN_CMD}

# In the panel: set this node's host = <Iran relay IP>.
#   single foreign per relay  -> keep the same port.
#   multiple foreigns / relay -> each foreign needs a UNIQUE port: give this
#                                node a distinct panel port (port & server_port);
#                                V2bX binds it from the panel automatically.

# Live tunnel logs (both servers):  journalctl -u hedioum -f
# Setup log (this server):          ${LOG}
INFOEOF
    chmod 600 "$INFO" 2>/dev/null

    tlog ""
    tlog "${green}==================================================${plain}"
    tlog "${green} FOREIGN side ready. Run THIS on your IRAN relay:${plain}"
    tlog "${green}==================================================${plain}"
    tlog "${yellow}${IRAN_CMD}${plain}"
    tlog "${green}==================================================${plain}"
    tlog "Saved to ${green}${INFO}${plain}  |  Setup log: ${green}${LOG}${plain}"
    tlog "Live tunnel logs: ${green}journalctl -u hedioum -f${plain}"
    tlog "Then in the panel set this node's ${green}host = Iran relay IP${plain}."
    tlog "  ${yellow}single foreign/relay: keep the port. multiple foreigns/relay: give each a UNIQUE port.${plain}"
}

stop_tunnel() {
    echo -e "${green}=== Stop tunnel (go direct) | توقف تونل (اتصال مستقیم) ===${plain}"
    if systemctl list-unit-files 2>/dev/null | grep -q '^hedioum\.service'; then
        systemctl stop hedioum 2>/dev/null
        systemctl disable hedioum 2>/dev/null   # persists across reboot
        echo -e "${green}[✓] Hedioum tunnel stopped & disabled on THIS node (won't start on reboot).${plain}"
        echo -e "${green}[✓] هستهٔ تونل روی این نود متوقف و غیرفعال شد (بعد از ری‌استارت هم خاموش می‌ماند).${plain}"
    else
        echo -e "${yellow}[!] No hedioum service on this node.${plain}"
    fi
    echo ""
    echo -e "${yellow}To fully go direct, ALSO do these two (order matters):${plain}"
    echo -e "  ${green}1)${plain} In the panel, revert this node's ${green}host${plain} back to its own domain/IP."
    echo -e "  ${green}2)${plain} On the IRAN relay:  ${green}systemctl disable --now hedioum${plain}"
    [ -f /etc/V2bX/tunnel-info.txt ] && echo -e "  (tunnel details: /etc/V2bX/tunnel-info.txt)"
    echo ""
    echo -e "Re-enable the tunnel later:  ${green}systemctl enable --now hedioum${plain}  (or menu 15 to reconfigure)."
}

show_menu() {
    # Show running status in header
    if systemctl is-active --quiet V2bX 2>/dev/null; then
        STATUS="${green}Running | در حال اجرا${plain}"
    else
        STATUS="${red}Stopped | متوقف${plain}"
    fi

    echo -e "
  ${green}V2bX Management | مدیریت V2bX${plain}
  ${green}GitHub: https://github.com/${GITHUB_REPO}${plain}
  Status | وضعیت: ${STATUS}
  ————————————————
  ${green}0.${plain}  Exit | خروج
  ${green}1.${plain}  Install V2bX | نصب V2bX
  ${green}2.${plain}  Update V2bX | به‌روزرسانی V2bX
  ${green}3.${plain}  Uninstall V2bX | حذف V2bX
  ————————————————
  ${green}4.${plain}  Start | راه‌اندازی
  ${green}5.${plain}  Stop | توقف
  ${green}6.${plain}  Restart | راه‌اندازی مجدد
  ${green}7.${plain}  Status | وضعیت
  ${green}8.${plain}  View logs | مشاهده لاگ
  ————————————————
  ${green}9.${plain}  Generate config wizard | راهنمای ساخت تنظیمات
  ${green}10.${plain} Edit config | ویرایش تنظیمات
  ${green}11.${plain} Generate X25519 key | تولید کلید X25519
  ${green}12.${plain} Install BBR | نصب BBR
  ${green}13.${plain} Allow all ports | باز کردن تمام پورت‌ها
  ${green}14.${plain} Certificate expiry | انقضای گواهی‌ها
  ${green}15.${plain} Setup Iran tunnel | راه‌اندازی تونل ایران
  ${green}16.${plain} Stop tunnel (go direct) | توقف تونل
  ————————————————
 "
    read -rp "Choose | انتخاب [0-16]: " num
    case "${num}" in
        0) exit 0 ;;
        1)
            install_base
            get_version "$1"
            install_V2bX
            ;;
        2) update_V2bX "$1" ;;
        3) uninstall_V2bX ;;
        4)
            systemctl start V2bX
            echo -e "${green}Started | راه‌اندازی شد${plain}"
            ;;
        5)
            systemctl stop V2bX
            echo -e "${green}Stopped | متوقف شد${plain}"
            ;;
        6)
            systemctl restart V2bX
            echo -e "${green}Restarted | مجدداً راه‌اندازی شد${plain}"
            ;;
        7) show_status ;;
        8) journalctl -u V2bX.service -e --no-pager -f ;;
        9) generate_config ;;
        10) nano /etc/V2bX/config.json ;;
        11) gen_x25519 ;;
        12) install_bbr ;;
        13) allow_all_ports ;;
        14) V2bX cert ;;
        15) setup_tunnel ;;
        16) stop_tunnel ;;
        *) echo -e "${red}Invalid option | گزینه نامعتبر${plain}" ;;
    esac
}

# ================================================================
# Smart setup | نصب/آپدیت هوشمند
# ================================================================
# If V2bX is already installed -> update, otherwise -> fresh install
# اگر V2bX نصب باشد آپدیت می‌شود، در غیر این صورت نصب می‌شود
smart_setup() {
    if [[ -f /usr/local/V2bX/V2bX ]]; then
        echo -e "${green}V2bX is already installed, updating... | V2bX نصب است، در حال به‌روزرسانی...${plain}"
        update_V2bX "$1"
    else
        echo -e "${green}V2bX is not installed, installing... | V2bX نصب نیست، در حال نصب...${plain}"
        install_base
        get_version "$1"
        install_V2bX
        if [[ x"${release}" != x"alpine" ]]; then
            systemctl enable V2bX >/dev/null 2>&1
            systemctl start V2bX
        fi
        show_status
    fi
}

# ================================================================
# Entry point | نقطه ورود
# ================================================================
# If called with argument, use it as target version
# اگر با آرگومان فراخوانی شود، آن را به عنوان نسخه هدف استفاده می‌کند

if [[ $# -ge 1 ]]; then
    case "$1" in
        install)
            install_base
            get_version "$2"
            install_V2bX
            ;;
        update)
            update_V2bX "$2"
            ;;
        setup|auto)
            smart_setup "$2"
            ;;
        uninstall)
            uninstall_V2bX
            ;;
        *)
            show_menu "$1"
            ;;
    esac
else
    show_menu
fi
