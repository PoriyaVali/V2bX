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

    # ── Core type (shared for all nodes) ──────────────────────────
    echo -e "Select core type | نوع هسته:"
    echo -e "  ${green}1.${plain} sing  (recommended | پیشنهادی)"
    echo -e "  ${green}2.${plain} xray"
    echo -e "  ${green}3.${plain} hysteria2"
    read -rp "Core [1-3, default=1]: " core_choice
    case "${core_choice}" in
        2) CORE_TYPE="xray" ;;
        3) CORE_TYPE="hysteria2" ;;
        *) CORE_TYPE="sing" ;;
    esac

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
    read -rp "Log level (debug/info/warn/error) [default: info]: " LOG_LEVEL
    LOG_LEVEL="${LOG_LEVEL:-info}"

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

    # ── Build core block ──────────────────────────────────────────
    if [[ "${CORE_TYPE}" == "sing" ]]; then
        if [[ -n "${BLOCKED_JSON}" ]]; then
            BLOCKED_FIELD=",
      \"BlockedCountries\": [\"${BLOCKED_JSON}\"]"
        else
            BLOCKED_FIELD=""
        fi
        CORE_BLOCK="{
      \"Type\": \"sing\",
      \"Log\": { \"Level\": \"${LOG_LEVEL}\", \"Timestamp\": true },
      \"NTP\": { \"Enable\": false, \"Server\": \"time.apple.com\", \"ServerPort\": 0 },
      \"OriginalPath\": \"/etc/V2bX/sing_origin.json\"${BLOCKED_FIELD}
    }"
    elif [[ "${CORE_TYPE}" == "xray" ]]; then
        CORE_BLOCK="{
      \"Type\": \"xray\",
      \"Log\": { \"Level\": \"${LOG_LEVEL}\" }
    }"
    else
        CORE_BLOCK="{
      \"Type\": \"hysteria2\"
    }"
    fi

    # ── Node loop — each node gets its own domain & cert ─────────
    NODES_BLOCK=""
    NODE_NUM=0
    while true; do
        NODE_NUM=$((NODE_NUM + 1))
        echo ""
        echo -e "${green}━━━ Node ${NODE_NUM} | نود ${NODE_NUM} ━━━${plain}"

        read -rp "Node ID: " NODE_ID

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

        read -rp "Listen IP [default: 0.0.0.0]: " LISTEN_IP
        LISTEN_IP="${LISTEN_IP:-0.0.0.0}"

        # TLS cert — each node gets its own domain → own cert files
        NODE_CERT_BLOCK=""
        if [[ "${CORE_TYPE}" == "sing" ]] && [[ "${NODE_TYPE}" != "shadowsocks" ]] && [[ "${NODE_TYPE}" != "hysteria2" ]]; then
            read -rp "Certificate domain (e.g. ff.example.com): " CERT_DOMAIN
            echo -e "Cert mode | نحوه دریافت سرتیفیکت:"
            echo -e "  ${green}1.${plain} http  (port 80 must be open)"
            echo -e "  ${green}2.${plain} self  (self-signed, test only)"
            echo -e "  ${green}3.${plain} file  (already have cert files)"
            echo -e "  ${green}4.${plain} none  (no TLS)"
            read -rp "Cert mode [1-4, default=1]: " cert_choice
            case "${cert_choice}" in
                2) CERT_MODE="self" ;;
                3) CERT_MODE="file" ;;
                4) CERT_MODE="none" ;;
                *) CERT_MODE="http" ;;
            esac
            # Cert path includes domain name — avoids conflicts between nodes
            NODE_CERT_BLOCK=",
        \"CertConfig\": {
          \"CertMode\": \"${CERT_MODE}\",
          \"RejectUnknownSni\": false,
          \"CertDomain\": \"${CERT_DOMAIN}\",
          \"CertFile\": \"/etc/V2bX/${CERT_DOMAIN}.cer\",
          \"KeyFile\": \"/etc/V2bX/${CERT_DOMAIN}.key\"
        }"
        fi

        # Build this node's JSON
        ONE_NODE="{
      \"Core\": \"${CORE_TYPE}\",
      \"ApiHost\": \"${API_HOST}\",
      \"ApiKey\": \"${API_KEY}\",
      \"NodeID\": ${NODE_ID},
      \"NodeType\": \"${NODE_TYPE}\",
      \"Timeout\": 30,
      \"ListenIP\": \"${LISTEN_IP}\",
      \"SendIP\": \"0.0.0.0\",
      \"DeviceOnlineMinTraffic\": 200,
      \"MinReportTraffic\": 0,
      \"SingOptions\": {
        \"EnableTFO\": false,
        \"EnableSniff\": true,
        \"SniffOverrideDestination\": true,
        \"EnableDNS\": false${MULTIPLEX_BLOCK}
      }${NODE_CERT_BLOCK}
    }"

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
    ${CORE_BLOCK}
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
  ————————————————
 "
    read -rp "Choose | انتخاب [0-13]: " num
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
        *) echo -e "${red}Invalid option | گزینه نامعتبر${plain}" ;;
    esac
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
