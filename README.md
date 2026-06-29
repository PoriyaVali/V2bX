# V2bX — DrMobile Fork

[![Release](https://img.shields.io/github/v/release/PoriyaVali/V2bX?color=blue&label=Release)](https://github.com/PoriyaVali/V2bX/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/PoriyaVali/V2bX/release.yml?label=Build)](https://github.com/PoriyaVali/V2bX/actions)
[![License](https://img.shields.io/github/license/PoriyaVali/V2bX)](LICENSE)

A multi-core V2board node server, forked from [wyx2685/V2bX](https://github.com/wyx2685/V2bX) with updated cores and bilingual (English/Persian) interface.

---

یک سرویس نود چند هسته‌ای برای V2board، منشعب از [wyx2685/V2bX](https://github.com/wyx2685/V2bX) با هسته‌های به‌روز و رابط دوزبانه (انگلیسی/فارسی).

---

## Features | ویژگی‌ها

- Permanently open source and free | همیشه متن‌باز و رایگان
- Supports Vmess/Vless, Trojan, Shadowsocks, Hysteria2 | پشتیبانی از پروتکل‌های Vmess/Vless، Trojan، Shadowsocks، Hysteria2
- Supports Vless + XTLS and Reality | پشتیبانی از Vless، XTLS و Reality
- Single instance, multiple nodes — no restart needed | یک نمونه برای چندین نود بدون نیاز به راه‌اندازی مجدد
- Online IP limit per user | محدودیت تعداد IP آنلاین
- TCP connection limit | محدودیت تعداد اتصال TCP
- Node-level and user-level speed limit | محدودیت سرعت در سطح نود و کاربر
- Simple configuration | پیکربندی ساده
- Auto-restart on config change | راه‌اندازی مجدد خودکار پس از تغییر تنظیمات
- Multi-core support, easy to extend | پشتیبانی از چند هسته، قابل گسترش

## Core Versions | نسخه هسته‌ها

| Core | Version |
|------|---------|
| xray-core | v26.6.22 (wyx2685 fork) |
| sing-box | v1.13.0-alpha.5 (wyx2685 fork) |
| hysteria2 | v2.9.3 |

## Feature Matrix | جدول قابلیت‌ها

| Feature | v2ray | trojan | shadowsocks | hysteria2 |
|---------|-------|--------|-------------|-----------|
| Auto TLS certificate | ✓ | ✓ | ✓ | ✓ |
| Auto TLS renewal | ✓ | ✓ | ✓ | ✓ |
| Online user stats | ✓ | ✓ | ✓ | ✓ |
| Audit rules | ✓ | ✓ | ✓ | ✓ |
| Custom DNS | ✓ | ✓ | ✓ | ✓ |
| Online IP limit | ✓ | ✓ | ✓ | ✓ |
| Connection limit | ✓ | ✓ | ✓ | ✓ |
| Cross-node IP limit | ✓ | ✓ | ✓ | ✓ |
| Per-user speed limit | ✓ | ✓ | ✓ | ✓ |

## Installation | نصب

### One-liner Install | نصب با یک دستور

```bash
wget -N https://raw.githubusercontent.com/PoriyaVali/V2bX/dev_new/install.sh && bash install.sh
```

### Download Binary | دانلود باینری

Download the latest release for your platform from:

آخرین نسخه برای پلتفرم خود را از اینجا دانلود کنید:

**[https://github.com/PoriyaVali/V2bX/releases](https://github.com/PoriyaVali/V2bX/releases)**

### Manual Install (Linux) | نصب دستی (لینوکس)

```bash
# Download latest release for linux amd64
# دانلود آخرین نسخه برای linux amd64
wget -O V2bX.zip https://github.com/PoriyaVali/V2bX/releases/latest/download/V2bX-linux-amd64.zip
unzip V2bX.zip -d V2bX-linux-amd64
cp V2bX-linux-amd64/V2bX /usr/local/bin/V2bX
chmod +x /usr/local/bin/V2bX

# Set up config directory | ایجاد دایرکتوری تنظیمات
mkdir -p /etc/V2bX
cp V2bX-linux-amd64/*.json /etc/V2bX/
```

### Service Setup | راه‌اندازی سرویس

```bash
# Create systemd service | ایجاد سرویس systemd
cat > /etc/systemd/system/V2bX.service << EOF
[Unit]
Description=V2bX Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/V2bX run -c /etc/V2bX/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable V2bX
systemctl start V2bX
```

### CLI Commands | دستورات

```bash
V2bX start      # Start service   | راه‌اندازی سرویس
V2bX stop       # Stop service    | توقف سرویس
V2bX restart    # Restart service | راه‌اندازی مجدد
V2bX log        # View logs       | مشاهده لاگ
V2bX update     # Update version  | به‌روزرسانی
V2bX uninstall  # Uninstall       | حذف
V2bX synctime   # Sync system time| همگام‌سازی زمان
```

## Build from Source | ساخت از سورس

```bash
git clone https://github.com/PoriyaVali/V2bX.git
cd V2bX

# Build with all cores | ساخت با تمام هسته‌ها
GOEXPERIMENT=jsonv2 go build -v -o V2bX \
  -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" \
  -trimpath -ldflags "-s -w -buildid="
```

## Configuration | تنظیمات

See the [example configs](example/) for reference.

برای مثال‌های تنظیمات به پوشه [example](example/) مراجعه کنید.

## Disclaimer | سلب مسئولیت

This project is provided as-is with no warranty. Use at your own risk.

این پروژه بدون هیچ ضمانتی ارائه می‌شود. استفاده از آن به عهده کاربر است.

## Credits | تشکر

- [wyx2685/V2bX](https://github.com/wyx2685/V2bX) — Original fork
- [Project X / XTLS](https://github.com/XTLS/)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [apernet/hysteria](https://github.com/apernet/hysteria)
- [XrayR](https://github.com/XrayR/XrayR)
- [V2Fly](https://github.com/v2fly)
