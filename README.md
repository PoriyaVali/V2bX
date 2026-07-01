# V2bX — DrMobile Fork

[![Release](https://img.shields.io/github/v/release/PoriyaVali/V2bX?color=blue&label=Release)](https://github.com/PoriyaVali/V2bX/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/PoriyaVali/V2bX/release.yml?label=Build)](https://github.com/PoriyaVali/V2bX/actions)
[![License](https://img.shields.io/github/license/PoriyaVali/V2bX)](LICENSE)

A multi-core V2board node server with updated cores and a bilingual (English/Persian) menu. Forked from [wyx2685/V2bX](https://github.com/wyx2685/V2bX).

یک سرویس نود چند هسته‌ای برای V2board با هسته‌های به‌روز و منوی دوزبانه (انگلیسی/فارسی). منشعب از [wyx2685/V2bX](https://github.com/wyx2685/V2bX).

---

## 🚀 One-Click Install / Update | نصب و آپدیت با یک کلیک

Auto-detects your server: **updates** if V2bX is already installed, otherwise does a **fresh install**.

خودش تشخیص می‌دهد: اگر V2bX نصب باشد **آپدیت** می‌کند، وگرنه **نصب کامل** انجام می‌دهد.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/PoriyaVali/V2bX/dev_new/install.sh) setup
```

Then open the management menu anytime with | سپس هر زمان منوی مدیریت را باز کنید با:

```bash
v2bx menu
```

The menu covers install, update, uninstall, start/stop/restart, logs, config wizard, X25519 key, and BBR.

منو شامل نصب، آپدیت، حذف، استارت/استاپ/ری‌استارت، لاگ، ویزارد کانفیگ، کلید X25519 و BBR است.

---

## ✨ Features | ویژگی‌ها

- Vmess/Vless, Trojan, Shadowsocks, Hysteria2 | پشتیبانی از پروتکل‌های Vmess/Vless، Trojan، Shadowsocks، Hysteria2
- Vless + XTLS and Reality | پشتیبانی از Vless، XTLS و Reality
- One instance, multiple nodes — no restart needed | یک نمونه برای چندین نود بدون راه‌اندازی مجدد
- Per-user online IP limit, TCP connection limit | محدودیت IP آنلاین و اتصال TCP در هر کاربر
- Node- and user-level speed limit | محدودیت سرعت در سطح نود و کاربر
- Auto TLS certificate + renewal | صدور و تمدید خودکار گواهی TLS
- Auto-restart on config change | راه‌اندازی مجدد خودکار پس از تغییر تنظیمات

## 🧩 Core Versions | نسخه هسته‌ها

| Core | Version |
|------|---------|
| xray-core | v26.6.22 (wyx2685 fork) |
| sing-box | v1.13.0-alpha.5 (wyx2685 fork) |
| hysteria2 | v2.9.3 |

## ⌨️ CLI Commands | دستورات

```bash
v2bx menu       # Management menu | منوی مدیریت
v2bx start      # Start service   | راه‌اندازی سرویس
v2bx stop       # Stop service    | توقف سرویس
v2bx restart    # Restart service | راه‌اندازی مجدد
v2bx log        # View logs       | مشاهده لاگ
v2bx update     # Update version  | به‌روزرسانی
v2bx uninstall  # Uninstall       | حذف
v2bx synctime   # Sync system time| همگام‌سازی زمان
```

## 🔧 Build from Source | ساخت از سورس

```bash
git clone https://github.com/PoriyaVali/V2bX.git && cd V2bX
GOEXPERIMENT=jsonv2 go build -v -o V2bX \
  -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" \
  -trimpath -ldflags "-s -w -buildid="
```

## ⚙️ Configuration | تنظیمات

Use the built-in config wizard (`v2bx menu` → option 9) or see the [example configs](example/).

از ویزارد داخلی (`v2bx menu` → گزینه ۹) استفاده کنید یا به پوشه [example](example/) مراجعه کنید.

## Credits | تشکر

[wyx2685/V2bX](https://github.com/wyx2685/V2bX) · [XTLS](https://github.com/XTLS/) · [sing-box](https://github.com/SagerNet/sing-box) · [hysteria](https://github.com/apernet/hysteria) · [XrayR](https://github.com/XrayR/XrayR) · [V2Fly](https://github.com/v2fly)

## Disclaimer | سلب مسئولیت

Provided as-is with no warranty. Use at your own risk. | بدون هیچ ضمانتی ارائه می‌شود؛ استفاده به عهده کاربر است.
