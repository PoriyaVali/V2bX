# V2bX — DrMobile Fork

[![Release](https://img.shields.io/github/v/release/PoriyaVali/V2bX?color=blue&label=Release)](https://github.com/PoriyaVali/V2bX/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/PoriyaVali/V2bX/release.yml?label=Build)](https://github.com/PoriyaVali/V2bX/actions)
[![License](https://img.shields.io/github/license/PoriyaVali/V2bX)](LICENSE)

A multi-core V2board node server with updated cores and a bilingual (English/Persian) menu. Forked from [wyx2685/V2bX](https://github.com/wyx2685/V2bX).

یک سرویس نود چند هسته‌ای برای V2board با هسته‌های به‌روز و منوی دوزبانه (انگلیسی/فارسی). منشعب از [wyx2685/V2bX](https://github.com/wyx2685/V2bX).

The optional **Mihomo server core** supports 11 multi-user listeners, including
HTTP/SOCKS5, Mieru, and ShadowQUIC. See [setup and supported settings](docs/mihomo-server.md).

هستهٔ سرور Mihomo با مدیریت مصرف و کاربران به‌صورت مستقل برای هر نود اضافه شده؛
[راهنمای تنظیم و محدودیت‌ها](docs/mihomo-server.md) را ببینید.

---

## 🚀 One-Click Install / Update | نصب و آپدیت با یک کلیک

Auto-detects your server: **updates** if V2bX is already installed, otherwise does a **fresh install**.

خودش تشخیص می‌دهد: اگر V2bX نصب باشد **آپدیت** می‌کند، وگرنه **نصب کامل** انجام می‌دهد.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/PoriyaVali/V2bX/dev_new/install.sh) setup
```

Already installed? Update to the latest complete release with one command:

برای نصب موجود، به‌روزرسانی به آخرین ریلیز کامل با یک دستور و دسترسی root انجام می‌شود:

```bash
v2bx update
```

Existing configuration and certificate files are preserved. An active service
is restarted; an inactive service stays inactive. See the
[v1.10.0 upgrade notes](docs/releases/v1.10.0.md) for Mihomo setup and compatibility.

تنظیمات و گواهی‌های موجود حفظ می‌شوند. سرویس فعال دوباره راه‌اندازی می‌شود؛ سرویس
خاموش، خاموش می‌ماند. جزئیات تغییرات خودکار و تنظیمات اختیاری در
[یادداشت ارتقا به v1.10.0](docs/releases/v1.10.0.md) آمده است.

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
- Answers active probes with a decoy site, tuned for lossy and filtered networks — see [docs/censorship-countermeasures.md](docs/censorship-countermeasures.md) | پاسخ به پروب فعال با سایت پوششی و تنظیم برای شبکه‌های ضعیف و فیلترشده — [توضیحات](docs/censorship-countermeasures.md)

## 🧩 Core Versions | نسخه هسته‌ها

| Core | Version |
|------|---------|
| xray-core | v26.9.9 (PoriyaVali fork v1.260909.1) |
| sing-box | v1.13.21-v2bx.2 (PoriyaVali fork) |
| hysteria2 | v2.11.0 |
| Mihomo | PoriyaVali fork, pinned `8fd40782e828` (managed server integration) |
| MasterDnsVPN | android-multiuser-20261023 (`25b103d6a5f4`) |

## ⌨️ CLI Commands | دستورات

```bash
v2bx menu       # Management menu | منوی مدیریت
v2bx start      # Start service   | راه‌اندازی سرویس
v2bx stop       # Stop service    | توقف سرویس
v2bx restart    # Restart service | راه‌اندازی مجدد
v2bx log        # View logs       | مشاهده لاگ
v2bx update     # Update version  | به‌روزرسانی
v2bx update 1.7.2   # Select a version (also accepts v1.7.2) | انتخاب نسخه با یا بدون v
v2bx uninstall  # Uninstall       | حذف
v2bx synctime   # Sync system time| همگام‌سازی زمان
```

`v2bx update 1.7.2` and `v2bx update v1.7.2` can both downgrade to the published
1.7.2 release. An exact tag is preferred; the alternate `v` spelling is tried
only when that tag is missing. A missing release or a network error leaves the
installed service unchanged instead of switching to the latest version.

هر دو دستور بالا برای دانگرید قابل استفاده‌اند. اگر نسخه پیدا نشود یا ارتباط با
گیت‌هاب خطا داشته باشد، نسخهٔ نصب‌شده و سرویس فعلی تغییری نمی‌کنند.

## 🔧 Build from Source | ساخت از سورس

```bash
git clone https://github.com/PoriyaVali/V2bX.git && cd V2bX
GOEXPERIMENT=jsonv2 go build -v -o V2bX \
  -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor mdns trusttunnel mihomo" \
  -trimpath -ldflags "-s -w -buildid="
```

## ⚙️ Configuration | تنظیمات

Use the built-in config wizard (`v2bx menu` → option 9) or see the [example configs](example/).

از ویزارد داخلی (`v2bx menu` → گزینه ۹) استفاده کنید یا به پوشه [example](example/) مراجعه کنید.

`V2bX configure` keeps mux, node ID and per-node core selection under the
administrator's control, then detects protocol/TLS/domain and asks for Enter
to continue. See [automated setup](docs/automated-setup.md) and
[cover-site security](docs/cover-site-security.md).

## Credits | تشکر

[wyx2685/V2bX](https://github.com/wyx2685/V2bX) · [XTLS](https://github.com/XTLS/) · [sing-box](https://github.com/SagerNet/sing-box) · [hysteria](https://github.com/apernet/hysteria) · [XrayR](https://github.com/XrayR/XrayR) · [V2Fly](https://github.com/v2fly)

## Disclaimer | سلب مسئولیت

Provided as-is with no warranty. Use at your own risk. | بدون هیچ ضمانتی ارائه می‌شود؛ استفاده به عهده کاربر است.
