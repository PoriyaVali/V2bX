#!/usr/bin/env python3
"""Render the final Persian audit report from recorded, immutable evidence.

No services are started, reset or queried. The latest main run is read from
results/checks.jsonl; optional controls and independent MDNS evidence are kept
as separate phases. Private keys, environment files and credentials are not
copied into the report.
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

MIHOMO = [
    "http",
    "socks5",
    "mieru",
    "shadowquic",
    "sudoku",
    "snell",
    "vmess",
    "vless",
    "trojan",
    "tuic",
    "hysteria2",
    "anytls",
    "trusttunnel",
]
LEGACY = ["shadowsocks", "hysteria"]
SERVER_TYPES = MIHOMO + LEGACY + ["mdns"]
EXTERNAL_TYPES = [
    "ssr",
    "wireguard",
    "gostrelay",
    "ssh",
    "masque",
    "openvpn",
    "tailscale",
    "zerotier",
    "easytier",
]
CERT_CASES = [
    (p, "tcp")
    for p in [
        "http",
        "socks5",
        "vmess",
        "vless",
        "trojan",
        "anytls",
        "trusttunnel",
    ]
] + [(p, "quic") for p in ["tuic", "hysteria2", "trusttunnel", "hysteria"]]
CERT_STAGES = [
    "verified-initial-certificate",
    "partial-pair-keeps-current-certificate",
    "live-certificate-rotation",
    "wrong-domain-keeps-last-valid-certificate",
    "certificate-recovery",
]
TEHRAN = ZoneInfo("Asia/Tehran")


def read_json(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def phase(directory, name):
    """Prefer JSONL: each row was serialized before later transfers occurred."""
    directory = Path(directory)
    check_file = directory / "checks.jsonl"
    summary_file = directory / "summary.json"
    if check_file.exists():
        checks = [
            json.loads(line)
            for line in check_file.read_text().splitlines()
            if line.strip()
        ]
        source = str(check_file)
    elif summary_file.exists():
        checks = read_json(summary_file, {}).get("results", [])
        source = str(summary_file)
    else:
        return None
    consistency = []
    for row in checks:
        detail = row.get("detail")
        if not row.get("passed") or not isinstance(detail, dict):
            continue
        for protocol, value in detail.items():
            if (
                isinstance(value, dict)
                and "expected" in value
                and "actual" in value
                and value["expected"] != value["actual"]
            ):
                consistency.append(
                    {"check": row.get("check"), "protocol": protocol, **value}
                )
    return {
        "name": name,
        "source": source,
        "checks": checks,
        "passed": sum(bool(r.get("passed")) for r in checks),
        "failed": sum(not r.get("passed") for r in checks),
        "accounting_evidence_inconsistencies": consistency,
        "manifest": read_json(directory / "manifest.json"),
    }


def state(value):
    if value is True:
        return "موفق"
    if value is False:
        return "ناموفق"
    return "بررسی نشده"


def grouped(checks, names):
    values = [checks.get(name, {}).get("passed") for name in names]
    if any(value is False for value in values):
        return False
    return True if values and all(value is True for value in values) else None


def evidence_count(path, action, status):
    if not path.exists():
        return None
    count = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("path", "").endswith("/" + action) and row.get("status") == status:
            count += 1
    return count


def build(work, controls, mdns_dir):
    phases = [
        p
        for p in [
            phase(work / "results", "اجرای اصلی"),
            phase(controls / "results", "کنترل نود"),
        ]
        if p
    ]
    # Avoid double-counting repeated case names such as daemon startup.
    all_rows = sorted(
        [row for p in phases for row in p["checks"]], key=lambda r: r.get("time", 0)
    )
    checks = {row["check"]: row for row in all_rows}
    creation = read_json(work / "results/node-creation.json", [])
    created = {row["protocol"]: row.get("status") == 200 for row in creation}
    proof = read_json(mdns_dir / "result.json", {})
    server_stats = read_json(work / "results/server-statistics.json")
    shutdown = read_json(work / "results/shutdown-and-version.json")
    additional_evidence_valid = all(
        [
            server_stats is None
            or (
                server_stats.get("passed") is True
                and server_stats.get("expected") == server_stats.get("actual")
            ),
            shutdown is None
            or (
                shutdown.get("passed") is True
                and shutdown.get("version_verified") is True
                and shutdown.get("online_after_graceful_shutdown") == 0
                and shutdown.get("failed_queue_jobs") == 0
            ),
        ]
    )
    coverage = []
    accounting_cases = [
        "exact-directional-usage-in-MariaDB",
        "lost-ack/no-double-billing",
        "exact-usage-after-live-speed-edits",
        "exact-usage-after-unban",
        "expired/exact-accounting",
        "quota-exhausted/exact-accounting",
        "final-exact-usage",
    ]
    for protocol in SERVER_TYPES:
        mdns = protocol == "mdns"
        tcp_key = protocol + (
            "/native-client-tcp-through-real-node"
            if mdns
            else "/tcp-from-real-subscription"
        )
        online_key = protocol + (
            "/native-online-device-in-panel" if mdns else "/online-in-panel"
        )
        tcp = checks.get(tcp_key, {}).get("passed")
        online = checks.get(online_key, {}).get("passed")
        # The separate proof is explicit additional evidence, not a rewritten
        # success for any failed main-run check.
        if tcp is None and mdns:
            tcp = proof.get("tcp_payload_verified")
        if online is None and mdns and proof:
            online = bool(proof.get("online", {}).get("alive_ip"))
        coverage.append(
            {
                "protocol": protocol,
                "core": "Mihomo"
                if protocol in MIHOMO
                else "MDNS بومی"
                if mdns
                else "Sing",
                "created": created.get(protocol),
                "tcp": tcp,
                "udp": None
                if protocol in ["http", "mdns"]
                else checks.get(protocol + "/udp-from-real-subscription", {}).get(
                    "passed"
                ),
                "udp_applicable": protocol not in ["http", "mdns"],
                "accounting": proof.get("exact_traffic")
                if mdns
                else grouped(checks, accounting_cases),
                "online": online,
                "speed": None
                if mdns
                else grouped(
                    checks,
                    [
                        protocol + "/1mbps-on-existing-session",
                        protocol + "/live-upgrade-on-same-session",
                    ],
                ),
                "eligibility": None
                if mdns
                else grouped(
                    checks,
                    [
                        protocol + "/ban-closes-active-session",
                        protocol + "/ban-rejects-cached-credentials",
                        protocol + "/unban-restores-access",
                        protocol + "/expired/active-session-revoked",
                        protocol + "/expired/access-restored",
                        protocol + "/quota-exhausted/active-session-revoked",
                        protocol + "/quota-exhausted/access-restored",
                    ],
                ),
            }
        )
    certificate_coverage = [
        {
            "protocol": protocol,
            "transport": transport,
            "passed": grouped(
                checks,
                [protocol + "/" + transport + "/" + stage for stage in CERT_STAGES],
            ),
        }
        for protocol, transport in CERT_CASES
    ]
    failed = [row for p in phases for row in p["checks"] if not row.get("passed")]
    inconsistencies = [
        row for p in phases for row in p["accounting_evidence_inconsistencies"]
    ]
    missing_coverage = []
    for row in coverage:
        fields = ["created", "tcp", "accounting", "online"]
        if row["protocol"] != "mdns":
            fields += ["speed", "eligibility"]
        if row["udp_applicable"]:
            fields += ["udp"]
        missing_coverage += [
            row["protocol"] + "/" + field for field in fields if row[field] is not True
        ]
    missing_coverage += [
        protocol + "/expected-501"
        for protocol in EXTERNAL_TYPES
        if created.get(protocol) is not True
        or checks.get(protocol + "/unsupported-server-rejected", {}).get("passed")
        is not True
    ]
    missing_coverage += [
        row["protocol"] + "/" + row["transport"] + "/certificate"
        for row in certificate_coverage
        if row["passed"] is not True
    ]
    result = {
        "generated_at": datetime.now(TEHRAN).isoformat(),
        "timezone": "Asia/Tehran",
        "complete_within_documented_scope": bool(phases)
        and not failed
        and not inconsistencies
        and not missing_coverage
        and additional_evidence_valid,
        "node_types_created": sum(created.values()),
        "unique_check_names": len(checks),
        "unique_passed_check_names": sum(
            bool(row.get("passed")) for row in checks.values()
        ),
        "phases": phases,
        "server_protocols": coverage,
        "external_protocols": [
            {
                "protocol": p,
                "created": created.get(p),
                "expected_server_status": 501,
                "passed": checks.get(p + "/unsupported-server-rejected", {}).get(
                    "passed"
                ),
            }
            for p in EXTERNAL_TYPES
        ],
        "certificate_paths": certificate_coverage,
        "mdns_independent_proof": proof,
        "additional_evidence": {
            "server_statistics": server_stats,
            "shutdown_and_version": shutdown,
            "consistent": additional_evidence_valid,
            "included_in_check_counts": False,
        },
        "failed_checks": failed,
        "missing_or_failed_coverage": missing_coverage,
        "accounting_evidence_inconsistencies": inconsistencies,
        "public_acme_tested": False,
        "traffic_reports": {
            "before_fix_http_400": evidence_count(
                work / "evidence/negative-before-webman-fix/logs/panel-exchanges.jsonl",
                "push",
                400,
            ),
            "final_run_http_200": evidence_count(
                work / "logs/panel-exchanges.jsonl", "push", 200
            ),
        },
    }
    return result, checks


def markdown(data, checks, work, controls):
    complete = data["complete_within_documented_scope"]
    lines = [
        "# گزارش اجرای یکپارچهٔ Irboard و V2bX",
        "",
        "زمان تولید: "
        + datetime.fromisoformat(data["generated_at"]).strftime("%Y-%m-%d %H:%M:%S")
        + "، به وقت تهران.",
        "",
        (
            "بررسی‌های ثبت‌شده در دامنهٔ زیر موفق‌اند."
            if complete
            else "نتیجه هنوز تأیید کامل نیست؛ موارد ناموفق یا شواهد ناقص در انتهای گزارش آمده‌اند."
        ),
        f"تعداد انواع نود ساخته‌شده: **{data['node_types_created']}**. تعداد عنوان‌های بررسیِ یکتا: **{data['unique_check_names']}**؛ موفق: **{data['unique_passed_check_names']}**.",
        "",
        "## محیط و روش اجرا",
        "",
        "Irboard با Webman، MariaDB 10.6، Redis و worker صف اجرا شد. نودها از API واقعی مدیریت ساخته شدند. کلاینت Mihomo در کانتینری جدا با IP مستقل، خروجی سابسکریپشن واقعی کاربر را خواند و به فایل اجرایی V2bX متصل شد. بایت‌های ارسال و دریافت با شمارنده‌های نهایی MariaDB مقایسه شدند.",
        "",
        "MDNS با کلاینت بومی MasterDnsVPN نیز بررسی شد. مقصد آن روی شبکهٔ Docker کاملاً داخلی با آدرس مستنداتی TEST-NET قرار گرفت؛ سیاست منع دسترسی به مقصد خصوصی در هسته تغییر نکرد.",
        "",
        "## نتیجهٔ پروتکل‌های سرور",
        "",
        "| پروتکل | هسته | ساخت در پنل | TCP | UDP | مصرف دقیق | آنلاین | سرعت زنده | مسدودی، انقضا و حجم |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in data["server_protocols"]:
        udp = (
            state(row["udp"])
            if row["udp_applicable"]
            else "کاربرد ندارد"
            if row["protocol"] == "http"
            else "بررسی نشده"
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    row["protocol"],
                    row["core"],
                    state(row["created"]),
                    state(row["tcp"]),
                    udp,
                    state(row["accounting"]),
                    state(row["online"]),
                    state(row["speed"]),
                    state(row["eligibility"]),
                ]
            )
            + " |"
        )
    lines += [
        "",
        "در ستون سرعت، محدودیت ۱ مگابیت و افزایش به ۲۰ مگابیت روی همان اتصال بررسی شد. ستون سیاست‌های کاربر شامل قطع اتصال فعال، رد مشخصات ذخیره‌شده و بازگشت دسترسی پس از رفع مسدودی، تمدید زمان یا بازگرداندن حجم است. آزمون MDNS محدود به مسیر بومی TCP، مصرف، آنلاین و سیاست مقصد بوده است؛ سرعت و همهٔ حالت‌های دسترسی MDNS در این اجرای یکپارچه سنجیده نشده‌اند.",
        "",
        "## انواع فاقد ورودی سرور مدیریت‌شده",
        "",
        "این انواع در پنل ساخته شدند. پاسخ ۵۰۱ برای پیکربندی سرور آن‌ها، نتیجهٔ مورد انتظار است و موفقیت اتصال سروری محسوب نمی‌شود.",
        "",
        "| نوع | ساخت در پنل | رد صریح پیکربندی سرور با ۵۰۱ |",
        "| --- | --- | --- |",
    ]
    lines += [
        f"| {row['protocol']} | {state(row['created'])} | {state(row['passed'])} |"
        for row in data["external_protocols"]
    ]
    lines += [
        "",
        "## گواهی و دامنه",
        "",
        "| پروتکل | مسیر | اعتبار دامنه و تعویض گواهی |",
        "| --- | --- | --- |",
    ]
    lines += [
        f"| {row['protocol']} | {row['transport'].upper()} | {state(row['passed'])} |"
        for row in data["certificate_paths"]
    ]
    lines += [
        "",
        "گواهی برای `node.e2e.test` با CA محلی امضا شد و کلاینت اعتبار دامنه را بررسی کرد. شمارهٔ گواهی از ۱۰۱ به ۱۰۲ تغییر کرد؛ فایل ناقص و گواهیِ دامنهٔ دیگر جایگزین گواهی معتبر نشدند؛ پس از اصلاح فایل‌ها، شمارهٔ ۱۰۴ ارائه شد. مسیر TCP و QUIC در TrustTunnel جداگانه بررسی شد. پروب بدون مشخصات ShadowQUIC نیز به سرویس واقعی QUIC استتار رسید.",
        "",
        "حالت گواهی این اجرای یکپارچه `file` بوده است. این آزمون، صدور یا تمدید گواهی از مرجع عمومی، انتشار DNS و چالش‌های HTTP-01/DNS-01 روی دامنهٔ واقعی را اثبات نمی‌کند. تصمیم زمان تمدید و تلاش مجدد در تست‌های جداگانهٔ مدیر گواهی بررسی می‌شود.",
        "",
        "## خطای واقعی پیدا‌شده و اصلاح",
        "",
        "در اجرای اولیه، اتصال کاربران برقرار می‌شد اما Webman بدنهٔ خام JSON را به درخواست Laravel منتقل نمی‌کرد. مسیر گزارش مصرف `getContent()` را خالی می‌دید و با `Invalid traffic JSON` و HTTP 400 پاسخ می‌داد؛ بنابراین مصرف به دیتابیس نمی‌رسید.",
        "",
        "پل درخواست در `app/Http/WebmanRequest.php` بدنهٔ واقعی Adapterman را به Symfony/Laravel می‌رساند و `start.php` در Webman از آن استفاده می‌کند. نوع عددهای JSON حفظ می‌شود؛ گزارش منفی، اعشاری، رشته‌ای یا با تعداد خانهٔ نادرست رد می‌شود. سازگاری فرم‌های PUT/PATCH/DELETE و جداسازی درخواست‌های متوالی نیز پوشش داده شد.",
        "",
        "پس از اصلاح، بایت‌های آپلود و دانلود از کلاینت تا MariaDB تطبیق داده شدند. پاسخ یک گزارش عمداً گم شد؛ ارسال مجدد با همان شناسه، مصرف را دوباره حساب نکرد.",
        "",
        "مشکل اولیهٔ مقصد MDNS ناشی از منع عمدیِ مقصد خصوصی بود. آزمون با مقصد TEST-NET کاملاً داخلی تکرار شد؛ حفاظت هسته برای عبور آزمون ضعیف نشد.",
        "",
        "## کنترل‌های تکمیلی",
        "",
    ]
    extra = {
        "فقدان پاسخ گزارش و جلوگیری از دوباره‌شماری": [
            "lost-ack/retried-same-report-id",
            "lost-ack/no-double-billing",
        ],
        "سقف اتصال هم‌زمان": ["connection-cap/fifth-forwarding-stream-rejected"],
        "سقف دستگاه با دو IP واقعی": [
            "device-cap/second-real-source-ip-rejected",
            "device-cap/second-ip-accepted-after-panel-edit",
        ],
        "ادامهٔ اتصال هنگام قطع پنل و بازیابی مصرف": [
            "panel-outage/live-session-kept",
            "panel-outage/queued-traffic-recovered-once",
        ],
        "تغییر مشخصات کاربر و حفظ حساب مصرف UID": [
            "credential-rotation/old-secret-rejected",
            "credential-rotation/new-subscription-connects",
            "credential-rotation/uid-accounting-retained",
        ],
        "مسدود و آزادکردن پورت مقصد از پنل": [
            "destination-policy/blocked-port-from-panel-rejected",
            "destination-policy/removing-rule-restores-access",
        ],
        "ضریب مصرف ۱٫۵ برای هر دو جهت": ["node-rate/1.5-multiplier-in-both-directions"],
        "تغییر پورت نود و هماهنگی سابسکریپشن": [
            "node-port/old-listener-retired",
            "node-port/subscription-follows-new-port",
            "node-port/new-listener-serves-same-user",
            "node-port/accounting-survives-reload",
        ],
    }
    lines += [
        f"- {name}: **{state(grouped(checks, names))}**."
        for name, names in extra.items()
    ]
    proof = data["mdns_independent_proof"]
    if proof:
        lines += [
            "",
            f"شاهد مستقل MDNS: محتوای TCP {state(proof.get('tcp_payload_verified'))}؛ تغییر مصرف {proof.get('actual_delta')} در برابر مقدار مورد انتظار {[proof.get('expected_upload'), proof.get('expected_download')]} بایت؛ منع مقصد خصوصی {state(proof.get('private_target_refused'))}.",
        ]
    extra_evidence = data["additional_evidence"]
    server_stats = extra_evidence["server_statistics"]
    shutdown = extra_evidence["shutdown_and_version"]
    if server_stats:
        lines += [
            "",
            "شاهد تکمیلی آمار نود: آمار روزانهٔ "
            + str(len(server_stats.get("actual", {})))
            + " نود، برای هر دو جهت آپلود و دانلود، با جمع گزارش‌های واقعی پذیرفته‌شده پس از حذف شناسه‌های تکراری "
            + (
                "برابر بود."
                if server_stats.get("expected") == server_stats.get("actual")
                and server_stats.get("passed")
                else "تطبیق کامل نداشت."
            ),
        ]
    if shutdown:
        versions = sorted(set(shutdown.get("versions", {}).values()))
        lines += [
            "",
            "شاهد تکمیلی وضعیت و خاموش‌شدن: پنل برای "
            + str(len(shutdown.get("versions", {})))
            + " نود نسخهٔ "
            + "، ".join("`" + version + "`" for version in versions)
            + " را ثبت کرد. تعداد کاربران آنلاین پس از خاموش‌شدن عادی: **"
            + str(shutdown.get("online_after_graceful_shutdown"))
            + "**؛ تعداد jobهای ناموفق صف: **"
            + str(shutdown.get("failed_queue_jobs"))
            + "**.",
        ]
    if server_stats or shutdown:
        lines += [
            "",
            "این دو فایل شاهد توصیفیِ جداگانه‌اند و به شمار عنوان‌های بررسی اضافه نشده‌اند.",
        ]
    lines += [
        "",
        "## شمارش و شواهد",
        "",
        "بررسی تکراری با نام یکسان در جمع عنوان‌های یکتا دوباره شمرده نشده است. تعداد رخدادهای هر فاز:",
        "",
    ]
    lines += [
        f"- {p['name']}: {p['passed']} موفق، {p['failed']} ناموفق."
        for p in data["phases"]
    ]
    for p in data["phases"]:
        manifest = p.get("manifest") or {}
        if manifest:
            lines += [
                "",
                f"فاز {p['name']} — SHA-256 فایل V2bX: `{manifest.get('v2bx_sha256', 'ثبت نشده')}`.",
            ]
            panel = manifest.get("panel") or {}
            if panel.get("source_head"):
                lines += [
                    f"نسخهٔ منبع Irboard: `{panel['source_head']}`؛ هش فایل‌های واقعاً اجراشده در manifest موجود است."
                ]
    lines += [
        "",
        "فایل‌های قابل بررسی:",
        "",
        "- `results/checks.jsonl`: نتایج هر بررسی در زمان اجرا؛ منبع اصلی این گزارش.",
        "- `results/consolidated.json`: نتیجهٔ ماشین‌خوان، پوشش هر پروتکل و شواهد هر فاز.",
        "- `results/manifest.json`: هش باینری‌ها و منبع فایل‌های اجراشده.",
        "- `results/server-statistics.json`: تطبیق آمار روزانهٔ نودها با گزارش‌های واقعیِ یکتا.",
        "- `results/shutdown-and-version.json`: نسخهٔ ثبت‌شده در پنل، آنلاین پس از خاموش‌شدن و وضعیت خطاهای صف.",
        "- `logs/panel-exchanges.jsonl`: پاسخ‌های واقعی API با حذف token از آدرس ثبت‌شده.",
        "- `logs/v2bx.log`، `logs/client.jsonl`، `logs/queue-worker.log` و `logs/traffic-drain.log`.",
        "- `mdns-proof/result.json` و لاگ‌های کناری آن: آزمون مستقل MDNS و منع مقصد خصوصی.",
        "",
        "کلید خصوصی CA، کلید سرور، فایل محیط و توکن مدیریت نباید داخل بستهٔ قابل اشتراک قرار گیرند.",
        "",
        "## حدود نتیجه و تغییرات قابل بررسی",
        "",
        "این گزارش رفتار مسیرهای مشخص‌شده را در شبکهٔ آزمایشگاهی ثبت می‌کند. همهٔ ترنسپورت‌ها و ترکیب تنظیمات، وضعیت اینترنت، دسترسی عمومی، بار طولانی‌مدت و صدور واقعی ACME در این دامنه نیستند. وضعیت CI از نتایج محلی استنباط نشده است.",
        "",
        "- [V2bX #20](https://github.com/PoriyaVali/V2bX/pull/20)",
        "- [Irboard #20](https://github.com/PoriyaVali/Irboard/pull/20)",
        "- [Mihomo #5](https://github.com/PoriyaVali/mihomo/pull/5)",
    ]
    if not complete:
        lines += ["", "## موارد باز", ""]
        lines += [
            "- ناموفق: `" + str(row.get("check")) + "`؛ " + str(row.get("detail"))[:300]
            for row in data["failed_checks"]
        ]
        lines += [
            "- شواهد ناقص یا ناموفق: `" + name + "`."
            for name in data["missing_or_failed_coverage"]
        ]
        lines += [
            "- ناسازگاری تصویر شمارنده: `" + row["check"] + "/" + row["protocol"] + "`."
            for row in data["accounting_evidence_inconsistencies"]
        ]
        if not extra_evidence["consistent"]:
            lines += [
                "- شواهد تکمیلی آمار نود یا خاموش‌شدن با نتیجهٔ ادعاشده تطبیق ندارند."
            ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True)
    parser.add_argument("--controls-dir")
    parser.add_argument("--mdns-proof-dir")
    args = parser.parse_args()
    work = Path(args.work).resolve()
    controls = (
        Path(args.controls_dir).resolve()
        if args.controls_dir
        else work / "evidence/final-controls"
    )
    mdns_dir = (
        Path(args.mdns_proof_dir).resolve()
        if args.mdns_proof_dir
        else work / "mdns-proof"
    )
    data, checks = build(work, controls, mdns_dir)
    output = work / "results"
    output.mkdir(parents=True, exist_ok=True)
    (output / "consolidated.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    )
    (output / "report-fa.md").write_text(markdown(data, checks, work, controls))
    print(
        json.dumps(
            {
                "report": str(output / "report-fa.md"),
                "unique_checks": data["unique_check_names"],
                "complete": data["complete_within_documented_scope"],
            },
            ensure_ascii=False,
        )
    )
    raise SystemExit(0 if data["complete_within_documented_scope"] else 1)


if __name__ == "__main__":
    main()
